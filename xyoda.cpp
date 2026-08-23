/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xyoda.h"
#include "xmaterializedunpackguard.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <cstring>

static inline quint8 yodaRol8(quint8 v, quint8 n)
{
    return (quint8)((v << (n & 7)) | (v >> ((8 - n) & 7)));
}

static inline quint8 yodaRor8(quint8 v, quint8 n)
{
    return (quint8)((v >> (n & 7)) | (v << ((8 - n) & 7)));
}

// bounds test for the poly-decryptor emulator's file accesses
static inline bool yodaOob(qint64 nOff, qint64 nFileSize)
{
    return (nOff < 0) || (nOff >= nFileSize);
}

XYODA::XYODA(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XYODA::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XYODA::~XYODA()
{
    QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (pLifetimeState) pLifetimeState->bOwnerAlive = false;
    m_pUnpackLifetimeState.clear();
    if (pLifetimeState && !pLifetimeState->bOperationInProgress) {
        const QSet<UNPACK_CONTEXT *> setContextsCopy = pLifetimeState->setContexts;
        pLifetimeState->setContexts.clear();
        for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
    }
}

XYODA::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XYODA::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive &&
           !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XYODA::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XYODA> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XYODA::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XYODA yoda(pDevice);
    return yoda.isValid(pPdStruct);
}

XBinary::FT XYODA::getFileType()
{
    return FT_PE32_YODA;
}

QString XYODA::getVersion()
{
    QPointer<XYODA> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo());
    return (guardedThis && pInfo && pInfo->bIsValid) ? pInfo->sVersion
                                                     : QString();
}

XYODA::INTERNAL_INFO XYODA::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XYODA::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XYODA> guardedThis(this);
    const bool bAlreadyHandled = guardedThis->isInternalInfoHandled();
    if (!guardedThis) return false;

    if (!bAlreadyHandled) {
        const quint64 nTransaction =
            guardedThis->beginInternalInfoTransaction();
        if (!nTransaction) return false;

        // The transaction supplies the recursion sentinel. Keep every
        // source-derived value local until the same binding is revalidated.
        guardedThis->m_internalInfo = INTERNAL_INFO();
        INTERNAL_INFO info = guardedThis->_getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }

        const auto memoryMap =
            guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        info.memoryMap = memoryMap;

        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        guardedThis->m_internalInfo = info;
        if (!guardedThis->commitInternalInfoTransaction(
                nTransaction,
                static_cast<XBinary::INTERNAL_INFO *>(
                    &guardedThis->m_internalInfo))) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
    }

    return true;
}

void *XYODA::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XYODA> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XYODA::setInternalInfo(void *pInternalInfo)
{
    if (pInternalInfo) {
        m_internalInfo = *static_cast<INTERNAL_INFO *>(pInternalInfo);
        setIsInternalInfoHandled(true);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    } else {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(false);
        XBinary::setInternalInfo(nullptr);
    }
}

// ---------------------------------------------------------------------------
// poly byte-decryptor emulator
// ---------------------------------------------------------------------------

int XYODA::_polyEmulate(quint8 *pBase, qint64 nFileSize, qint64 nDecOff, qint64 nCodeOff, quint32 nEcx, quint32 nMaxEmu)
{
    quint8 cl = (quint8)(nEcx & 0xff);
    quint32 nMaxJmp = 100000000;

    for (quint32 i = 0; (i < nEcx) && (i < nMaxEmu); i++) {
        if (yodaOob(nCodeOff + i, nFileSize)) return 2;
        quint8 al = pBase[nCodeOff + i];

        for (int j = 0; j < 0x30; j++) {
            if (yodaOob(nDecOff + j, nFileSize)) return 2;
            quint8 op = pBase[nDecOff + j];

            switch (op) {
                case 0xEB:  // JMP short
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (!nMaxJmp) return 2;
                    nMaxJmp--;
                    j = j + (qint8)pBase[nDecOff + j];
                    break;
                case 0xFE:  // DEC AL
                    al--;
                    j++;
                    break;
                case 0x2A:  // SUB AL,CL
                    al = (quint8)(al - cl);
                    j++;
                    break;
                case 0x02:  // ADD AL,CL
                    al = (quint8)(al + cl);
                    j++;
                    break;
                case 0x32:  // XOR AL,CL
                    al ^= cl;
                    j++;
                    break;
                case 0x04:  // ADD AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al = (quint8)(al + pBase[nDecOff + j]);
                    break;
                case 0x34:  // XOR AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al ^= pBase[nDecOff + j];
                    break;
                case 0x2C:  // SUB AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al = (quint8)(al - pBase[nDecOff + j]);
                    break;
                case 0xC0:  // ROL/ROR AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (pBase[nDecOff + j] == 0xC0) {
                        j++;
                        if (yodaOob(nDecOff + j, nFileSize)) return 2;
                        al = yodaRol8(al, pBase[nDecOff + j]);
                    } else {
                        j++;
                        if (yodaOob(nDecOff + j, nFileSize)) return 2;
                        al = yodaRor8(al, pBase[nDecOff + j]);
                    }
                    break;
                case 0xD2:  // ROL/ROR AL,CL
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (pBase[nDecOff + j] == 0xC8) {
                        j++;
                        al = yodaRor8(al, cl);
                    } else {
                        j++;
                        al = yodaRol8(al, cl);
                    }
                    break;
                case 0x90:
                case 0xf8:
                case 0xf9:
                    break;
                default:
                    return 1;
            }
        }

        cl--;
        if (yodaOob(nCodeOff + i, nFileSize)) return 2;
        pBase[nCodeOff + i] = al;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XYODA::INTERNAL_INFO XYODA::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) {
        return result;
    }

    const quint32 nEpRva = pe.getOptionalHeader_AddressOfEntryPoint();
    if (nEpRva != listSections.at(n - 1).VirtualAddress + 0x60) {
        return result;
    }

    qint64 nEpOffset = pe.relAddressToOffset(nEpRva);
    if (nEpOffset == -1) {
        return result;
    }

    QByteArray baEp = read_array_process(nEpOffset, 0x80, pPdStruct);
    if (baEp.size() < 0x80) {
        return result;
    }
    const char *ep = baEp.constData();

    qint32 nOffset = 0;
    quint32 nEcx = 0;
    QString sVersion;

    // yC 1.3
    if ((memcmp(ep, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED", 15) == 0) &&
        (memcmp(ep + 0x26, "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) == 0) && ((quint8)ep[0x13] == 0xB9) &&
        (_read_uint16((char *)ep + 0x18) == 0xE981) && (memcmp(ep + 0x1e, "\x8B\xD5\x81\xC2", 4) == 0)) {
        nOffset = 0;
        if (0x6c - _read_uint32((char *)ep + 0xf) + _read_uint32((char *)ep + 0x22) == 0xC6) {
            nEcx = _read_uint32((char *)ep + 0x14) - _read_uint32((char *)ep + 0x1a);
            sVersion = "1.3";
        }
    }

    // yC 1.3 variant
    if (!nEcx && (memcmp(ep, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) == 0) && (memcmp(ep + 0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) == 0) &&
        ((quint8)ep[0x23] == 0xB9)) {
        nOffset = 0x10;
        if (0x6c - _read_uint32((char *)ep + 0x1f) + _read_uint32((char *)ep + 0x32) == 0xC6) {
            nEcx = _read_uint32((char *)ep + 0x24) - _read_uint32((char *)ep + 0x2a);
            sVersion = "1.3 (variant)";
        }
    }

    // yC 1.x / modified
    if (!nEcx && (memcmp(ep, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", 9) == 0) && ((quint8)ep[0xd] == 0xb9) && (_read_uint16((char *)ep + 0x12) == 0xbd8d) &&
        (memcmp(ep + 0x18, "\x8b\xf7\xac", 3) == 0)) {
        nOffset = -0x18;
        if (0x66 - _read_uint32((char *)ep + 0x9) + _read_uint32((char *)ep + 0x14) == 0xae) {
            nEcx = _read_uint32((char *)ep + 0xe);
            sVersion = "1.x (modified)";
        }
    }

    if ((nEcx <= 0x800) || (nEcx >= 0x2000)) {
        return result;
    }

    qint64 nMarkerIdx = 0x63 + nOffset;
    if ((nMarkerIdx < 0) || (nMarkerIdx + 3 > baEp.size()) || (memcmp(ep + nMarkerIdx, "\xaa\xe2\xcc", 3) != 0)) {
        return result;
    }

    const qint64 nFileSize = getSize();
    const qint64 nLastRaw = listSections.at(n - 1).PointerToRawData;
    const qint64 nYcSect = nLastRaw + nOffset;
    const auto isRangeWithinFile = [nFileSize](qint64 nOffset, qint64 nSize) -> bool {
        return (nFileSize >= 0) && (nOffset >= 0) && (nSize >= 0) &&
               (nOffset <= nFileSize) && (nSize <= nFileSize - nOffset);
    };
    // yc.c consumes both regions unconditionally: the first-layer encrypted
    // code and the stored original entry point.  Reject a partial candidate
    // here instead of publishing an output with the packed OEP left intact.
    if (!isRangeWithinFile(nYcSect + 0xc6, nEcx) ||
        !isRangeWithinFile(nYcSect + 0xa0f, 4)) {
        return result;
    }

    result.bIsValid = true;
    result.sVersion = sVersion;
    result.nOffset = nOffset;
    result.nEcx = nEcx;

    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XYODA::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XYODA::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool {
        return !pPdStruct || isPdStructLifetimeAlive(progressLifetime);
    };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XYODA> guardedThis(this);

    if (pState->pContext || !pState->baUnpackSourceToken.isEmpty()) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pOldContext || !pLifetimeState->setContexts.contains(pOldContext) ||
            (pOldContext->pOwnerState != pState) ||
            (pOldContext->baToken != pState->baUnpackSourceToken)) return false;
        pLifetimeState->setContexts.remove(pOldContext);
        *pState = UNPACK_STATE();
        delete pOldContext;
    } else {
        *pState = UNPACK_STATE();
    }
    if (!isProgressAlive() || !guardedThis || !isPdStructNotCanceled(pPdStruct)) return false;
    const QSharedPointer<LIFETIME_STATE> pOwnerLifetimeState = pLifetimeState;

    QPointer<QIODevice> guardedSource(getDevice());
    const quint64 nGeneration = getDeviceGeneration();
    const bool bIsImage = isImage();
    const XADDR nModuleAddress = getModuleAddress();
    if (!guardedSource) return false;
    const QString sFileName = getUnpackedFileName(guardedSource.data());
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;
    const qint64 nSourceSize = guardedSource->size();
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || (nSourceSize < 0)) return false;
    QScopedPointer<XMaterializedUnpackGuard> pSourceGuard(XMaterializedUnpackGuard::bind(guardedSource.data(), pPdStruct));
    if (!isProgressAlive() || !pSourceGuard || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    QScopedPointer<QIODevice> pSnapshot(createFileBuffer(nSourceSize, pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pSnapshot ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;
    const bool bCopied = copyDeviceMemory(guardedSource.data(), 0, pSnapshot.data(), 0, nSourceSize, pPdStruct);
    if (!isProgressAlive() || !bCopied || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    XYODA worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !info.bIsValid) return false;
    QByteArray baData;
    const bool bUnpacked = worker._unpackToBuffer(baData, nOutputLimit, pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !bUnpacked || baData.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
    pContext->baData = baData;
    pContext->sFileName = sFileName;
    pContext->sInfo = QString("Yoda %1").arg(info.sVersion);
    pContext->pSourceDevice = guardedSource;
    pContext->pOwnerState = pState;
    pContext->baToken = QUuid::createUuid().toRfc4122();
    pContext->nDeviceGeneration = nGeneration;
    pContext->nSourceSize = nSourceSize;
    pContext->nCurrentOffset = 0;
    pContext->nCurrentIndex = 0;
    if (pContext->baToken.isEmpty()) return false;
    const bool bSourceFinal = pSourceGuard->validateAndFinalize(pPdStruct);
    if (!isProgressAlive() || !bSourceFinal || !guardedThis || !guardedSource ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
        !isPdStructNotCanceled(pPdStruct)) return false;
    pContext->pSourceGuard = pSourceGuard.take();

    pState->nCurrentOffset = 0;
    pState->nTotalSize = nSourceSize;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 1;
    pState->mapUnpackProperties = mapProperties;
    pState->pContext = pContext.data();
    pState->baUnpackSourceToken = pContext->baToken;
    pOwnerLifetimeState->setContexts.insert(pContext.take());
    if (!guardedThis || !pOwnerLifetimeState->bOwnerAlive) return false;
    return true;
}

XBinary::ARCHIVERECORD XYODA::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XYODA> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize)) return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return result;

    result.nStreamOffset = 0;
    result.nStreamSize = pContext->baData.size();
    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, pContext->sFileName);
    result.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, pContext->nSourceSize);
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, (qint64)pContext->baData.size());
    result.mapProperties.insert(FPART_PROP_HANDLEMETHOD, (qint32)HANDLE_METHOD_FILE);
    result.mapProperties.insert(FPART_PROP_ISFOLDER, false);
    result.mapProperties.insert(FPART_PROP_INFO, pContext->sInfo);

    return guardedThis ? result : ARCHIVERECORD();
}

bool XYODA::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= 1) ||
        (pState->nNumberOfRecords != 1) || (pState->nTotalSize != pContext->nSourceSize)) return false;

    return false;
}

bool XYODA::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    if (!pState->pContext && pState->baUnpackSourceToken.isEmpty()) {
        *pState = UNPACK_STATE();
        return true;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pContext || !pLifetimeState->setContexts.contains(pContext) ||
        (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return false;
    pLifetimeState->setContexts.remove(pContext);
    *pState = UNPACK_STATE();
    delete pContext;
    return true;
}

bool XYODA::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XYODA> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !guardedOutput || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize)) return false;

    const bool bOpen = guardedOutput->isOpen();
    if (!guardedThis || !guardedOutput || !bOpen) return false;
    const bool bWritable = guardedOutput->isWritable();
    if (!guardedThis || !guardedOutput || !bWritable) return false;
    const bool bSequential = guardedOutput->isSequential();
    if (!guardedThis || !guardedOutput || bSequential) return false;
    const QIODevice::OpenMode openMode = guardedOutput->openMode();
    if (!guardedThis || !guardedOutput ||
        (openMode & (QIODevice::Append | QIODevice::Text)) ||
        !isResizeEnable(guardedOutput.data())) return false;
    QPointer<QIODevice> guardedSource(pContext->pSourceDevice);
    if (guardedSource && devicesAlias(guardedSource.data(), guardedOutput.data())) return false;
    if (!guardedThis || !guardedOutput) return false;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis || !guardedOutput ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return false;

    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    const bool bResult = writeUnpackData(&writeState, guardedOutput.data(), pContext->baData, pPdStruct);
    const bool bSourceCurrent = bResult && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bAuthenticated = bSourceCurrent && guardedThis && guardedOutput && pLifetimeState->bOwnerAlive &&
                                pLifetimeState->setContexts.contains(pContext) &&
                                (pState->pContext == pContext) && (pContext->pOwnerState == pState) &&
                                (pState->baUnpackSourceToken == pContext->baToken) &&
                                (pState->nCurrentIndex == pContext->nCurrentIndex) &&
                                (pState->nCurrentOffset == pContext->nCurrentOffset) &&
                                (pState->nNumberOfRecords == 1) &&
                                (pState->nTotalSize == pContext->nSourceSize);
    if (!bResult || !bAuthenticated) {
        if (bResult && guardedOutput) {
            resize(guardedOutput.data(), 0);
            if (guardedOutput) guardedOutput->seek(0);
        }
        return false;
    }
    pContext->nCurrentOffset = writeState.nCurrentOffset;
    pState->nCurrentOffset = writeState.nCurrentOffset;
    return true;
}

bool XYODA::_unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) return false;
    const int nSectCount = n - 1;  // yC section is the last one

    const qint64 nFileSize = getSize();
    const qint64 nLastRaw = listSections.at(nSectCount).PointerToRawData;
    const qint64 nDeclaredYcRawSize = listSections.at(nSectCount).SizeOfRawData;
    if ((nFileSize <= 0) || (nFileSize > 0x7fffffff) ||
        (nLastRaw < 0) || (nLastRaw >= nFileSize) ||
        (nDeclaredYcRawSize <= 0)) return false;

    // ClamAV's PE parser stores the unaligned raw size in ursz and truncates
    // it to the bytes available at EOF before yc_decrypt() removes it.  PE
    // files commonly retain an aligned declared size after final padding was
    // stripped, so subtracting the declaration directly loses valid output.
    const qint64 nEffectiveYcRawSize = qMin(nDeclaredYcRawSize, nFileSize - nLastRaw);
    const qint64 nCurFileSize = nFileSize - nEffectiveYcRawSize;
    if ((nCurFileSize <= 0) ||
        ((nOutputLimit >= 0) && ((quint64)nCurFileSize > (quint64)nOutputLimit))) return false;

    QByteArray baFile = read_array_process(0, nFileSize, pPdStruct);
    if (baFile.size() != nFileSize) return false;
    quint8 *pBase = (quint8 *)baFile.data();

    const qint64 nYcSect = nLastRaw + info.nOffset;

    // layer 1: decrypt the section-decryptor code
    if (_polyEmulate(pBase, nFileSize, nYcSect + 0x93, nYcSect + 0xc6, info.nEcx, info.nEcx) != 0) {
        return false;
    }

    // layer 2: decrypt each original section
    const qint64 nDecOff = nYcSect + ((info.nOffset == -0x18) ? 0x3ea : 0x457);

    for (int i = 0; i < nSectCount; i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &sec = listSections.at(i);
        const quint32 nName = _read_uint32((char *)sec.Name);

        if ((sec.PointerToRawData == 0) || (sec.SizeOfRawData == 0) || (nName == 0x63727372) || (nName == 0x7273722E) || (nName == 0x6F6C6572) ||
            (nName == 0x6C65722E) || (nName == 0x6164652E) || (nName == 0x6164722E) || (nName == 0x6164692E) || (nName == 0x736C742E) ||
            ((nName & 0xffff) == 0x4379)) {
            continue;
        }

        // yc.c detects the unsigned underflow in (filesize - raw) and aborts.
        // Silently skipping this case would publish a partially decrypted PE.
        if ((qint64)sec.PointerToRawData >= nCurFileSize) return false;
        quint32 nMaxEmu = (quint32)(nCurFileSize - sec.PointerToRawData);
        const quint32 nEffectiveRawSize = (quint32)qMin<qint64>(
            sec.SizeOfRawData, nFileSize - sec.PointerToRawData);

        if (_polyEmulate(pBase, nFileSize, nDecOff, sec.PointerToRawData, nEffectiveRawSize, nMaxEmu) != 0) {
            return false;
        }

        if (!isPdStructNotCanceled(pPdStruct)) return false;
    }

    // header fixups
    const qint64 nPeOff = _read_uint32((char *)pBase + 0x3C);
    if ((nPeOff <= 0) || (nPeOff > nCurFileSize) ||
        (0x18 + 0x70 > nCurFileSize - nPeOff) ||
        (nYcSect < 0) || (nYcSect > nFileSize) ||
        (0xa0f + 4 > nFileSize - nYcSect)) return false;

    _write_uint16((char *)pBase + nPeOff + 6, (quint16)nSectCount);           // NumberOfSections
    memset(pBase + nPeOff + 0x18 + 0x68, 0, 8);                               // clear import directory
    _write_uint32((char *)pBase + nPeOff + 0x18 + 16, _read_uint32((char *)pBase + nYcSect + 0xa0f));  // OEP
    quint32 nSizeOfImage = _read_uint32((char *)pBase + nPeOff + 0x18 + 0x38);
    const quint32 nYcVirtualSize = listSections.at(nSectCount).Misc.VirtualSize;
    if (nSizeOfImage < nYcVirtualSize) return false;
    _write_uint32((char *)pBase + nPeOff + 0x18 + 0x38, nSizeOfImage - nYcVirtualSize);  // SizeOfImage

    baOut = baFile.left((int)nCurFileSize);

    return true;
}
