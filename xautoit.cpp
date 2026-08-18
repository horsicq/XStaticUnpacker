/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xautoit.h"
#include "xmaterializedunpackguard.h"
#include "xpe.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <cstring>

static inline quint32 aiRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 aiBe32(const quint8 *p)
{
    return (quint32)(((quint32)p[0] << 24) | ((quint32)p[1] << 16) | ((quint32)p[2] << 8) | p[3]);
}

// MSB-first bit reader for the AutoIt custom inflate stream.
struct AI_BITREADER {
    const quint8 *pInput;
    quint32 nCsize;
    quint32 full;
    quint32 bits_avail;
    quint32 cur_input;
    bool error;
};

static quint32 aiGetBits(AI_BITREADER *br, quint32 sz)
{
    br->full &= 0x0000ffff;  // clear high half
    if ((sz > br->bits_avail) && (((sz - br->bits_avail - 1) / 16 + 1) * 2 > br->nCsize - br->cur_input)) {
        br->error = true;
        return 0;
    }
    while (sz) {
        if (!br->bits_avail) {
            if (br->cur_input + 2 > br->nCsize) {
                br->error = true;
                return (br->full >> 16) & 0xffff;
            }
            quint32 low = br->full & 0xffff;
            low |= (quint32)br->pInput[br->cur_input++] << 8;
            low |= br->pInput[br->cur_input++];
            br->full = (br->full & 0xffff0000) | (low & 0xffff);
            br->bits_avail = 16;
        }
        br->full <<= 1;
        br->bits_avail--;
        sz--;
    }
    return (br->full >> 16) & 0xffff;
}

XAUTOIT::XAUTOIT(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XAUTOIT::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XAUTOIT::~XAUTOIT()
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

XAUTOIT::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XAUTOIT::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive &&
           !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XAUTOIT::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XAUTOIT> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XAUTOIT::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XAUTOIT a(pDevice);
    return a.isValid(pPdStruct);
}

XBinary::FT XAUTOIT::getFileType()
{
    XPE pe(getDevice());

    if (pe.isValid() && pe.is64()) {
        return FT_PE64_AUTOIT;
    }

    return FT_PE32_AUTOIT;
}

// ---------------------------------------------------------------------------
// MT stream cipher
// ---------------------------------------------------------------------------

void XAUTOIT::_mtDecrypt(quint8 *pBuf, quint32 nSize, quint32 nSeed)
{
    quint32 mt[624];
    mt[0] = nSeed;
    for (unsigned i = 1; i < 624; i++) {
        mt[i] = i + 0x6c078965 * ((mt[i - 1] >> 30) ^ mt[i - 1]);
    }
    quint32 items = 1;
    quint32 nextIdx = 0;

    while (nSize--) {
        if (!--items) {
            items = 624;
            nextIdx = 0;
            unsigned i;
            for (i = 0; i < 227; i++)
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0u - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i + 397];
            for (; i < 623; i++)
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0u - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i - 227];
            mt[623] = ((((mt[623] ^ mt[0]) & 0x7ffffffe) ^ mt[623]) >> 1) ^ ((0u - (mt[0] & 1)) & 0x9908b0df) ^ mt[i - 227];
        }
        quint32 r = mt[nextIdx++];
        r ^= (r >> 11);
        r ^= ((r & 0xff3a58ad) << 7);
        r ^= ((r & 0xffffdf8c) << 15);
        r ^= (r >> 18);
        *pBuf++ ^= (quint8)(r >> 1);
    }
}

// ---------------------------------------------------------------------------
// custom inflate
// ---------------------------------------------------------------------------

bool XAUTOIT::_inflate(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize)
{
    quint32 cur_output = 0;

    AI_BITREADER br;
    br.pInput = pInput;
    br.nCsize = nCsize;
    br.full = 0;
    br.bits_avail = 0;
    br.cur_input = 8;
    br.error = false;

    while (!br.error && (cur_output < nUsize)) {
        if (aiGetBits(&br, 1)) {
            quint32 bb = aiGetBits(&br, 15);
            quint32 bs, addme = 0;
            if ((bs = aiGetBits(&br, 2)) == 3) {
                addme = 3;
                if ((bs = aiGetBits(&br, 3)) == 7) {
                    addme = 10;
                    if ((bs = aiGetBits(&br, 5)) == 31) {
                        addme = 41;
                        if ((bs = aiGetBits(&br, 8)) == 255) {
                            addme = 296;
                            while ((bs = aiGetBits(&br, 8)) == 255) addme += 255;
                        }
                    }
                }
            }
            bs += 3 + addme;
            if (br.error) break;
            if ((bb == 0) || (bb > cur_output) || ((quint64)cur_output + bs > nUsize)) {
                br.error = true;
                break;
            }
            while (bs--) {
                pOutput[cur_output] = pOutput[cur_output - bb];
                cur_output++;
            }
        } else {
            if (cur_output >= nUsize) break;
            pOutput[cur_output++] = (quint8)aiGetBits(&br, 8);
        }
    }

    // partial output is acceptable (matches reference behaviour)
    return (cur_output > 0);
}

// ---------------------------------------------------------------------------
// unicode -> ascii (for names)
// ---------------------------------------------------------------------------

quint32 XAUTOIT::_u2a(quint8 *pDest, quint32 nLen)
{
    quint8 *src = pDest;
    quint32 i, j;

    if (nLen < 2) return nLen;

    if ((nLen > 4) && (src[0] == 0xff) && (src[1] == 0xfe) && src[2]) {
        nLen -= 2;
        src += 2;
    } else {
        quint32 cnt = 0;
        j = (nLen > 20) ? 20 : (nLen & ~1u);
        for (i = 0; i < j; i += 2) cnt += (src[i] != 0 && src[i + 1] == 0);
        if (cnt * 4 < j) return nLen;
    }

    j = nLen;
    nLen >>= 1;
    for (i = 0; i < j; i += 2) *pDest++ = src[i];
    return nLen;
}

// ---------------------------------------------------------------------------
// EA05 record parser
// ---------------------------------------------------------------------------

QList<XAUTOIT::RECORD> XAUTOIT::_parseEA05(const quint8 *pData, qint64 nSize, qint64 nBase, PDSTRUCT *pPdStruct)
{
    QList<RECORD> listResult;

    if (nBase + 16 > nSize) return listResult;

    quint32 m4sum = 0;
    for (int i = 0; i < 16; i++) m4sum += pData[nBase + i];
    nBase += 16;

    while (isPdStructNotCanceled(pPdStruct)) {
        if (nBase + 8 > nSize) break;
        if (aiRd32(pData + nBase) != 0xceb06dff) break;  // FILE magic

        quint32 s1 = aiRd32(pData + nBase + 4) ^ 0x29bc;
        if ((qint32)s1 < 0) break;
        nBase += 8;
        if (nBase + s1 > nSize) break;
        nBase += s1;  // skip magic string

        if (nBase + 4 > nSize) break;
        quint32 s2 = aiRd32(pData + nBase) ^ 0x29ac;
        if ((qint32)s2 < 0) break;
        nBase += 4;
        if (nBase + s2 > nSize) break;

        QByteArray baName((const char *)(pData + nBase), (int)s2);
        _mtDecrypt((quint8 *)baName.data(), s2, s2 + 0xf25e);
        quint32 nNameLen = _u2a((quint8 *)baName.data(), s2);
        baName.resize((int)nNameLen);
        nBase += s2;

        if (nBase + 13 > nSize) break;
        quint8 comp = pData[nBase];
        quint32 csize = aiRd32(pData + nBase + 1) ^ 0x45aa;
        if ((qint32)csize < 0) break;

        if (!csize) {
            nBase += 13 + 16;
            continue;
        }
        nBase += 13 + 16;
        if (nBase + csize > nSize) break;

        QByteArray baInput((const char *)(pData + nBase), (int)csize);
        nBase += csize;
        _mtDecrypt((quint8 *)baInput.data(), csize, 0x22af + m4sum);

        QByteArray baOutput;
        if (comp == 1) {
            if (csize < 8) continue;
            if (aiRd32((const quint8 *)baInput.constData()) != 0x35304145) continue;  // "EA05"
            quint32 usize = aiBe32((const quint8 *)baInput.constData() + 4);
            if (!usize) usize = csize;
            if (usize > (256u * 1024 * 1024)) continue;
            baOutput.resize((int)usize);
            memset(baOutput.data(), 0, usize);
            if (!_inflate((const quint8 *)baInput.constData(), csize, (quint8 *)baOutput.data(), usize)) {
                continue;
            }
        } else {
            baOutput = baInput;
        }

        if (baOutput.size() < 4) continue;

        RECORD rec;
        rec.sName = QString::fromLatin1(baName.constData(), baName.size());
        if (rec.sName.isEmpty()) {
            rec.sName = QString("autoit_%1").arg(listResult.size(), 3, 10, QChar('0'));
        }
        rec.baData = baOutput;
        listResult.append(rec);

        if (listResult.size() > 100000) break;
    }

    return listResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XAUTOIT::INTERNAL_INFO XAUTOIT::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nMarkerOffset = -1;

    qint64 nSize = getSize();
    if (nSize < 24) return result;

    qint64 nOff = find_ansiString(0, nSize, "AU3!EA05", pPdStruct);
    if (nOff != -1) {
        result.bIsValid = true;
        result.nVersion = 5;
        result.sVersion = "EA05";
        result.nMarkerOffset = nOff;
        return result;
    }

    nOff = find_ansiString(0, nSize, "AU3!EA06", pPdStruct);
    if (nOff != -1) {
        result.bIsValid = true;
        result.nVersion = 6;
        result.sVersion = "EA06 (unsupported)";
        result.nMarkerOffset = nOff;
        return result;
    }

    return result;
}

XAUTOIT::INTERNAL_INFO XAUTOIT::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XAUTOIT::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XAUTOIT> guardedThis(this);
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

void *XAUTOIT::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XAUTOIT> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XAUTOIT::setInternalInfo(void *pInternalInfo)
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
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XAUTOIT::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XAUTOIT::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool {
        return !pPdStruct || isPdStructLifetimeAlive(progressLifetime);
    };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);

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

    XAUTOIT worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !info.bIsValid) return false;

    QList<RECORD> listRecords;
    if (info.nVersion == 5) {
        const qint64 nWorkerSize = worker.getSize();
        QByteArray baFile = worker.read_array_process(0, nWorkerSize, pPdStruct);
        if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data()) || (nWorkerSize < 0) ||
            ((qint64)baFile.size() != nWorkerSize)) return false;
        listRecords = worker._parseEA05(reinterpret_cast<const quint8 *>(baFile.constData()),
                                        baFile.size(), info.nMarkerOffset + 8, pPdStruct);
        if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data()) || listRecords.isEmpty()) return false;
    }
    // EA06 remains detected but intentionally has no extractable records.
    if (!isProgressAlive() || !isPdStructNotCanceled(pPdStruct)) return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
    pContext->listRecords = listRecords;
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
    pState->nNumberOfRecords = listRecords.size();
    pState->mapUnpackProperties = mapProperties;
    pState->pContext = pContext.data();
    pState->baUnpackSourceToken = pContext->baToken;
    pOwnerLifetimeState->setContexts.insert(pContext.take());
    if (!guardedThis || !pOwnerLifetimeState->bOwnerAlive) return false;
    return true;
}

XBinary::ARCHIVERECORD XAUTOIT::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize)) return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nNumberOfRecords != pContext->listRecords.size())) return result;
    const qint32 nIndex = pContext->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return result;

    const RECORD &rec = pContext->listRecords.at(nIndex);
    result.nStreamOffset = 0;
    result.nStreamSize = rec.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = rec.sName.isEmpty() ? QString("autoit_%1").arg(nIndex, 3, 10, QChar('0')) : rec.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)rec.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;

    return guardedThis ? result : ARCHIVERECORD();
}

bool XAUTOIT::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
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
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize)) return false;
    const qint32 nIndex = pContext->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return false;

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

    const QByteArray &baData = pContext->listRecords.at(nIndex).baData;
    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    const bool bResult = writeUnpackData(&writeState, guardedOutput.data(), baData, pPdStruct);
    const bool bSourceCurrent = bResult && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bAuthenticated = bSourceCurrent && guardedThis && guardedOutput && pLifetimeState->bOwnerAlive &&
                                pLifetimeState->setContexts.contains(pContext) &&
                                (pState->pContext == pContext) && (pContext->pOwnerState == pState) &&
                                (pState->baUnpackSourceToken == pContext->baToken) &&
                                (pState->nCurrentIndex == pContext->nCurrentIndex) &&
                                (pState->nCurrentOffset == pContext->nCurrentOffset) &&
                                (pState->nNumberOfRecords == pContext->listRecords.size()) &&
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

bool XAUTOIT::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize) ||
        (pContext->nCurrentIndex < 0) ||
        (pContext->nCurrentIndex >= pContext->listRecords.size() - 1)) return false;

    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pContext->nCurrentIndex >= pContext->listRecords.size() - 1)) return false;

    ++pContext->nCurrentIndex;
    pContext->nCurrentOffset = 0;
    pState->nCurrentIndex = pContext->nCurrentIndex;
    pState->nCurrentOffset = 0;
    return true;
}

bool XAUTOIT::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
