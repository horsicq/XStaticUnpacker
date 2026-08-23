/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xsfx.h"

#include <QScopedValueRollback>

#include "subdevice.h"
#include "xmsdos.h"
#include "xpe.h"
#include "../XArchive/xsevenzip.h"
#include "../XArchive/xrar.h"
#include "../XArchive/xcab.h"

XSFX::UNPACK_DEFERRED_CLEANUP::~UNPACK_DEFERRED_CLEANUP()
{
    const QSet<UNPACK_CONTEXT *> contexts = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : contexts) {
        if (pContext->pArchive) {
            pContext->pArchive->finishUnpack(&pContext->innerState, nullptr);
            delete pContext->pArchive;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
        }
        delete pContext;
    }
}

XSFX::XSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackDeferredCleanup = QSharedPointer<UNPACK_DEFERRED_CLEANUP>::create();
    const QSharedPointer<UNPACK_DEFERRED_CLEANUP> pDeferredCleanup = m_pUnpackDeferredCleanup;
    m_pUnpackOperationState = QSharedPointer<bool>(new bool(false), [pDeferredCleanup](bool *pValue) { delete pValue; });
    m_internalInfo = INTERNAL_INFO();
    setIsArchive(true);
}

XSFX::~XSFX()
{
    if (m_pUnpackOperationState) *m_pUnpackOperationState = true;
    if (m_pUnpackDeferredCleanup) {
        m_pUnpackDeferredCleanup->setContexts.unite(m_setUnpackContexts);
        m_setUnpackContexts.clear();
    }
    m_pUnpackDeferredCleanup.clear();
    m_pUnpackOperationState.clear();
}

bool XSFX::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XSFX> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}

XSFX::INTERNAL_INFO XSFX::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XSFX::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XSFX> guardedThis(this);
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

void *XSFX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XSFX> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XSFX::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XSFX::getFileType()
{
    XPE pe(getDevice());

    if (pe.isValid() && pe.is64()) {
        return FT_PE64_SFX;
    }

    return FT_PE32_SFX;
}

QString XSFX::getArch()
{
    XMSDOS msdos(getDevice(), isImage(), getModuleAddress());
    if (msdos.isValid()) {
        return msdos.getArch();
    }
    return QString();
}

XBinary::MODE XSFX::getMode()
{
    return MODE_DATA;
}

QString XSFX::getMIMEString()
{
    return "application/x-sfx";
}

bool XSFX::_matchArchiveAt(qint64 nOffset, qint64 nSize, ARCTYPE *pType, qint64 *pArchiveSize, PDSTRUCT *pPdStruct)
{
    const qint64 nTotalSize = getSize();
    if (!pType || !pArchiveSize || (nOffset < 0) || (nSize < 8) || (nOffset > nTotalSize) ||
        (nSize > nTotalSize - nOffset) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    QByteArray baMagic = read_array_process(nOffset, 8, pPdStruct);
    if (baMagic.size() < 6) {
        return false;
    }
    const quint8 *p = (const quint8 *)baMagic.constData();

    ARCTYPE candidate = ARC_UNKNOWN;

    if ((p[0] == 0x37) && (p[1] == 0x7A) && (p[2] == 0xBC) && (p[3] == 0xAF) && (p[4] == 0x27) && (p[5] == 0x1C)) {
        candidate = ARC_7Z;  // '7z' BC AF 27 1C
    } else if ((p[0] == 0x52) && (p[1] == 0x61) && (p[2] == 0x72) && (p[3] == 0x21) && (p[4] == 0x1A) && (p[5] == 0x07)) {
        candidate = ARC_RAR;  // 'Rar!' 1A 07 (RAR4/RAR5)
    } else if ((p[0] == 0x52) && (p[1] == 0x45) && (p[2] == 0x7E) && (p[3] == 0x5E)) {
        candidate = ARC_RAR;  // 'RE~^' (RAR1.4)
    } else if ((p[0] == 0x4D) && (p[1] == 0x53) && (p[2] == 0x43) && (p[3] == 0x46)) {
        candidate = ARC_CAB;  // 'MSCF'
    } else {
        return false;
    }

    // Confirm the candidate really is a valid archive at that offset.
    SubDevice sub(getDevice(), nOffset, nSize);
    if (!sub.open(QIODevice::ReadOnly)) {
        return false;
    }

    bool bValid = false;
    qint64 nLogicalSize = 0;
    XArchive *pArc = _createArchive(candidate, &sub);
    if (pArc) {
        UNPACK_STATE state = {};
        QMap<UNPACK_PROP, QVariant> properties;
        bValid = pArc->initUnpack(&state, properties, pPdStruct);
        if (bValid) {
            bValid = pArc->finishUnpack(&state, pPdStruct);
        } else if ((candidate == ARC_7Z) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            // Preserve detection of password-protected encoded headers while
            // still requiring a structurally parsed encrypted stream map.
            XSevenZip *pSevenZip = static_cast<XSevenZip *>(pArc);
            bValid = pSevenZip->isValid(pPdStruct) && pSevenZip->isEncrypted();
        }
        if (bValid) nLogicalSize = pArc->getFileFormatSize(pPdStruct);
        delete pArc;
    }
    sub.close();

    if (bValid && (nLogicalSize > 0) && (nLogicalSize <= nSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        *pType = candidate;
        *pArchiveSize = nLogicalSize;
        return true;
    }

    return false;
}

XSFX::INTERNAL_INFO XSFX::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.arcType = ARC_UNKNOWN;

    const qint64 nTotalSize = getSize();
    if (nTotalSize < 0x40) {
        return result;
    }

    // Must be an executable stub (MZ/PE). A bare archive is handled by its own class.
    XMSDOS msdos(getDevice(), isImage(), getModuleAddress());
    if (!msdos.isValid(pPdStruct)) {
        return result;
    }

    // 1) Preferred: the archive sits in the executable overlay.  XSFX itself
    // has XBinary's flat memory map, whose raw extent is the whole input, so
    // asking `this` for the overlay always returned EOF.  Use the parsed stub
    // map instead.
    qint64 nOverlayOffset = -1;
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (pe.isValid(pPdStruct)) {
        nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    } else {
        nOverlayOffset = msdos.getOverlayOffset(pPdStruct);
    }
    if ((nOverlayOffset > 0) && (nOverlayOffset < nTotalSize)) {
        ARCTYPE type = ARC_UNKNOWN;
        qint64 nArchiveSize = 0;
        if (_matchArchiveAt(nOverlayOffset, nTotalSize - nOverlayOffset, &type, &nArchiveSize, pPdStruct)) {
            result.bIsValid = true;
            result.arcType = type;
            result.nArchiveOffset = nOverlayOffset;
            result.nArchiveSize = nArchiveSize;
            return result;
        }
    }

    // 2) Fallback: scan only the executable overlay. Searching mapped PE
    // sections classified ordinary programs containing CAB resources as SFXs.
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    const char *apszSignatures[] = {"377ABCAF271C", "52617221", "52457E5E", "4D534346"};  // 7z, Rar!, RE~^, MSCF
    const qint64 nScanStart = nOverlayOffset;
    qint32 nCandidates = 0;

    for (int i = 0; (i < 4) && (nCandidates < 256) && isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nPos = nScanStart;
        while ((nCandidates < 256) && isPdStructNotCanceled(pPdStruct) &&
               ((nPos = find_signature(nPos, nTotalSize - nPos, apszSignatures[i], nullptr, pPdStruct)) != -1)) {
            ARCTYPE type = ARC_UNKNOWN;
            qint64 nArchiveSize = 0;
            nCandidates++;
            if (_matchArchiveAt(nPos, nTotalSize - nPos, &type, &nArchiveSize, pPdStruct)) {
                result.bIsValid = true;
                result.arcType = type;
                result.nArchiveOffset = nPos;
                result.nArchiveSize = nArchiveSize;
                return result;
            }
            nPos++;
        }
    }

    return result;
}

XArchive *XSFX::_createArchive(ARCTYPE arcType, QIODevice *pDevice)
{
    switch (arcType) {
        case ARC_7Z: return new XSevenZip(pDevice);
        case ARC_RAR: return new XRar(pDevice);
        case ARC_CAB: return new XCab(pDevice);
        default: return nullptr;
    }
}

QMap<XBinary::UNPACK_PROP, QVariant> XSFX::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    QIODevice *pDevice = getDevice();

    if (pDevice) {
        INTERNAL_INFO info = _detect(nullptr);

        if (info.bIsValid && (info.nArchiveOffset >= 0) && (info.nArchiveSize > 0)) {
            SubDevice subDevice(pDevice, info.nArchiveOffset, info.nArchiveSize);

            if (subDevice.open(QIODevice::ReadOnly)) {
                XArchive *pArchive = _createArchive(info.arcType, &subDevice);

                if (pArchive) {
                    QMap<UNPACK_PROP, QVariant> mapInnerProperties = pArchive->getDefaultUnpackProperties();

                    if (mapInnerProperties.contains(UNPACK_PROP_PASSWORD)) {
                        result.insert(UNPACK_PROP_PASSWORD, mapInnerProperties.value(UNPACK_PROP_PASSWORD));
                    }

                    for (QMap<UNPACK_PROP, QVariant>::const_iterator it = mapInnerProperties.constBegin(); it != mapInnerProperties.constEnd(); ++it) {
                        if (XBinary::isUnpackCRCProperty(it.key())) {
                            result.insert(it.key(), it.value());
                        }
                    }

                    delete pArchive;
                }

                subDevice.close();
            }
        }
    }

    return result;
}

bool XSFX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    Q_UNUSED(nOutputLimit)
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    if (!pState->baUnpackSourceToken.isEmpty()) return false;
    if (pState->pContext) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!m_setUnpackContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState)) return false;
        m_setUnpackContexts.remove(pOldContext);
        pState->pContext = nullptr;
        bool bFinishOK = true;
        if (pOldContext->pArchive) {
            bFinishOK = pOldContext->pArchive->finishUnpack(&pOldContext->innerState, nullptr);
            delete pOldContext->pArchive;
        }
        if (pOldContext->pSubDevice) {
            pOldContext->pSubDevice->close();
            delete pOldContext->pSubDevice;
        }
        delete pOldContext;
        *pState = UNPACK_STATE();
        if (!guardedThis || !bFinishOK) return false;
    }
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
    pState->mapUnpackProperties = mapProperties;

    QPointer<QIODevice> guardedSource(getDevice());
    if (!guardedSource) return false;
    XSFX detector(guardedSource.data(), isImage(), getModuleAddress());
    INTERNAL_INFO info = detector._detect(pPdStruct);
    if (!guardedThis || !guardedSource || !info.bIsValid) return false;
    const qint64 nTotalSize = guardedSource->size();
    if (!guardedThis || !guardedSource || (nTotalSize < 0)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pOuterSourceDevice = guardedSource;
    pContext->nOwnerDeviceGeneration = getDeviceGeneration();
    pContext->info = info;
    pContext->pSubDevice = nullptr;
    pContext->pArchive = nullptr;
    pContext->innerState = UNPACK_STATE();

    pContext->pSubDevice = new SubDevice(guardedSource.data(), info.nArchiveOffset, info.nArchiveSize);
    if (!pContext->pSubDevice->open(QIODevice::ReadOnly)) {
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    if (!guardedThis || !guardedSource) {
        pContext->pSubDevice->close();
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    pContext->pArchive = _createArchive(info.arcType, pContext->pSubDevice);
    if (!pContext->pArchive) {
        pContext->pSubDevice->close();
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    if (!pContext->pArchive->initUnpack(&pContext->innerState, mapProperties, pPdStruct) || !guardedThis || !guardedSource) {
        pContext->pArchive->finishUnpack(&pContext->innerState, nullptr);
        delete pContext->pArchive;
        pContext->pSubDevice->close();
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->innerState.nNumberOfRecords;
    pState->nTotalSize = nTotalSize;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    pContext->pOwnerState = pState;
    pState->pContext = pContext;
    m_setUnpackContexts.insert(pContext);

    return true;
}

XBinary::ARCHIVERECORD XSFX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return result;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);

    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return result;
    }

    result = pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return ARCHIVERECORD();
    return result;
}

bool XSFX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !guardedOutput || !guardedOutput->isOpen() ||
        !guardedOutput->isWritable() || guardedOutput->isSequential() || !guardedThis || !guardedOutput ||
        (guardedOutput->openMode() & (QIODevice::Append | QIODevice::Text)) ||
        !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return false;
    }

    bool bResult = pContext->pArchive->unpackCurrent(&pContext->innerState, guardedOutput.data(), pPdStruct);
    if (!guardedThis || !guardedOutput || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    return bResult;
}

bool XSFX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return false;
    }

    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;

    return bResult;
}

bool XSFX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }
    if (!pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);

    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState)) return false;
        m_setUnpackContexts.remove(pContext);
        pState->pContext = nullptr;

        if (pContext->pArchive) {
            bResult = pContext->pArchive->finishUnpack(&pContext->innerState, nullptr);
            delete pContext->pArchive;
            pContext->pArchive = nullptr;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
            pContext->pSubDevice = nullptr;
        }

        delete pContext;
        if (!guardedThis) return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();

    return bResult;
}
