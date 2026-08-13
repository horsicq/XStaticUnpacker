/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xwinrarsfx.h"

#include <QScopedValueRollback>

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xrar.h"

XWinRarSfx::UNPACK_DEFERRED_CLEANUP::~UNPACK_DEFERRED_CLEANUP()
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

XWinRarSfx::XWinRarSfx(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackDeferredCleanup = QSharedPointer<UNPACK_DEFERRED_CLEANUP>::create();
    const QSharedPointer<UNPACK_DEFERRED_CLEANUP> pDeferredCleanup = m_pUnpackDeferredCleanup;
    m_pUnpackOperationState = QSharedPointer<bool>(new bool(false), [pDeferredCleanup](bool *pValue) { delete pValue; });
    m_internalInfo = INTERNAL_INFO();
    setIsArchive(true);
}

XWinRarSfx::~XWinRarSfx()
{
    if (m_pUnpackOperationState) *m_pUnpackOperationState = true;
    if (m_pUnpackDeferredCleanup) {
        m_pUnpackDeferredCleanup->setContexts.unite(m_setUnpackContexts);
        m_setUnpackContexts.clear();
    }
    m_pUnpackDeferredCleanup.clear();
    m_pUnpackOperationState.clear();
}

bool XWinRarSfx::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XWinRarSfx> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XWinRarSfx::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XWinRarSfx x(pDevice);
    return x.isValid(pPdStruct);
}

XWinRarSfx::INTERNAL_INFO XWinRarSfx::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XWinRarSfx::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XWinRarSfx> guardedThis(this);
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

void *XWinRarSfx::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XWinRarSfx> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XWinRarSfx::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XWinRarSfx::getFileType()
{
    return FT_ARCHIVE;
}

XWinRarSfx::INTERNAL_INFO XWinRarSfx::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nArchiveOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    const qint64 nTotalSize = getSize();
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    QByteArray baHead = read_array_process(nOverlayOffset, 8, pPdStruct);
    if (baHead.size() < 8) return result;
    const quint8 *p = (const quint8 *)baHead.constData();

    // RAR signature at overlay start (RAR5 = ..07 01 00, RAR4 = ..07 00).
    bool bRar5 = (p[0] == 0x52) && (p[1] == 0x61) && (p[2] == 0x72) && (p[3] == 0x21) && (p[4] == 0x1A) && (p[5] == 0x07) && (p[6] == 0x01) && (p[7] == 0x00);
    bool bRar4 = (p[0] == 0x52) && (p[1] == 0x61) && (p[2] == 0x72) && (p[3] == 0x21) && (p[4] == 0x1A) && (p[5] == 0x07) && (p[6] == 0x00);
    if (!bRar5 && !bRar4) return result;

    // Attribution must come from the PE stub, not from an arbitrary file in
    // the appended archive that happens to contain a WinRAR marker string.
    bool bWinRar = (find_ansiString(0, nOverlayOffset, "name=\"WinRAR", pPdStruct) != -1) ||
                   (find_ansiString(0, nOverlayOffset, "sfxrar", pPdStruct) != -1) ||
                   (find_ansiString(0, nOverlayOffset, "sfxcon", pPdStruct) != -1);
    if (!bWinRar) return result;

    qint64 nArchiveSize = nTotalSize - nOverlayOffset;
    SubDevice subDevice(getDevice(), nOverlayOffset, nArchiveSize);
    if (!subDevice.open(QIODevice::ReadOnly)) return result;

    XRar archive(&subDevice);
    XBinary::FILEFORMATINFO archiveInfo = archive.getFileFormatInfo(pPdStruct);
    qint64 nLogicalArchiveSize = archiveInfo.nSize;
    subDevice.close();
    if (!archiveInfo.bIsValid || (nLogicalArchiveSize <= 0) || (nLogicalArchiveSize > nArchiveSize)) return result;

    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    result.bIsValid = true;
    result.nArchiveOffset = nOverlayOffset;
    result.nArchiveSize = nLogicalArchiveSize;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();  // console modules only
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    if (!XBinary::isPdStructNotCanceled(pPdStruct)) result.bIsValid = false;

    return result;
}

// --- streaming extraction: delegate to the XArchive RAR handler ---

QMap<XBinary::UNPACK_PROP, QVariant> XWinRarSfx::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    QIODevice *pDevice = getDevice();

    if (pDevice) {
        INTERNAL_INFO info = _detect(nullptr);

        if (info.bIsValid && (info.nArchiveOffset >= 0) && (info.nArchiveSize > 0)) {
            SubDevice subDevice(pDevice, info.nArchiveOffset, info.nArchiveSize);

            if (subDevice.open(QIODevice::ReadOnly)) {
                {
                    XRar archive(&subDevice);
                    QMap<UNPACK_PROP, QVariant> mapInnerProperties = archive.getDefaultUnpackProperties();

                    if (mapInnerProperties.contains(UNPACK_PROP_PASSWORD)) {
                        result.insert(UNPACK_PROP_PASSWORD, mapInnerProperties.value(UNPACK_PROP_PASSWORD));
                    }

                    for (QMap<UNPACK_PROP, QVariant>::const_iterator it = mapInnerProperties.constBegin(); it != mapInnerProperties.constEnd(); ++it) {
                        if (XBinary::isUnpackCRCProperty(it.key())) {
                            result.insert(it.key(), it.value());
                        }
                    }
                }

                subDevice.close();
            }
        }
    }

    return result;
}

bool XWinRarSfx::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XWinRarSfx> guardedThis(this);
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
    XWinRarSfx detector(guardedSource.data(), isImage(), getModuleAddress());
    INTERNAL_INFO info = detector._detect(pPdStruct);
    if (!guardedThis || !guardedSource || !info.bIsValid || (info.nArchiveOffset < 0) || (info.nArchiveSize <= 0)) return false;
    const qint64 nTotalSize = guardedSource->size();
    if (!guardedThis || !guardedSource || (nTotalSize < 0)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pOuterSourceDevice = guardedSource;
    pContext->nOwnerDeviceGeneration = getDeviceGeneration();
    pContext->pSubDevice = new SubDevice(guardedSource.data(), info.nArchiveOffset, info.nArchiveSize);
    pContext->pArchive = nullptr;
    pContext->innerState = UNPACK_STATE();

    if (!pContext->pSubDevice->open(QIODevice::ReadOnly)) {
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    pContext->pArchive = new XRar(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD XWinRarSfx::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return result;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XWinRarSfx> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) return result;
    result = pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return ARCHIVERECORD();
    return result;
}

bool XWinRarSfx::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XWinRarSfx> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !guardedOutput || !guardedOutput->isOpen() ||
        !guardedOutput->isWritable() || guardedOutput->isSequential() || !guardedThis || !guardedOutput ||
        (guardedOutput->openMode() & (QIODevice::Append | QIODevice::Text)) ||
        !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) return false;
    bool bResult = pContext->pArchive->unpackCurrent(&pContext->innerState, guardedOutput.data(), pPdStruct);
    if (!guardedThis || !guardedOutput || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    return bResult;
}

bool XWinRarSfx::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XWinRarSfx> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) return false;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    return bResult;
}

bool XWinRarSfx::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState) return false;
    if (!pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XWinRarSfx> guardedThis(this);
    bool bResult = true;

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState)) return false;
        m_setUnpackContexts.remove(pContext);
        pState->pContext = nullptr;
        if (pContext->pArchive) {
            bResult = pContext->pArchive->finishUnpack(&pContext->innerState, nullptr) && bResult;
            delete pContext->pArchive;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
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
