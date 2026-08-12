/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xsfx.h"

#include "subdevice.h"
#include "xmsdos.h"
#include "../XArchive/xsevenzip.h"
#include "../XArchive/xrar.h"
#include "../XArchive/xcab.h"

XSFX::XSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_internalInfo = INTERNAL_INFO();
    setIsArchive(true);
}

XSFX::~XSFX()
{
}

bool XSFX::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
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
    if (!isInternalInfoHandled()) {
        INTERNAL_INFO info = _getInternalInfo(pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        info.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        m_internalInfo = info;
        setIsInternalInfoHandled(true);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XSFX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
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
    return FT_ARCHIVE;
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

    // 1) Preferred: the archive sits in the PE overlay.
    qint64 nOverlayOffset = getOverlayOffset(pPdStruct);
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

                    for (auto it = mapInnerProperties.constBegin(); it != mapInnerProperties.constEnd(); ++it) {
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
    if (pState->pContext && !finishUnpack(pState, nullptr)) return false;
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) {
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->info = info;
    pContext->pSubDevice = nullptr;
    pContext->pArchive = nullptr;
    pContext->innerState = UNPACK_STATE();

    pContext->pSubDevice = new SubDevice(getDevice(), info.nArchiveOffset, info.nArchiveSize);
    if (!pContext->pSubDevice->open(QIODevice::ReadOnly)) {
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

    if (!pContext->pArchive->initUnpack(&pContext->innerState, mapProperties, pPdStruct)) {
        delete pContext->pArchive;
        pContext->pSubDevice->close();
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->innerState.nNumberOfRecords;
    pState->nTotalSize = getSize();
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    pState->pContext = pContext;

    return true;
}

XBinary::ARCHIVERECORD XSFX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};

    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) {
        return result;
    }

    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XSFX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) {
        return false;
    }

    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    return bResult;
}

bool XSFX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) {
        return false;
    }

    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;

    return bResult;
}

bool XSFX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

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
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();

    return bResult;
}
