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
    setIsArchive(true);
}

XSFX::~XSFX()
{
}

bool XSFX::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

bool XSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}

XSFX::INTERNAL_INFO XSFX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
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

bool XSFX::_matchArchiveAt(qint64 nOffset, qint64 nSize, ARCTYPE *pType, PDSTRUCT *pPdStruct)
{
    if ((nOffset < 0) || (nSize < 8) || (nOffset + nSize > getSize())) {
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
    XArchive *pArc = _createArchive(candidate, &sub);
    if (pArc) {
        bValid = pArc->isValid(pPdStruct);
        delete pArc;
    }
    sub.close();

    if (bValid) {
        *pType = candidate;
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
        if (_matchArchiveAt(nOverlayOffset, nTotalSize - nOverlayOffset, &type, pPdStruct)) {
            result.bIsValid = true;
            result.arcType = type;
            result.nArchiveOffset = nOverlayOffset;
            result.nArchiveSize = nTotalSize - nOverlayOffset;
            return result;
        }
    }

    // 2) Fallback: scan for an archive signature past the PE headers.
    const char *apszSignatures[] = {"377ABCAF271C", "52617221", "4D534346"};  // 7z, Rar!, MSCF
    const qint64 nScanStart = 0x40;

    for (int i = 0; i < 3; i++) {
        qint64 nPos = nScanStart;
        while ((nPos = find_signature(nPos, nTotalSize - nPos, apszSignatures[i], nullptr, pPdStruct)) != -1) {
            ARCTYPE type = ARC_UNKNOWN;
            if (_matchArchiveAt(nPos, nTotalSize - nPos, &type, pPdStruct)) {
                result.bIsValid = true;
                result.arcType = type;
                result.nArchiveOffset = nPos;
                result.nArchiveSize = nTotalSize - nPos;
                return result;
            }
            nPos++;
            if (!isPdStructNotCanceled(pPdStruct)) {
                break;
            }
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

bool XSFX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
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
    pState->pContext = pContext;

    return true;
}

XBinary::ARCHIVERECORD XSFX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};

    if (!pState || !pState->pContext) {
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
    if (!pState || !pState->pContext || !pDevice) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) {
        return false;
    }

    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XSFX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) {
        return false;
    }

    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;

    return bResult;
}

bool XSFX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

        if (pContext->pArchive) {
            pContext->pArchive->finishUnpack(&pContext->innerState, pPdStruct);
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
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}
