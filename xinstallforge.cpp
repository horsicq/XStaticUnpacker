/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinstallforge.h"

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xsevenzip.h"
#include "../XArchive/xbzip2.h"
#include "../XArchive/xgzip.h"

XInstallForge::XInstallForge(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XInstallForge::~XInstallForge()
{
}

bool XInstallForge::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XInstallForge::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XInstallForge x(pDevice);
    return x.isValid(pPdStruct);
}

XInstallForge::INTERNAL_INFO XInstallForge::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XInstallForge::getFileType()
{
    return FT_ARCHIVE;
}

XInstallForge::INTERNAL_INFO XInstallForge::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nArchiveOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    const qint64 nTotalSize = getSize();
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    // 13-byte "IFSETUP_START" marker (each byte +1) at the overlay start, then an
    // 8-byte LE length, then the file payload. The payload container depends on the
    // chosen compressor: 7z (lzma/store), raw BZip2 ("BZh"), or gzip/deflate (1F 8B).
    static const char kMarker[13] = {0x4A, 0x47, 0x54, 0x46, 0x55, 0x56, 0x51, 0x60, 0x54, 0x55, 0x42, 0x53, 0x55};
    QByteArray baHead = read_array_process(nOverlayOffset, 29, pPdStruct);
    if (baHead.size() < 29) return result;
    if (memcmp(baHead.constData(), kMarker, 13) != 0) return result;

    const quint8 *pLen = (const quint8 *)baHead.constData() + 13;
    quint64 nLen = 0;
    for (int i = 0; i < 8; i++) nLen |= ((quint64)pLen[i]) << (8 * i);

    const quint8 *pPayload = (const quint8 *)baHead.constData() + 21;
    result.payload = PAYLOAD_UNKNOWN;
    if ((pPayload[0] == 0x37) && (pPayload[1] == 0x7A) && (pPayload[2] == 0xBC) && (pPayload[3] == 0xAF) && (pPayload[4] == 0x27) && (pPayload[5] == 0x1C)) {
        result.payload = PAYLOAD_7Z;
    } else if ((pPayload[0] == 0x42) && (pPayload[1] == 0x5A) && (pPayload[2] == 0x68)) {
        result.payload = PAYLOAD_BZIP2;  // "BZh"
    } else if ((pPayload[0] == 0x1F) && (pPayload[1] == 0x8B)) {
        result.payload = PAYLOAD_GZIP;
    }

    qint64 nArcOff = nOverlayOffset + 21;
    if ((nLen == 0) || ((qint64)(nArcOff + nLen) > nTotalSize)) {
        // Fall back to the rest of the overlay if the length field looks off.
        nLen = (quint64)(nTotalSize - nArcOff);
    }

    result.bIsValid = true;
    result.nArchiveOffset = nArcOff;
    result.nArchiveSize = (qint64)nLen;

    // Engine version from the RT_VERSION "Comments" field ("Created with InstallForge X.Y.Z").
    QString sComments = pe.getResourcesVersionValue("Comments").trimmed();
    int nIdx = sComments.indexOf("InstallForge");
    if (nIdx >= 0) {
        QString sTail = sComments.mid(nIdx + 12).trimmed();
        if (!sTail.isEmpty()) result.sVersion = sTail;
    }

    return result;
}

// --- streaming extraction: delegate to the XArchive 7z handler ---

bool XInstallForge::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || (info.nArchiveOffset < 0) || (info.nArchiveSize <= 0)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pSubDevice = new SubDevice(getDevice(), info.nArchiveOffset, info.nArchiveSize);
    pContext->pArchive = nullptr;
    pContext->innerState = UNPACK_STATE();

    if (!pContext->pSubDevice->open(QIODevice::ReadOnly)) {
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    switch (info.payload) {
        case PAYLOAD_BZIP2: pContext->pArchive = new XBZIP2(pContext->pSubDevice); break;
        case PAYLOAD_GZIP: pContext->pArchive = new XGzip(pContext->pSubDevice); break;
        case PAYLOAD_7Z:
        default: pContext->pArchive = new XSevenZip(pContext->pSubDevice); break;
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

XBinary::ARCHIVERECORD XInstallForge::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XInstallForge::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XInstallForge::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    return bResult;
}

bool XInstallForge::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        if (pContext->pArchive) {
            pContext->pArchive->finishUnpack(&pContext->innerState, pPdStruct);
            delete pContext->pArchive;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
        }
        delete pContext;
        pState->pContext = nullptr;
    }
    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    return true;
}
