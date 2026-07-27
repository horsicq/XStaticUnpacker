/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xwinrarsfx.h"

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xrar.h"

XWinRarSfx::XWinRarSfx(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XWinRarSfx::~XWinRarSfx()
{
}

bool XWinRarSfx::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XWinRarSfx::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XWinRarSfx x(pDevice);
    return x.isValid(pPdStruct);
}

XWinRarSfx::INTERNAL_INFO XWinRarSfx::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
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

    // Attribution to WinRAR (separates from an arbitrary RAR-appended PE).
    bool bWinRar = (find_ansiString(0, nTotalSize, "name=\"WinRAR", pPdStruct) != -1) || (find_ansiString(0, nTotalSize, "sfxrar", pPdStruct) != -1) ||
                   (find_ansiString(0, nTotalSize, "sfxcon", pPdStruct) != -1);
    if (!bWinRar) return result;

    result.bIsValid = true;
    result.nArchiveOffset = nOverlayOffset;
    result.nArchiveSize = nTotalSize - nOverlayOffset;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();  // console modules only
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    return result;
}

// --- streaming extraction: delegate to the XArchive RAR handler ---

bool XWinRarSfx::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    pContext->pArchive = new XRar(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD XWinRarSfx::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XWinRarSfx::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XWinRarSfx::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    return bResult;
}

bool XWinRarSfx::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
