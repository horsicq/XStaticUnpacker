/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xactualinstaller.h"

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xzip.h"

XActualInstaller::XActualInstaller(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XActualInstaller::~XActualInstaller()
{
}

bool XActualInstaller::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XActualInstaller::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XActualInstaller x(pDevice);
    return x.isValid(pPdStruct);
}

XActualInstaller::INTERNAL_INFO XActualInstaller::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XActualInstaller::getFileType()
{
    return FT_ARCHIVE;
}

XActualInstaller::INTERNAL_INFO XActualInstaller::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nArchiveOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    const qint64 nTotalSize = getSize();
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    // Overlay must begin with a local ZIP header (PK\x03\x04).
    QByteArray baHead = read_array_process(nOverlayOffset, 4, pPdStruct);
    if (baHead != QByteArray("\x50\x4B\x03\x04", 4)) return result;

    // Unique marker: the metadata archive's stored "aisetup.ini" entry name.
    if (find_ansiString(nOverlayOffset, nTotalSize - nOverlayOffset, "aisetup.ini", pPdStruct) == -1) return result;

    result.bIsValid = true;
    result.nArchiveOffset = nOverlayOffset;
    result.nArchiveSize = nTotalSize - nOverlayOffset;

    // Edition from the .rsrc DFM caption ("Actual Installer Free" for the Free edition).
    if (find_ansiString(0, nTotalSize, "Actual Installer Free", pPdStruct) != -1) {
        result.sVersion = "Free";
    }

    return result;
}

// --- streaming extraction: delegate to the XArchive ZIP handler ---

bool XActualInstaller::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    pContext->pArchive = new XZip(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD XActualInstaller::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XActualInstaller::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XActualInstaller::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    return bResult;
}

bool XActualInstaller::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
