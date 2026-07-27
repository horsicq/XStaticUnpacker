/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xiexpress.h"

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xcab.h"

// RT_RCDATA resource type id.
#define IEXPRESS_RT_RCDATA 10

XIExpress::XIExpress(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XIExpress::~XIExpress()
{
}

bool XIExpress::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XIExpress::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XIExpress x(pDevice);
    return x.isValid(pPdStruct);
}

XIExpress::INTERNAL_INFO XIExpress::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XIExpress::getFileType()
{
    return FT_ARCHIVE;
}

XIExpress::INTERNAL_INFO XIExpress::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nArchiveOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE::RESOURCE_RECORD> listResources = pe.getResources(10000, pPdStruct);

    // The MSCF cabinet lives in RT_RCDATA "CABINET".
    XPE::RESOURCE_RECORD rrCab = XPE::getResourceRecord(IEXPRESS_RT_RCDATA, "CABINET", &listResources);
    if ((rrCab.nOffset <= 0) || (rrCab.nSize < 8)) return result;

    QByteArray baMagic = read_array_process(rrCab.nOffset, 4, pPdStruct);
    if (baMagic != QByteArray("MSCF", 4)) return result;

    // Harden: a Wextract-only sibling resource / marker (kills generic cab-in-resource).
    XPE::RESOURCE_RECORD rrRun = XPE::getResourceRecord(IEXPRESS_RT_RCDATA, "RUNPROGRAM", &listResources);
    bool bWextract = (rrRun.nOffset > 0) || (find_ansiStringI(0, getSize(), "wextract", pPdStruct) != -1) ||
                     (find_ansiString(0, getSize(), "IExpress extraction tool", pPdStruct) != -1);
    if (!bWextract) return result;

    result.bIsValid = true;
    result.nArchiveOffset = rrCab.nOffset;
    result.nArchiveSize = rrCab.nSize;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    return result;
}

// --- streaming extraction: delegate to the XArchive CAB handler ---

bool XIExpress::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    pContext->pArchive = new XCab(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD XIExpress::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XIExpress::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XIExpress::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    return bResult;
}

bool XIExpress::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
