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
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XIExpress::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XIExpress x(pDevice);
    return x.isValid(pPdStruct);
}

XIExpress::INTERNAL_INFO XIExpress::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XIExpress::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(true);
        m_internalInfo = _getInternalInfo(pPdStruct);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XIExpress::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XIExpress::setInternalInfo(void *pInternalInfo)
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
    qint64 nTotalSize = getSize();
    if ((rrCab.nOffset <= 0) || (rrCab.nSize < (qint64)sizeof(XCab::CFHEADER)) || (rrCab.nOffset > nTotalSize) ||
        (rrCab.nSize > nTotalSize - rrCab.nOffset)) {
        return result;
    }

    QByteArray baMagic = read_array_process(rrCab.nOffset, 4, pPdStruct);
    if (baMagic != QByteArray("MSCF", 4)) return result;

    // Harden: a Wextract-only sibling resource / marker (kills generic cab-in-resource).
    XPE::RESOURCE_RECORD rrRun = XPE::getResourceRecord(IEXPRESS_RT_RCDATA, "RUNPROGRAM", &listResources);
    bool bWextract = (rrRun.nOffset > 0) || (find_ansiStringI(0, getSize(), "wextract", pPdStruct) != -1) ||
                     (find_ansiString(0, getSize(), "IExpress extraction tool", pPdStruct) != -1);
    if (!bWextract) return result;

    // Authenticate the complete cabinet table during detection.  A resource
    // named CABINET with only an MSCF prefix is not a usable IExpress payload.
    SubDevice cabinetDevice(getDevice(), rrCab.nOffset, rrCab.nSize);
    if (!cabinetDevice.open(QIODevice::ReadOnly)) return result;

    XCab cabinet(&cabinetDevice);
    UNPACK_STATE state = {};
    QMap<UNPACK_PROP, QVariant> mapProperties;
    bool bCabinetValid = cabinet.initUnpack(&state, mapProperties, pPdStruct);
    if (bCabinetValid) {
        cabinet.finishUnpack(&state, pPdStruct);
    }
    cabinetDevice.close();

    if (!bCabinetValid || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    result.bIsValid = true;
    result.nArchiveOffset = rrCab.nOffset;
    result.nArchiveSize = rrCab.nSize;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    return result;
}

// --- streaming extraction: delegate to the XArchive CAB handler ---

QMap<XBinary::UNPACK_PROP, QVariant> XIExpress::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

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
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
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
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    return bResult;
}

bool XIExpress::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        if (pContext->pArchive) {
            bResult = pContext->pArchive->finishUnpack(&pContext->innerState, pPdStruct);
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
    return bResult;
}
