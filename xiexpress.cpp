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
    m_internalInfo = INTERNAL_INFO();
    setIsArchive(true);
}

XIExpress::~XIExpress()
{
}

bool XIExpress::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
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
    if ((listResources.size() >= 10000) || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    // The MSCF cabinet lives in RT_RCDATA "CABINET".
    XPE::RESOURCE_RECORD rrCab = {};
    rrCab.nOffset = -1;
    for (const XPE::RESOURCE_RECORD &record : listResources) {
        if (record.irin[0].bIsName || !record.irin[1].bIsName ||
            (record.irin[0].nID != IEXPRESS_RT_RCDATA) || (record.irin[1].sName != QStringLiteral("CABINET"))) continue;
        if (rrCab.nOffset < 0) {
            rrCab = record;
        } else if ((rrCab.nOffset != record.nOffset) || (rrCab.nSize != record.nSize)) {
            // Different language entries must not select ambiguous payloads.
            return result;
        }
    }
    qint64 nTotalSize = getSize();
    if ((rrCab.nOffset <= 0) || (rrCab.nSize < (qint64)sizeof(XCab::CFHEADER)) || (rrCab.nOffset > nTotalSize) ||
        (rrCab.nSize > nTotalSize - rrCab.nOffset)) {
        return result;
    }

    QByteArray baMagic = read_array_process(rrCab.nOffset, 4, pPdStruct);
    if (baMagic != QByteArray("MSCF", 4)) return result;

    // Harden: a Wextract-only sibling resource / marker (kills generic cab-in-resource).
    const qint64 nCabinetEnd = rrCab.nOffset + rrCab.nSize;
    bool bRunResource = false;
    for (const XPE::RESOURCE_RECORD &record : listResources) {
        if (!record.irin[0].bIsName && record.irin[1].bIsName &&
            (record.irin[0].nID == IEXPRESS_RT_RCDATA) && (record.irin[1].sName == QStringLiteral("RUNPROGRAM")) &&
            (record.nOffset > 0) && (record.nSize > 0) && (record.nSize <= (1 << 20)) && (record.nOffset <= nTotalSize) &&
            (record.nSize <= nTotalSize - record.nOffset) &&
            (((record.nOffset + record.nSize) <= rrCab.nOffset) || (record.nOffset >= nCabinetEnd))) {
            bRunResource = true;
            break;
        }
    }
    auto findStubString = [&](const QString &sString, bool bCaseInsensitive) -> bool {
        qint64 nFound = bCaseInsensitive ? find_ansiStringI(0, rrCab.nOffset, sString, pPdStruct)
                                         : find_ansiString(0, rrCab.nOffset, sString, pPdStruct);
        if (nFound != -1) return true;
        nFound = bCaseInsensitive ? find_ansiStringI(nCabinetEnd, nTotalSize - nCabinetEnd, sString, pPdStruct)
                                  : find_ansiString(nCabinetEnd, nTotalSize - nCabinetEnd, sString, pPdStruct);
        return nFound != -1;
    };
    bool bWextract = bRunResource || findStubString(QStringLiteral("wextract"), true) ||
                     findStubString(QStringLiteral("IExpress extraction tool"), false);
    if (!bWextract) return result;

    // Authenticate the complete cabinet table during detection.  A resource
    // named CABINET with only an MSCF prefix is not a usable IExpress payload.
    SubDevice cabinetDevice(getDevice(), rrCab.nOffset, rrCab.nSize);
    if (!cabinetDevice.open(QIODevice::ReadOnly)) return result;

    XCab cabinet(&cabinetDevice);
    UNPACK_STATE state = {};
    QMap<UNPACK_PROP, QVariant> mapProperties;
    bool bCabinetValid = cabinet.initUnpack(&state, mapProperties, pPdStruct);
    qint64 nLogicalCabinetSize = 0;
    if (bCabinetValid) {
        nLogicalCabinetSize = cabinet.getFileFormatSize(pPdStruct);
        bCabinetValid = cabinet.finishUnpack(&state, pPdStruct);
    }
    cabinetDevice.close();

    if (!bCabinetValid || (nLogicalCabinetSize < (qint64)sizeof(XCab::CFHEADER)) ||
        (nLogicalCabinetSize > rrCab.nSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    result.bIsValid = true;
    result.nArchiveOffset = rrCab.nOffset;
    result.nArchiveSize = nLogicalCabinetSize;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    if (!XBinary::isPdStructNotCanceled(pPdStruct)) result.bIsValid = false;

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
    if (pState->pContext && !finishUnpack(pState, pPdStruct)) return false;
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
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
    pState->nTotalSize = getSize();
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XIExpress::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XIExpress::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    return bResult;
}

bool XIExpress::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
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
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();
    return bResult;
}
