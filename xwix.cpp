/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xwix.h"

#include "xmsi.h"

XWiX::XWiX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XWiX::~XWiX()
{
}

bool XWiX::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XWiX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XWiX x(pDevice);
    return x.isValid(pPdStruct);
}

XWiX::INTERNAL_INFO XWiX::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XWiX::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *XWiX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XWiX::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XWiX::getFileType()
{
    return FT_ARCHIVE;
}

XWiX::INTERNAL_INFO XWiX::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    // Must be an MSI container.
    if (!XMSI::isValid(getDevice(), pPdStruct)) return result;

    const qint64 nSize = getSize();

    // WiX authoring marker (SummaryInformation "Creating Application").
    qint64 nPos = find_ansiString(0, nSize, "Windows Installer XML", pPdStruct);
    if (nPos == -1) nPos = find_ansiString(0, nSize, "WiX Toolset (", pPdStruct);
    if (nPos == -1) return result;

    result.bIsValid = true;

    // Version = the dotted number in parentheses after the app name.
    QString sApp = read_ansiString(nPos, 128);
    int nOpen = sApp.indexOf('(');
    int nClose = sApp.indexOf(')', nOpen + 1);
    if ((nOpen >= 0) && (nClose > nOpen)) {
        QString sFull = sApp.mid(nOpen + 1, nClose - nOpen - 1).trimmed();
        QStringList listParts = sFull.split('.');
        if (listParts.size() >= 2) {
            result.sVersion = listParts.at(0) + "." + listParts.at(1);
        } else {
            result.sVersion = sFull;
        }
    }

    return result;
}

QMap<XBinary::UNPACK_PROP, QVariant> XWiX::getDefaultUnpackProperties()
{
    return XBinary::getDefaultUnpackProperties();
}

bool XWiX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState || !_detect(pPdStruct).bIsValid) {
        return false;
    }

    *pState = UNPACK_STATE();
    pState->nTotalSize = getSize();
    pState->mapUnpackProperties = mapProperties;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pMSI = new XMSI(getDevice());
    pContext->state = UNPACK_STATE();

    if (!pContext->pMSI->initUnpack(&pContext->state, mapProperties, pPdStruct)) {
        delete pContext->pMSI;
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->state.nNumberOfRecords;
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XWiX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext || (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pMSI->infoCurrent(&pContext->state, pPdStruct);
}

bool XWiX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pMSI->unpackCurrent(&pContext->state, pDevice, pPdStruct);
}

bool XWiX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pMSI->moveToNext(&pContext->state, pPdStruct);
    pState->nCurrentIndex = pContext->state.nCurrentIndex;
    pState->nCurrentOffset = pContext->state.nCurrentOffset;
    return bResult;
}

bool XWiX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        pContext->pMSI->finishUnpack(&pContext->state, pPdStruct);
        delete pContext->pMSI;
        delete pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    return true;
}
