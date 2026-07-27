/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xmsi.h"

#include "subdevice.h"
#include "../XArchive/xcfbf.h"

XMSI::XMSI(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XMSI::~XMSI()
{
}

bool XMSI::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XMSI::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XMSI x(pDevice);
    return x.isValid(pPdStruct);
}

XMSI::INTERNAL_INFO XMSI::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XMSI::getFileType()
{
    return FT_ARCHIVE;
}

XMSI::INTERNAL_INFO XMSI::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    // 1) CFBF / OLE2 magic.
    QByteArray baMagic = read_array_process(0, 8, pPdStruct);
    if (baMagic != QByteArray("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) return result;

    // 2) sector size from the sector shift at 0x1E.
    QByteArray baShift = read_array_process(0x1E, 2, pPdStruct);
    if (baShift.size() < 2) return result;
    quint16 nShift = (quint16)((quint8)baShift.at(0) | ((quint16)(quint8)baShift.at(1) << 8));
    if ((nShift < 7) || (nShift > 20)) return result;
    quint32 nSectorSize = (quint32)1 << nShift;

    // 3) root-storage directory entry -> CLSID at +0x50.
    QByteArray baFirstDir = read_array_process(0x30, 4, pPdStruct);
    if (baFirstDir.size() < 4) return result;
    const quint8 *pfd = (const quint8 *)baFirstDir.constData();
    quint32 nFirstDir = (quint32)(pfd[0] | ((quint32)pfd[1] << 8) | ((quint32)pfd[2] << 16) | ((quint32)pfd[3] << 24));

    qint64 nRootOff = (qint64)(nFirstDir + 1) * (qint64)nSectorSize;
    QByteArray baClsid = read_array_process(nRootOff + 0x50, 16, pPdStruct);
    if (baClsid.size() < 16) return result;
    const quint8 *c = (const quint8 *)baClsid.constData();

    // MSI class GUID {000C108x-0000-0000-C000-000000000046}.
    bool bTail = (c[1] == 0x10) && (c[2] == 0x0C) && (c[3] == 0x00) && (c[8] == 0xC0) && (c[9] == 0x00) && (c[10] == 0x00) && (c[11] == 0x00) && (c[12] == 0x00) &&
                 (c[13] == 0x00) && (c[14] == 0x00) && (c[15] == 0x46);
    if (!bTail) return result;

    if (c[0] == 0x84) {
        result.bIsValid = true;
        result.sVersion = "database";
    } else if (c[0] == 0x86) {
        result.bIsValid = true;
        result.sVersion = "patch";
    } else if (c[0] == 0x82) {
        result.bIsValid = true;
        result.sVersion = "transform";
    }

    return result;
}

// --- streaming extraction: delegate to the XArchive CFBF handler (whole file) ---

bool XMSI::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    if (!_detect(pPdStruct).bIsValid) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pSubDevice = new SubDevice(getDevice(), 0, getSize());
    pContext->pArchive = nullptr;
    pContext->innerState = UNPACK_STATE();

    if (!pContext->pSubDevice->open(QIODevice::ReadOnly)) {
        delete pContext->pSubDevice;
        delete pContext;
        return false;
    }

    pContext->pArchive = new XCFBF(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD XMSI::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool XMSI::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool XMSI::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    return bResult;
}

bool XMSI::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
