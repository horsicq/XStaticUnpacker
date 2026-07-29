/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "x7zsfx.h"

#include "xpe.h"
#include "subdevice.h"
#include "../XArchive/xsevenzip.h"

X7ZSFX::X7ZSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

X7ZSFX::~X7ZSFX()
{
}

bool X7ZSFX::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool X7ZSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    X7ZSFX x(pDevice);
    return x.isValid(pPdStruct);
}

X7ZSFX::INTERNAL_INFO X7ZSFX::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool X7ZSFX::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *X7ZSFX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void X7ZSFX::setInternalInfo(void *pInternalInfo)
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

XBinary::FT X7ZSFX::getFileType()
{
    return FT_ARCHIVE;
}

X7ZSFX::INTERNAL_INFO X7ZSFX::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nArchiveOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    const qint64 nTotalSize = getSize();
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    QByteArray baHead = read_array_process(nOverlayOffset, 20, pPdStruct);
    if (baHead.size() < 6) return result;
    const quint8 *p = (const quint8 *)baHead.constData();

    static const char k7z[6] = {0x37, 0x7A, (char)0xBC, (char)0xAF, 0x27, 0x1C};
    const char *kConfig = ";!@Install@!UTF-8!";
    const int nConfigLen = 18;

    bool bConfig = (baHead.size() >= nConfigLen) && (memcmp(baHead.constData(), kConfig, nConfigLen) == 0);
    bool bBomConfig = false;
    if ((baHead.size() >= 3) && ((quint8)p[0] == 0xEF) && ((quint8)p[1] == 0xBB) && ((quint8)p[2] == 0xBF)) {
        QByteArray baAfter = read_array_process(nOverlayOffset + 3, nConfigLen, pPdStruct);
        bBomConfig = (baAfter.size() == nConfigLen) && (memcmp(baAfter.constData(), kConfig, nConfigLen) == 0);
    }
    bool bPlain7z = (memcmp(baHead.constData(), k7z, 6) == 0);

    if (bConfig || bBomConfig) {
        // Config SFX: the 7z archive follows the ";!@InstallEnd@!" text block.
        qint64 nSearchOffset = nOverlayOffset;
        qint32 nCandidates = 0;

        while ((nSearchOffset <= nTotalSize - 6) && (nCandidates < 64) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            qint64 nArchiveOffset = find_array(nSearchOffset, nTotalSize - nSearchOffset, k7z, 6, pPdStruct);
            if (nArchiveOffset < 0) break;

            SubDevice archiveDevice(getDevice(), nArchiveOffset, nTotalSize - nArchiveOffset);
            if (archiveDevice.open(QIODevice::ReadOnly)) {
                bool bArchiveValid = XSevenZip::isValid(&archiveDevice, pPdStruct);
                archiveDevice.close();

                if (bArchiveValid) {
                    result.bIsValid = true;
                    result.nArchiveOffset = nArchiveOffset;
                    break;
                }
            }

            nCandidates++;
            nSearchOffset = nArchiveOffset + 6;
        }
    } else if (bPlain7z) {
        // Plain-magic branch: require a 7-Zip stub attribution to avoid firing on
        // any PE that merely appends a .7z file.
        QString sInternal = pe.getResourcesVersionValue("InternalName").trimmed().toLower();
        QString sProduct = pe.getResourcesVersionValue("ProductName").trimmed();
        bool bHarden = (sInternal.startsWith("7z") && sInternal.endsWith(".sfx")) || (sProduct == "7-Zip");
        if (bHarden) {
            SubDevice archiveDevice(getDevice(), nOverlayOffset, nTotalSize - nOverlayOffset);
            if (archiveDevice.open(QIODevice::ReadOnly)) {
                result.bIsValid = XSevenZip::isValid(&archiveDevice, pPdStruct);
                archiveDevice.close();
                if (result.bIsValid) result.nArchiveOffset = nOverlayOffset;
            }
        }
    }

    if (!result.bIsValid) return result;

    result.nArchiveSize = nTotalSize - result.nArchiveOffset;

    QString sVer = pe.getResourcesVersionValue("FileVersion").trimmed();
    if (sVer.isEmpty()) sVer = pe.getFileVersion().trimmed();
    result.sVersion = sVer;

    return result;
}

// --- streaming extraction: delegate to the XArchive 7z handler ---

QMap<XBinary::UNPACK_PROP, QVariant> X7ZSFX::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    QIODevice *pDevice = getDevice();

    if (pDevice) {
        INTERNAL_INFO info = _detect(nullptr);

        if (info.bIsValid && (info.nArchiveOffset >= 0) && (info.nArchiveSize > 0)) {
            SubDevice subDevice(pDevice, info.nArchiveOffset, info.nArchiveSize);

            if (subDevice.open(QIODevice::ReadOnly)) {
                {
                    XSevenZip archive(&subDevice);
                    QMap<UNPACK_PROP, QVariant> mapInnerProperties = archive.getDefaultUnpackProperties();

                    if (mapInnerProperties.contains(UNPACK_PROP_PASSWORD)) {
                        result.insert(UNPACK_PROP_PASSWORD, mapInnerProperties.value(UNPACK_PROP_PASSWORD));
                    }

                    for (auto it = mapInnerProperties.constBegin(); it != mapInnerProperties.constEnd(); ++it) {
                        if (XBinary::isUnpackCRCProperty(it.key())) {
                            result.insert(it.key(), it.value());
                        }
                    }
                }

                subDevice.close();
            }
        }
    }

    return result;
}

bool X7ZSFX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    pContext->pArchive = new XSevenZip(pContext->pSubDevice);
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

XBinary::ARCHIVERECORD X7ZSFX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return result;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
}

bool X7ZSFX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (!pContext->pArchive) return false;
    pContext->innerState.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pArchive->unpackCurrent(&pContext->innerState, pDevice, pPdStruct);
}

bool X7ZSFX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool X7ZSFX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
