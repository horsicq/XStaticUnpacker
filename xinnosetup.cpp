/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinnosetup.h"

#include "xpe.h"
#include "xbzip2decoder.h"
#include "xdeflatedecoder.h"
#include "xstoredecoder.h"
#include "xlzmadecoder.h"

#include <QBuffer>
#include <QtEndian>
#include <QCryptographicHash>
#include <QDebug>
#include <QTemporaryFile>

#include <limits>

#include "../XArchive/xarchive.h"

XBinary::XCONVERT _TABLE_XINNOSETUP_STRUCTID[] = {
    {XInnoSetup::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XInnoSetup::STRUCTID_HEADER, "HEADER", QString("Header")},
};

// rDlPtS magic bytes for InnoSetup offset table (version 5.1.5+)
static const quint8 g_aRDlPtSMagic[] = {0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A};
static const qint32 g_nRDlPtSMagicSize = 12;

namespace {
const qint64 INNO_MAX_HEADER_BLOCK_SIZE = 64LL * 1024 * 1024;
const qint64 INNO_MAX_HEADER_STORED_SIZE =
    INNO_MAX_HEADER_BLOCK_SIZE + ((INNO_MAX_HEADER_BLOCK_SIZE + 4095) / 4096) * 4;
const quint32 INNO_MAX_HEADER_LZMA_DICTIONARY_SIZE = 64U * 1024 * 1024;

class InnoBoundedBuffer : public QBuffer {
public:
    explicit InnoBoundedBuffer(qint64 nLimit) : m_nLimit(nLimit) {}

protected:
    qint64 writeData(const char *pData, qint64 nSize) override
    {
        if ((nSize < 0) || (pos() < 0) || (pos() > m_nLimit) || (nSize > m_nLimit - pos())) return -1;
        return QBuffer::writeData(pData, nSize);
    }

private:
    qint64 m_nLimit;
};

struct InnoCRCProgressBridge {
    XBinary::PDSTRUCT *pOriginal;
    XBinary::PDSTRUCTLIFETIME originalLifetime;
};

void innoCRCProgressCallback(void *pUserData, XBinary::PDSTRUCT *pLocalProgress)
{
    InnoCRCProgressBridge *pBridge = static_cast<InnoCRCProgressBridge *>(pUserData);
    if (!pBridge || !pLocalProgress) return;

    if (!XBinary::isPdStructLifetimeAlive(pBridge->originalLifetime) ||
        !XBinary::isPdStructNotCanceled(pBridge->pOriginal)) {
        XBinary::setPdStructStopped(pLocalProgress);
    }
}

class InnoOperationGuard {
public:
    explicit InnoOperationGuard(const QSharedPointer<XInnoSetup::UNPACK_LIFETIME_STATE> &pState) : m_pState(pState), m_bAcquired(false)
    {
        if (m_pState && m_pState->bOwnerAlive && !m_pState->bOperationInProgress) {
            m_pState->bOperationInProgress = true;
            m_bAcquired = true;
        }
    }
    ~InnoOperationGuard() { if (m_pState && m_bAcquired) m_pState->bOperationInProgress = false; }
    bool isAcquired() const { return m_bAcquired; }
private:
    QSharedPointer<XInnoSetup::UNPACK_LIFETIME_STATE> m_pState;
    bool m_bAcquired;
};

class InnoPublisher : public XArchive {
public:
    explicit InnoPublisher(QIODevice *pDevice) : XArchive(pDevice) {}
    using XArchive::publishUnpackOutput;
};

quint64 innoVersionValue(const XInnoSetup::INNO_VERSION &version)
{
    return (quint64(version.nMajor) << 48) | (quint64(version.nMinor) << 32) |
           (quint64(version.nPatch) << 16) | quint64(version.nRevision);
}

quint64 innoVersionValue(quint16 nMajor, quint16 nMinor, quint16 nPatch = 0, quint16 nRevision = 0)
{
    return (quint64(nMajor) << 48) | (quint64(nMinor) << 32) |
           (quint64(nPatch) << 16) | quint64(nRevision);
}

XBinary::HANDLE_METHOD innoCompressionToHandleMethod(XInnoSetup::INNO_COMPRESSION compression)
{
    switch (compression) {
        case XInnoSetup::INNO_COMPRESSION_STORE: return XBinary::HANDLE_METHOD_STORE;
        case XInnoSetup::INNO_COMPRESSION_ZLIB: return XBinary::HANDLE_METHOD_ZLIB;
        case XInnoSetup::INNO_COMPRESSION_BZIP2: return XBinary::HANDLE_METHOD_BZIP2;
        case XInnoSetup::INNO_COMPRESSION_LZMA1: return XBinary::HANDLE_METHOD_LZMA;
        case XInnoSetup::INNO_COMPRESSION_LZMA2: return XBinary::HANDLE_METHOD_LZMA2;
        default: return XBinary::HANDLE_METHOD_UNKNOWN;
    }
}

XInnoSetup::INNO_COMPRESSION innoHandleMethodToCompression(XBinary::HANDLE_METHOD handleMethod)
{
    switch (handleMethod) {
        case XBinary::HANDLE_METHOD_STORE: return XInnoSetup::INNO_COMPRESSION_STORE;
        case XBinary::HANDLE_METHOD_ZLIB: return XInnoSetup::INNO_COMPRESSION_ZLIB;
        case XBinary::HANDLE_METHOD_BZIP2: return XInnoSetup::INNO_COMPRESSION_BZIP2;
        case XBinary::HANDLE_METHOD_LZMA: return XInnoSetup::INNO_COMPRESSION_LZMA1;
        case XBinary::HANDLE_METHOD_LZMA2: return XInnoSetup::INNO_COMPRESSION_LZMA2;
        default: return XInnoSetup::INNO_COMPRESSION_UNKNOWN;
    }
}

void innoDecodeExeFilter4108(QByteArray *pData)
{
    if (!pData) return;

    quint32 nAddress = 0;
    qint32 nAddressBytesLeft = 0;

    for (qint32 i = 0; i < pData->size(); i++) {
        quint8 nByte = (quint8)pData->at(i);

        if (nAddressBytesLeft == 0) {
            if ((nByte == 0xe8) || (nByte == 0xe9)) {
                // Inno's pre-5.2 filter makes CALL/JMP operands relative to
                // the address immediately after the five-byte instruction.
                nAddress = ~quint32(i + 5) + 1;
                nAddressBytesLeft = 4;
            }
        } else {
            nAddress += nByte;
            (*pData)[i] = char(quint8(nAddress));
            nAddress >>= 8;
            nAddressBytesLeft--;
        }
    }
}

void innoDecodeExeFilter5200(QByteArray *pData, bool bFlipHighByte)
{
    if (!pData) return;

    qint32 nPos = 0;

    while (nPos < pData->size()) {
        const quint8 nOpcode = (quint8)pData->at(nPos);

        if (((nOpcode != 0xe8) && (nOpcode != 0xe9)) ||
            ((0x10000 - (nPos % 0x10000)) < 5) || (nPos + 5 > pData->size())) {
            nPos++;
            continue;
        }

        quint8 nHigh = (quint8)pData->at(nPos + 4);

        if ((nHigh == 0x00) || (nHigh == 0xff)) {
            quint32 nRelative = (quint8)pData->at(nPos + 1) |
                                (quint32((quint8)pData->at(nPos + 2)) << 8) |
                                (quint32((quint8)pData->at(nPos + 3)) << 16);
            nRelative -= quint32(nPos + 5) & 0x00ffffff;
            (*pData)[nPos + 1] = char(quint8(nRelative));
            (*pData)[nPos + 2] = char(quint8(nRelative >> 8));
            (*pData)[nPos + 3] = char(quint8(nRelative >> 16));

            if (bFlipHighByte && (nRelative & 0x00800000)) {
                (*pData)[nPos + 4] = char(quint8(~nHigh));
            }
        }

        nPos += 5;
    }
}

void innoDecodeExeFilter(QByteArray *pData, const XInnoSetup::INNO_VERSION &version)
{
    const quint64 nVersion = innoVersionValue(version);

    if (nVersion < innoVersionValue(5, 2, 0)) {
        innoDecodeExeFilter4108(pData);
    } else {
        innoDecodeExeFilter5200(pData, nVersion >= innoVersionValue(5, 3, 9));
    }
}
}

XInnoSetup::UNPACK_LIFETIME_STATE::~UNPACK_LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> contexts = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : contexts) XInnoSetup::deleteUnpackContext(pContext);
}

void XInnoSetup::deleteUnpackContext(UNPACK_CONTEXT *pContext)
{
    if (!pContext) return;
    if (pContext->pSourceValidator) {
        pContext->pSourceValidator->releaseUnpackSource(&pContext->sourceValidationState);
        delete pContext->pSourceValidator;
    }
    delete pContext;
}

XInnoSetup::XInnoSetup(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<UNPACK_LIFETIME_STATE>::create();
}

XInnoSetup::~XInnoSetup()
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    if (pLifetime) pLifetime->bOwnerAlive = false;
    m_pUnpackLifetimeState.clear();
}

QString XInnoSetup::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XINNOSETUP_STRUCTID, sizeof(_TABLE_XINNOSETUP_STRUCTID) / sizeof(XBinary::XCONVERT));
}

QString XInnoSetup::structIDToFtString(quint32 nID)
{
    return XBinary::XCONVERT_idToFtString(nID, _TABLE_XINNOSETUP_STRUCTID, sizeof(_TABLE_XINNOSETUP_STRUCTID) / sizeof(XBinary::XCONVERT));
}

quint32 XInnoSetup::ftStringToStructID(const QString &sFtString)
{
    return XCONVERT_ftStringToId(sFtString, _TABLE_XINNOSETUP_STRUCTID, sizeof(_TABLE_XINNOSETUP_STRUCTID) / sizeof(XBinary::XCONVERT));
}

XBinary::FT XInnoSetup::getFileType()
{
    XPE pe(getDevice());

    if (pe.isValid() && pe.is64()) {
        return FT_PE64_INNOSETUP;
    }

    return FT_PE32_INNOSETUP;
}

bool XInnoSetup::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XInnoSetup> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

XInnoSetup::INTERNAL_INFO XInnoSetup::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _analyse(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XInnoSetup::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XInnoSetup> guardedThis(this);
    const bool bAlreadyHandled = guardedThis->isInternalInfoHandled();
    if (!guardedThis) return false;

    if (!bAlreadyHandled) {
        const quint64 nTransaction =
            guardedThis->beginInternalInfoTransaction();
        if (!nTransaction) return false;

        // The transaction supplies the recursion sentinel. Keep every
        // source-derived value local until the same binding is revalidated.
        guardedThis->m_internalInfo = INTERNAL_INFO();
        INTERNAL_INFO info = guardedThis->_getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }

        const auto memoryMap =
            guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        info.memoryMap = memoryMap;

        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        guardedThis->m_internalInfo = info;
        if (!guardedThis->commitInternalInfoTransaction(
                nTransaction,
                static_cast<XBinary::INTERNAL_INFO *>(
                    &guardedThis->m_internalInfo))) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
    }

    return true;
}

void *XInnoSetup::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XInnoSetup> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XInnoSetup::setInternalInfo(void *pInternalInfo)
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

XInnoSetup::INTERNAL_INFO XInnoSetup::_analyse(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    const char *apszSignatures[] = {"Inno Setup Setup Data", "Inno Setup: Setup Data"};
    const qint32 nSignatureCount = sizeof(apszSignatures) / sizeof(const char *);
    qint64 nFileSize = getSize();

    for (qint32 i = 0; (i < nSignatureCount) && (!result.bIsValid); i++) {
        QString sSignature = QString::fromLatin1(apszSignatures[i]);
        qint64 nOffset = find_utf8String(0, nFileSize, sSignature, pPdStruct);

        if (nOffset != -1) {
            result.bIsValid = true;
            result.nSignatureOffset = nOffset;

            const qint32 nWindowSize = 0x80;
            qint64 nRemaining = nFileSize - nOffset;
            if (nRemaining < 0) {
                nRemaining = 0;
            }
            qint64 nBytesToRead = qMin((qint64)nWindowSize, nRemaining);

            if (nBytesToRead > 0) {
                QByteArray baData = read_array_process(nOffset, nBytesToRead, pPdStruct);
                QString sWindow = QString::fromLatin1(baData.constData(), baData.size());

                qint32 nLeftBracket = sWindow.indexOf('(');
                if (nLeftBracket != -1) {
                    qint32 nRightBracket = sWindow.indexOf(')', nLeftBracket + 1);
                    if ((nRightBracket != -1) && (nRightBracket > nLeftBracket)) {
                        QString sVersionCandidate = sWindow.mid(nLeftBracket + 1, nRightBracket - nLeftBracket - 1).trimmed();
                        result.sVersion = sVersionCandidate;
                    }
                }

                if (result.sVersion.isEmpty()) {
                    qint32 nSignaturePos = sWindow.indexOf(sSignature);
                    if (nSignaturePos != -1) {
                        qint32 nSearchPos = nSignaturePos + sSignature.size();
                        while ((nSearchPos < sWindow.size()) && sWindow.at(nSearchPos).isSpace()) {
                            nSearchPos++;
                        }
                        if ((nSearchPos < sWindow.size()) && (sWindow.at(nSearchPos) == QChar('v'))) {
                            nSearchPos++;
                        }
                        qint32 nVersionStart = nSearchPos;
                        while ((nSearchPos < sWindow.size()) &&
                               ((sWindow.at(nSearchPos).isDigit()) || (sWindow.at(nSearchPos) == QChar('.')) || (sWindow.at(nSearchPos) == QChar('_')))) {
                            nSearchPos++;
                        }
                        if (nSearchPos > nVersionStart) {
                            result.sVersion = sWindow.mid(nVersionStart, nSearchPos - nVersionStart).trimmed();
                        }
                    }
                }
            }
        }
    }

    return result;
}

// Synthetic InnoSetup test format ("ISDF" marker):
// After the null-terminated InnoSetup signature:
//   "ISDF"     - 4-byte magic
//   uint32_le  - number of files
//   uint64_le  - data area offset (absolute)
//   Per file entry:
//     uint16_le  - filename length
//     char[N]    - filename (UTF-8)
//     uint64_le  - data offset (absolute)
//     uint64_le  - data size
//     uint32_le  - CRC32

QList<XBinary::ARCHIVERECORD> XInnoSetup::_parseSyntheticFileEntries(qint64 nSignatureOffset, PDSTRUCT *pPdStruct)
{
    QList<ARCHIVERECORD> listResult;

    qint64 nFileSize = getSize();

    // Skip past the null-terminated signature string
    qint64 nOffset = nSignatureOffset;
    qint64 nMaxScan = qMin(nSignatureOffset + 0x100, nFileSize);

    while (nOffset < nMaxScan) {
        quint8 nByte = read_uint8(nOffset);

        if (nByte == 0) {
            nOffset++;  // Skip the null terminator
            break;
        }

        nOffset++;
    }

    // Check for "ISDF" magic (4 bytes)
    if (nOffset + 4 > nFileSize) {
        return listResult;
    }

    QByteArray baMagic = read_array(nOffset, 4);

    if (baMagic != QByteArray("ISDF", 4)) {
        return listResult;  // Not a synthetic test file
    }

    nOffset += 4;

    // Read number of files (uint32_le)
    if (nOffset + 4 > nFileSize) {
        return listResult;
    }

    quint32 nNumberOfFiles = read_uint32(nOffset, false);
    nOffset += 4;

    // Read data area offset (uint64_le)
    if (nOffset + 8 > nFileSize) {
        return listResult;
    }

    quint64 nDataAreaOffset = read_uint64(nOffset, false);
    nOffset += 8;

    Q_UNUSED(nDataAreaOffset)

    // Read file entries
    for (quint32 i = 0; (i < nNumberOfFiles) && isPdStructNotCanceled(pPdStruct); i++) {
        // Read filename length (uint16_le)
        if (nOffset + 2 > nFileSize) {
            break;
        }

        quint16 nNameLen = read_uint16(nOffset, false);
        nOffset += 2;

        // Read filename
        if (nOffset + nNameLen > nFileSize) {
            break;
        }

        QByteArray baName = read_array(nOffset, nNameLen);
        QString sFileName = QString::fromUtf8(baName);
        nOffset += nNameLen;

        // Read data offset (uint64_le)
        if (nOffset + 8 > nFileSize) {
            break;
        }

        quint64 nDataOffset = read_uint64(nOffset, false);
        nOffset += 8;

        // Read data size (uint64_le)
        if (nOffset + 8 > nFileSize) {
            break;
        }

        quint64 nDataSize = read_uint64(nOffset, false);
        nOffset += 8;

        // Read CRC32 (uint32_le)
        if (nOffset + 4 > nFileSize) {
            break;
        }

        quint32 nCRC32 = read_uint32(nOffset, false);
        nOffset += 4;

        // Build ARCHIVERECORD
        ARCHIVERECORD record = {};
        record.mapProperties.insert(FPART_PROP_ORIGINALNAME, sFileName);
        record.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, (qint64)nDataSize);
        record.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, (qint64)nDataSize);
        record.mapProperties.insert(FPART_PROP_RESULTCRC, nCRC32);
        record.mapProperties.insert(FPART_PROP_CRC_TYPE, CRC_TYPE_FFFFFFFF_EDB88320_FFFFFFFFF);
        record.mapProperties.insert(FPART_PROP_ISFOLDER, false);
        record.mapProperties.insert(FPART_PROP_STREAMOFFSET, (qint64)nDataOffset);
        record.mapProperties.insert(FPART_PROP_STREAMSIZE, (qint64)nDataSize);

        listResult.append(record);
    }

    return listResult;
}

QMap<XBinary::UNPACK_PROP, QVariant> XInnoSetup::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XInnoSetup::initUnpack(XBinary::UNPACK_STATE *pState, const QMap<XBinary::UNPACK_PROP, QVariant> &mapProperties, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    InnoOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XInnoSetup> guardedThis(this);
    if (pState->pContext) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pLifetime->setContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState)) return false;
        pLifetime->setContexts.remove(pOldContext);
        pState->pContext = nullptr;
        deleteUnpackContext(pOldContext);
        *pState = UNPACK_STATE();
        if (!guardedThis || !pLifetime->bOwnerAlive) return false;
    }
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
    pState->mapUnpackProperties = mapProperties;

    QPointer<QIODevice> guardedSource(getDevice());
    if (!guardedSource) return false;
    XArchive *pSourceValidator = new XArchive(guardedSource.data());
    UNPACK_STATE sourceValidationState = {};
    if (!pSourceValidator->bindUnpackSource(&sourceValidationState, pPdStruct) || !guardedThis || !guardedSource) {
        pSourceValidator->releaseUnpackSource(&sourceValidationState);
        delete pSourceValidator;
        return false;
    }
    XInnoSetup detector(guardedSource.data(), isImage(), getModuleAddress());
    const qint64 nTotalSize = guardedSource->size();
    INTERNAL_INFO info = detector._analyse(pPdStruct);
    if (!guardedThis || !guardedSource || (nTotalSize < 0) || !info.bIsValid ||
        !pSourceValidator->isUnpackSourceCurrent(&sourceValidationState, pPdStruct) || !guardedThis || !guardedSource) {
        pSourceValidator->releaseUnpackSource(&sourceValidationState);
        delete pSourceValidator;
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT();
    pContext->pOuterSourceDevice = guardedSource;
    pContext->nOwnerDeviceGeneration = getDeviceGeneration();
    pContext->pSourceValidator = pSourceValidator;
    pContext->sourceValidationState = UNPACK_STATE();
    if (!pContext->pSourceValidator->transferUnpackSourceOwnership(&sourceValidationState, &pContext->sourceValidationState)) {
        pContext->pSourceValidator->releaseUnpackSource(&sourceValidationState);
        deleteUnpackContext(pContext);
        return false;
    }
    pContext->bIsRealFormat = false;
    pContext->version = {};
    pContext->nSignatureOffset = info.nSignatureOffset;
    pContext->nDataStreamOffset = 0;
    pContext->chunkCache.nChunkOffset = -1;
    pContext->chunkCache.compression = INNO_COMPRESSION_UNKNOWN;

    // Try real InnoSetup format first
    if (detector._parseRealInnoSetup(pContext, pPdStruct)) {
        pContext->bIsRealFormat = true;
    } else {
        // Fallback to synthetic ISDF format
        QList<ARCHIVERECORD> listRecords = detector._parseSyntheticFileEntries(info.nSignatureOffset, pPdStruct);
        pContext->listAllRecords = listRecords;
        pContext->bIsRealFormat = false;
    }

    if (!guardedThis || !guardedSource || pContext->listAllRecords.isEmpty() ||
        !pContext->pSourceValidator->validateAndFinalizeUnpackSource(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedSource) {
        deleteUnpackContext(pContext);
        return false;
    }

    pState->nTotalSize = nTotalSize;
    pContext->pOwnerState = pState;
    pState->pContext = pContext;
    pState->nNumberOfRecords = pContext->listAllRecords.count();
    pLifetime->setContexts.insert(pContext);

    return true;
}

XBinary::ARCHIVERECORD XInnoSetup::infoCurrent(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    InnoOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return result;
    QPointer<XInnoSetup> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetime->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) ||
        !pContext->pSourceValidator || (pState->nNumberOfRecords != pContext->listAllRecords.size()) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) || !guardedThis ||
        !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) return result;
    result = pContext->listAllRecords.at(pState->nCurrentIndex);
    return result;
}

static bool xinnoFailOutput(bool bSeekableOutput, QIODevice *pDevice, XBinary::UNPACK_STATE *pState)
{
    if (bSeekableOutput) {
        XBinary::resize(pDevice, 0);
        pDevice->seek(0);
    }
    pState->nCurrentOffset = 0;
    return false;
}

static bool xinnoVerifyCRC(const XBinary::ARCHIVERECORD &record, XBinary::UNPACK_STATE *pState, QIODevice *pDevice,
                           XBinary::PDSTRUCT *pPdStruct)
{
    XBinary::CRC_TYPE crcType = (XBinary::CRC_TYPE)record.mapProperties.value(XBinary::FPART_PROP_CRC_TYPE, XBinary::CRC_TYPE_UNKNOWN).toUInt();

    if (!XBinary::isUnpackCRCEnabled(pState->mapUnpackProperties, crcType) || (crcType == XBinary::CRC_TYPE_UNKNOWN) ||
        !record.mapProperties.contains(XBinary::FPART_PROP_RESULTCRC)) {
        return true;
    }

    if (!pDevice || !pDevice->isReadable() || !pDevice->seek(0)) {
        XBinary::setPdStructErrorString(pPdStruct, XInnoSetup::tr("CRC check requires a readable output device"));
        return false;
    }

    bool bCRCOk = XBinary::checkCRC(pDevice, crcType, record.mapProperties.value(XBinary::FPART_PROP_RESULTCRC), pPdStruct);

    if (!bCRCOk) {
        XBinary::setPdStructErrorString(pPdStruct, XInnoSetup::tr("Invalid CRC"));
    }

    return bCRCOk;
}

bool XInnoSetup::unpackCurrent(XBinary::UNPACK_STATE *pState, QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct)
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    InnoOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XInnoSetup> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !guardedOutput || !guardedOutput->isOpen() ||
        !guardedOutput->isWritable() || guardedOutput->isSequential() || !guardedThis || !guardedOutput ||
        (guardedOutput->openMode() & (QIODevice::Append | QIODevice::Text)) || !XBinary::isResizeEnable(guardedOutput.data()) ||
        !guardedThis || !guardedOutput || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    const XBinary::PDSTRUCTLIFETIME progressLifetime = XBinary::retainPdStructLifetime(pPdStruct);
    // CRC traversal updates progress on every chunk.  Keep those notifications
    // private so a caller callback cannot destroy the public state mid-check;
    // the bridge still observes cancellation without invoking user code.
    XBinary::PDSTRUCT crcProgress = XBinary::createPdStruct();
    InnoCRCProgressBridge crcProgressBridge = {pPdStruct, progressLifetime};
    if (pPdStruct) {
        const XBinary::PDSTRUCT progressSnapshot = XBinary::getPdStructSnapshot(pPdStruct);
        crcProgress.nBufferSize.storeRelease(progressSnapshot.nBufferSize.loadAcquire());
        crcProgress.nFileBufferSize.storeRelease(progressSnapshot.nFileBufferSize.loadAcquire());
        XBinary::setPdStructCallback(&crcProgress, innoCRCProgressCallback, &crcProgressBridge);
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);

    if (!pLifetime->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) ||
        !pContext->pSourceValidator || (pState->nNumberOfRecords != pContext->listAllRecords.size()) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listAllRecords.count()) ||
        XBinary::devicesAlias(pContext->pOuterSourceDevice.data(), guardedOutput.data()) || !guardedThis || !guardedOutput ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) || !guardedThis || !guardedOutput ||
        !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) {
        return false;
    }

    ARCHIVERECORD record = pContext->listAllRecords.at(pState->nCurrentIndex);
    QTemporaryFile stage;
    if (!stage.open()) return false;
    UNPACK_STATE stageState = *pState;
    stageState.baUnpackSourceToken.clear();
    stageState.pContext = nullptr;
    const bool bOuterIsImage = isImage();
    const XADDR nOuterModuleAddress = getModuleAddress();
    XInnoSetup decoder(pContext->pOuterSourceDevice.data(), bOuterIsImage, nOuterModuleAddress);

    auto isContextCurrent = [&]() -> bool {
        return guardedThis && guardedOutput && pLifetime->bOwnerAlive && pLifetime->setContexts.contains(pContext) &&
               (pContext->pOwnerState == pState);
    };

    auto verifyCRC = [&]() -> bool {
        CRC_TYPE crcType = (CRC_TYPE)record.mapProperties.value(FPART_PROP_CRC_TYPE, CRC_TYPE_UNKNOWN).toUInt();

        if (!XBinary::isUnpackCRCEnabled(stageState.mapUnpackProperties, crcType) || (crcType == CRC_TYPE_UNKNOWN) ||
            !record.mapProperties.contains(FPART_PROP_RESULTCRC)) {
            return true;
        }

        const auto isOriginalProgressAlive = [&]() -> bool {
            return !pPdStruct || (XBinary::isPdStructLifetimeAlive(progressLifetime) &&
                                  XBinary::isPdStructNotCanceled(pPdStruct));
        };
        if (!isOriginalProgressAlive()) return false;

        if (!stage.seek(0)) {
            if (isOriginalProgressAlive()) {
                XBinary::setPdStructErrorString(pPdStruct, tr("CRC check requires a readable output device"));
            }
            return false;
        }

        const bool bCRCOk = XBinary::checkCRC(&stage, crcType,
                                              record.mapProperties.value(FPART_PROP_RESULTCRC),
                                              &crcProgress);

        if (!isOriginalProgressAlive()) return false;
        if (!bCRCOk) {
            XBinary::setPdStructErrorString(pPdStruct, tr("Invalid CRC"));
        }

        return bCRCOk;
    };

    auto verifyChecksum = [&]() -> bool {
        const bool bHasChecksum = record.mapProperties.contains(FPART_PROP_CHECKSUM);
        const bool bHasType = record.mapProperties.contains(FPART_PROP_CHECKSUMTYPE);
        if (!bHasChecksum && !bHasType) return true;
        if (!bHasChecksum || !bHasType || !stage.seek(0)) return false;

        const QString sType = record.mapProperties.value(FPART_PROP_CHECKSUMTYPE).toString();
        QCryptographicHash::Algorithm algorithm;
        if (sType == QLatin1String("MD5")) algorithm = QCryptographicHash::Md5;
        else if (sType == QLatin1String("SHA1")) algorithm = QCryptographicHash::Sha1;
        else if (sType == QLatin1String("SHA256")) algorithm = QCryptographicHash::Sha256;
        else return false;

        QCryptographicHash hash(algorithm);
        QByteArray baBuffer(65536, '\0');

        while (true) {
            if (!isContextCurrent() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            const qint64 nRead = stage.read(baBuffer.data(), baBuffer.size());
            if (nRead < 0) return false;
            if (nRead == 0) break;
            hash.addData(baBuffer.constData(), nRead);
        }

        const QByteArray baExpected = record.mapProperties.value(FPART_PROP_CHECKSUM).toString().toLatin1().toLower();
        const bool bOk = (hash.result().toHex() == baExpected);
        if (!bOk) XBinary::setPdStructErrorString(pPdStruct, tr("Invalid checksum"));
        return bOk;
    };

    qint64 nUncompressedSize = record.mapProperties.value(FPART_PROP_UNCOMPRESSEDSIZE).toLongLong();

    // Empty file — nothing to write
    if (nUncompressedSize == 0) {
        if (!verifyChecksum() || !verifyCRC() || !isContextCurrent()) return false;
    }

    if (nUncompressedSize < 0) return false;

    if (nUncompressedSize > 0 && pContext->bIsRealFormat) {
        qint64 nStreamOffset = record.nStreamOffset;                                                    // Absolute offset of zlb chunk in file
        qint64 nStreamSize = record.nStreamSize;                                                        // Compressed bytes after the zlb magic
        qint64 nDecompressedOffset = record.mapProperties.value(FPART_PROP_STREAMOFFSET).toLongLong();  // Offset within decompressed chunk
        INNO_COMPRESSION compression = innoHandleMethodToCompression(
            (HANDLE_METHOD)record.mapProperties.value(FPART_PROP_HANDLEMETHOD, HANDLE_METHOD_UNKNOWN).toUInt());

        if (compression == INNO_COMPRESSION_UNKNOWN) return false;

        // Solid members share the exact same chunk start. Equal compressed sizes do not identify a chunk.
        if ((pContext->chunkCache.nChunkOffset != nStreamOffset) || (pContext->chunkCache.compression != compression) ||
            pContext->chunkCache.baDecompressedData.isEmpty()) {
            qint64 nChunkOutputLimit = 0;
            for (const DATA_ENTRY &entry : pContext->listDataEntries) {
                if (entry.nChunkStartOffset > (std::numeric_limits<qint64>::max)() - pContext->nDataStreamOffset) return false;
                if (pContext->nDataStreamOffset + entry.nChunkStartOffset != nStreamOffset) continue;
                if ((entry.compression != compression) || (entry.nChunkCompressedSize != nStreamSize) ||
                    (entry.nChunkSubOffset > (std::numeric_limits<qint64>::max)() - entry.nOriginalSize)) return false;
                nChunkOutputLimit = qMax(nChunkOutputLimit, entry.nChunkSubOffset + entry.nOriginalSize);
            }

            // QByteArray-backed caching cannot safely represent an unbounded or
            // multi-gigabyte solid chunk. The decoder's processed window also
            // prevents corrupt input from allocating past the metadata-derived end.
            if ((nChunkOutputLimit <= 0) || (nChunkOutputLimit > (std::numeric_limits<qint32>::max)())) return false;
            QByteArray baDecompressed = decoder._decompressDataChunk(nStreamOffset, nStreamSize, nChunkOutputLimit,
                                                                      compression, pPdStruct);

            if (!isContextCurrent() || baDecompressed.isEmpty()) {
                qWarning() << "[InnoSetup] Failed to decompress data chunk at offset" << nStreamOffset;
                return false;
            }

            pContext->chunkCache.nChunkOffset = nStreamOffset;
            pContext->chunkCache.compression = compression;
            pContext->chunkCache.baDecompressedData = baDecompressed;
        }

        // Extract this file's data from the decompressed chunk
        const QByteArray &baChunk = pContext->chunkCache.baDecompressedData;

        if ((nDecompressedOffset < 0) || (nDecompressedOffset > baChunk.size()) ||
            (nUncompressedSize > ((qint64)baChunk.size() - nDecompressedOffset))) {
            qWarning() << "[InnoSetup] File data exceeds chunk boundary: offset" << nDecompressedOffset << "size" << nUncompressedSize << "chunk size" << baChunk.size();
            return false;
        }

        QByteArray baFileData = baChunk.mid((qint32)nDecompressedOffset, (qint32)nUncompressedSize);

        if (record.mapProperties.value(FPART_PROP_HANDLEMETHOD2, HANDLE_METHOD_UNKNOWN).toUInt() == HANDLE_METHOD_BCJ) {
            innoDecodeExeFilter(&baFileData, pContext->version);
        }

        if (!XBinary::writeUnpackData(&stageState, &stage, baFileData.constData(), baFileData.size(), pPdStruct) || !isContextCurrent()) return false;
        if (!verifyChecksum() || !verifyCRC() || !isContextCurrent()) return false;
    } else if (nUncompressedSize > 0) {
        // Synthetic ISDF: stored data — direct copy using XStoreDecoder
        qint64 nStreamOffset = record.mapProperties.value(FPART_PROP_STREAMOFFSET).toLongLong();
        qint64 nStreamSize = record.mapProperties.value(FPART_PROP_STREAMSIZE).toLongLong();

        if (nStreamSize == 0) {
            return false;
        }

        // Clamp to file size
        qint64 nFileSize = decoder.getSize();
        if (!isContextCurrent()) return false;

        if ((nStreamOffset < 0) || (nStreamSize < 0) || (nStreamOffset > nFileSize)) {
            return false;
        }

        if (nStreamSize > (nFileSize - nStreamOffset)) {
            nStreamSize = nFileSize - nStreamOffset;

            if (nStreamSize <= 0) {
                return false;
            }
        }

        XBinary::DATAPROCESS_STATE decompressState = {};
        decompressState.mapProperties.insert(XBinary::FPART_PROP_HANDLEMETHOD, XBinary::HANDLE_METHOD_STORE);
        decompressState.mapProperties.insert(XBinary::FPART_PROP_UNCOMPRESSEDSIZE, nStreamSize);
        decompressState.pDeviceInput = pContext->pOuterSourceDevice.data();
        decompressState.pDeviceOutput = &stage;
        decompressState.nInputOffset = nStreamOffset;
        decompressState.nInputLimit = nStreamSize;
        decompressState.nProcessedOffset = 0;
        decompressState.nProcessedLimit = -1;

        if (!XStoreDecoder::decompress(&decompressState, pPdStruct) || (decompressState.nCountInput != nStreamSize) ||
            (decompressState.nCountOutput != nStreamSize) || !isContextCurrent()) {
            return false;
        }

        stageState.nCurrentOffset = decompressState.nCountOutput;
        if (!verifyChecksum() || !verifyCRC() || !isContextCurrent()) return false;
    }

    if (!guardedThis || !guardedOutput || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) || !guardedThis || !guardedOutput ||
        !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    InnoPublisher publisher(pContext->pOuterSourceDevice.data());
    UNPACK_STATE publicationState = {};
    if (!publisher.bindUnpackSource(&publicationState, pPdStruct) ||
        !publisher.validateAndFinalizeUnpackSource(&publicationState, pPdStruct) || !guardedThis || !guardedOutput ||
        !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext) ||
        !publisher.publishUnpackOutput(&stage, guardedOutput.data(), &publicationState, pPdStruct) || !isContextCurrent()) return false;
    pState->nCurrentOffset = stage.size();
    return true;
}

bool XInnoSetup::moveToNext(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    InnoOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XInnoSetup> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetime->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) ||
        !pContext->pSourceValidator || (pState->nNumberOfRecords != pContext->listAllRecords.size()) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) || !guardedThis ||
        !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    const bool bCurrent = pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct);
    return bCurrent && guardedThis && pLifetime->bOwnerAlive && pLifetime->setContexts.contains(pContext) &&
           (pState->pContext == pContext) && (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XInnoSetup::finishUnpack(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) return false;
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    InnoOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pLifetime->setContexts.contains(pContext) || (pContext->pOwnerState != pState)) return false;
        pLifetime->setContexts.remove(pContext);
        pState->pContext = nullptr;
        deleteUnpackContext(pContext);
    }
    *pState = UNPACK_STATE();
    return true;
}

// ============================================================================
// Real InnoSetup format parsing methods
// ============================================================================

XInnoSetup::OFFSET_TABLE XInnoSetup::_findOffsetTable(PDSTRUCT *pPdStruct)
{
    OFFSET_TABLE invalidResult = {};
    const qint64 nFileSize = getSize();
    const QByteArray baMagic(reinterpret_cast<const char *>(g_aRDlPtSMagic), g_nRDlPtSMagicSize);
    qint64 nSearchOffset = 0;

    // The ID may occur in payload text. Keep scanning until a complete, CRC-valid
    // loader table is found instead of trusting the first byte match.
    while ((nSearchOffset >= 0) && (nSearchOffset <= nFileSize - g_nRDlPtSMagicSize) &&
           XBinary::isPdStructNotCanceled(pPdStruct)) {
        const qint64 nTableOffset = find_array(nSearchOffset, nFileSize - nSearchOffset,
                                               baMagic.constData(), baMagic.size(), pPdStruct);
        if (nTableOffset == -1) break;

        if (nTableOffset <= nFileSize - 16) {
            const quint32 nRevision = read_uint32(nTableOffset + 12, false);
            const qint32 nTableSize = (nRevision == 1) ? 44 : ((nRevision == 2) ? 64 : 0);

            if ((nTableSize != 0) && (nTableOffset <= nFileSize - nTableSize)) {
                const QByteArray baTable = read_array(nTableOffset, nTableSize);
                if (baTable.size() == nTableSize) {
                    const quint32 nExpectedCRC = qFromLittleEndian<quint32>(
                        reinterpret_cast<const uchar *>(baTable.constData() + nTableSize - 4));
                    const quint32 nActualCRC = _getCRC32(baTable.constData(), nTableSize - 4, 0xFFFFFFFF,
                                                         _getCRC32Table_EDB88320()) ^ 0xFFFFFFFF;

                    if (nExpectedCRC == nActualCRC) {
                        OFFSET_TABLE candidate = {};
                        candidate.nTableOffset = nTableOffset;
                        candidate.nRevision = nRevision;

                        quint64 nHeaderOffset = 0;
                        quint64 nDataOffset = 0;

                        if (nRevision == 1) {
                            candidate.nTotalSize = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 16));
                            candidate.nExeOffset = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 20));
                            candidate.nExeUncompressedSize = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 24));
                            candidate.nExeChecksum = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 28));
                            nHeaderOffset = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 32));
                            nDataOffset = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 36));
                        } else {
                            candidate.nTotalSize = qFromLittleEndian<quint64>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 16));
                            const quint64 nExeOffset = qFromLittleEndian<quint64>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 24));
                            candidate.nExeUncompressedSize = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 32));
                            candidate.nExeChecksum = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 36));
                            nHeaderOffset = qFromLittleEndian<quint64>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 40));
                            nDataOffset = qFromLittleEndian<quint64>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 48));
                            const quint32 nReserved = qFromLittleEndian<quint32>(
                                reinterpret_cast<const uchar *>(baTable.constData() + 56));
                            if ((nExeOffset > quint64((std::numeric_limits<qint64>::max)())) || (nReserved != 0)) {
                                nHeaderOffset = 0;
                                nDataOffset = 0;
                            } else {
                                candidate.nExeOffset = (qint64)nExeOffset;
                            }
                        }

                        const quint64 nTableEnd = quint64(nTableOffset) + quint64(nTableSize);
                        const quint64 nMinimumHeaderEnd = nHeaderOffset + 64;
                        if ((candidate.nTotalSize >= nTableEnd) &&
                            (candidate.nTotalSize <= quint64(nFileSize)) &&
                            (candidate.nExeUncompressedSize > 0) &&
                            (candidate.nExeOffset > 0) && (quint64(candidate.nExeOffset) < candidate.nTotalSize) &&
                            (nHeaderOffset > 0) && (nHeaderOffset <= quint64((std::numeric_limits<qint64>::max)())) &&
                            (nMinimumHeaderEnd >= nHeaderOffset) &&
                            (nMinimumHeaderEnd <= quint64(candidate.nExeOffset)) &&
                            (nDataOffset > 0) && (nDataOffset <= nHeaderOffset) &&
                            (nDataOffset <= quint64((std::numeric_limits<qint64>::max)()))) {
                            candidate.nHeaderOffset = (qint64)nHeaderOffset;
                            candidate.nDataOffset = (qint64)nDataOffset;
                            candidate.bIsValid = true;
                            return candidate;
                        }
                    }
                }
            }
        }

        if (nTableOffset == (std::numeric_limits<qint64>::max)()) break;
        nSearchOffset = nTableOffset + 1;
    }

    return invalidResult;
}

QByteArray XInnoSetup::_stripCRCChunks(const QByteArray &baData, bool *pbValid)
{
    // Block stream data is split into chunks: [4-byte CRC32][up to 4096 bytes payload]
    // Validate the CRC32 prefixes before concatenating any payload.
    if (pbValid) *pbValid = false;
    QByteArray baResult;
    qint32 nPos = 0;
    qint32 nSize = baData.size();

    while (nPos < nSize) {
        // A checksum without at least one payload byte is malformed. This also
        // rejects the one-to-four trailing bytes that the old parser ignored.
        if (nSize - nPos <= 4) return QByteArray();

        const quint32 nExpectedCRC = qFromLittleEndian<quint32>(
            reinterpret_cast<const uchar *>(baData.constData() + nPos));
        nPos += 4;

        qint32 nChunkSize = qMin(4096, nSize - nPos);
        const quint32 nActualCRC = _getCRC32(baData.constData() + nPos, nChunkSize, 0xFFFFFFFF,
                                              _getCRC32Table_EDB88320()) ^ 0xFFFFFFFF;
        if (nActualCRC != nExpectedCRC) return QByteArray();

        baResult.append(baData.constData() + nPos, nChunkSize);
        nPos += nChunkSize;
    }

    if (pbValid) *pbValid = true;
    return baResult;
}

QByteArray XInnoSetup::_decompressLZMA1(const QByteArray &baData)
{
    // LZMA1 format: 1-byte props + 4-byte dict_size (LE) + raw stream
    if (baData.size() < 6) {
        return QByteArray();
    }

    const quint32 nDictionarySize = qFromLittleEndian<quint32>(
        reinterpret_cast<const uchar *>(baData.constData() + 1));
    if (nDictionarySize > INNO_MAX_HEADER_LZMA_DICTIONARY_SIZE) return QByteArray();

    QByteArray baProperty = baData.left(5);  // props byte + 4-byte dict_size
    QByteArray baCompressed = baData.mid(5);

    QBuffer bufInput;
    bufInput.setData(baCompressed);

    InnoBoundedBuffer bufOutput(INNO_MAX_HEADER_BLOCK_SIZE);

    if (!bufInput.open(QIODevice::ReadOnly) || !bufOutput.open(QIODevice::WriteOnly)) {
        bufInput.close();
        bufOutput.close();
        return QByteArray();
    }

    XBinary::DATAPROCESS_STATE decompressState = {};
    decompressState.pDeviceInput = &bufInput;
    decompressState.pDeviceOutput = &bufOutput;
    decompressState.nInputOffset = 0;
    decompressState.nInputLimit = baCompressed.size();
    decompressState.nProcessedOffset = 0;
    // Permit the first byte beyond the cap to reach InnoBoundedBuffer. It then
    // fails the decoder immediately; bytes outside the requested window would
    // otherwise be silently counted and discarded by XBinary::_writeDevice.
    decompressState.nProcessedLimit = INNO_MAX_HEADER_BLOCK_SIZE + 1;

    bool bOk = XLZMADecoder::decompress(&decompressState, baProperty, nullptr);

    bufInput.close();
    bufOutput.close();

    if (!bOk || decompressState.bReadError || decompressState.bWriteError ||
        (decompressState.nCountInput != baCompressed.size()) ||
        (decompressState.nCountOutput < 0) ||
        (decompressState.nCountOutput > INNO_MAX_HEADER_BLOCK_SIZE) ||
        (decompressState.nCountOutput != bufOutput.data().size())) {
        return QByteArray();
    }

    return bufOutput.data();
}

QByteArray XInnoSetup::_readBlockStream(qint64 nOffset, qint64 *pnConsumed, PDSTRUCT *pPdStruct, bool b64BitStoredSize)
{
    // Block stream format:
    // uint32 CRC32 of (stored_size + compressed_flag)
    // uint32/uint64 stored_size  (widened to 64-bit in Inno Setup >= 6.5.0, revision 2)
    // uint8  compressed_flag (1 = LZMA1 compressed)
    // <stored_size bytes of CRC-chunked data>

    qint64 nFileSize = getSize();

    // Header size: rev-1 = CRC(4) + size(4) + flag(1) = 9; rev-2 = CRC(4) + size(8) + flag(1) = 13.
    const qint64 nHeaderSize = b64BitStoredSize ? 13 : 9;

    if (nOffset + nHeaderSize > nFileSize) {
        if (pnConsumed) {
            *pnConsumed = 0;
        }

        return QByteArray();
    }

    // The header checksum covers the encoded stored size and compressed flag.
    const quint32 nExpectedHeaderCRC = read_uint32(nOffset, false);
    const QByteArray baHeaderPayload = read_array(nOffset + 4, nHeaderSize - 4);
    if (baHeaderPayload.size() != nHeaderSize - 4) return QByteArray();
    const quint32 nActualHeaderCRC = _getCRC32(baHeaderPayload, 0xFFFFFFFF,
                                                _getCRC32Table_EDB88320()) ^ 0xFFFFFFFF;
    if (nActualHeaderCRC != nExpectedHeaderCRC) {
        setPdStructErrorString(pPdStruct, tr("Invalid Inno Setup block header CRC"));
        return QByteArray();
    }

    quint64 nStoredSize = b64BitStoredSize ? read_uint64(nOffset + 4, false) : read_uint32(nOffset + 4, false);
    quint8 nCompressedFlag = read_uint8(nOffset + nHeaderSize - 1);
    if (nCompressedFlag > 1) {
        setPdStructErrorString(pPdStruct, tr("Invalid Inno Setup block compression flag"));
        return QByteArray();
    }

    if (nStoredSize > quint64(INNO_MAX_HEADER_STORED_SIZE)) {
        setPdStructErrorString(pPdStruct, tr("Inno Setup header block exceeds the supported size limit"));
        return QByteArray();
    }

    qint64 nConsumed = nHeaderSize + (qint64)nStoredSize;

    if (nOffset + nConsumed > nFileSize) {
        if (pnConsumed) {
            *pnConsumed = 0;
        }

        return QByteArray();
    }

    // Read the stored data
    QByteArray baStoredData = read_array(nOffset + nHeaderSize, (qint64)nStoredSize);
    if (quint64(baStoredData.size()) != nStoredSize) return QByteArray();

    // Strip and validate per-chunk CRC32 prefixes.
    bool bChunksValid = false;
    QByteArray baPayload = _stripCRCChunks(baStoredData, &bChunksValid);
    if (!bChunksValid) {
        setPdStructErrorString(pPdStruct, tr("Invalid Inno Setup block CRC"));
        return QByteArray();
    }
    if (baPayload.size() > INNO_MAX_HEADER_BLOCK_SIZE) {
        setPdStructErrorString(pPdStruct, tr("Inno Setup header block exceeds the supported size limit"));
        return QByteArray();
    }

    if (pnConsumed) {
        *pnConsumed = nConsumed;
    }

    if (nCompressedFlag == 1) {
        return _decompressLZMA1(baPayload);
    }

    return baPayload;
}

QString XInnoSetup::_readWideString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset)
{
    // Delphi WideString format: uint32 length_in_bytes, then UTF-16LE data
    if ((nOffset < 0) || (nOffset > baData.size() - 4)) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset;
        }

        return QString();
    }

    quint32 nByteLen = qFromLittleEndian<quint32>((const uchar *)(baData.constData() + nOffset));

    if (nByteLen == 0) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset + 4;
        }

        return QString();
    }

    if (((nByteLen & 1U) != 0) || (nByteLen > 0x1000000) ||
        (nByteLen > quint32(baData.size() - nOffset - 4))) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset;
        }

        return QString();
    }

    const qint32 nCharCount = (qint32)(nByteLen / 2);
    QString sResult(nCharCount, QChar());
    const uchar *pStringData = reinterpret_cast<const uchar *>(baData.constData() + nOffset + 4);
    for (qint32 i = 0; i < nCharCount; i++) {
        sResult[i] = QChar(qFromLittleEndian<quint16>(pStringData + i * 2));
    }

    if (pnNewOffset) {
        *pnNewOffset = nOffset + 4 + nByteLen;
    }

    return sResult;
}

QString XInnoSetup::_decodeWindows1252(const char *pData, qint32 nSize)
{
    static const ushort anC1Map[32] = {
        0x20ac, 0xfffd, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
        0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0xfffd, 0x017d, 0xfffd,
        0xfffd, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
        0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xfffd, 0x017e, 0x0178,
    };

    QString result;

    if (!pData || (nSize <= 0)) return result;
    result.reserve(nSize);

    for (qint32 i = 0; i < nSize; i++) {
        const quint8 nByte = (quint8)pData[i];
        result.append(QChar((nByte >= 0x80) && (nByte <= 0x9f) ? anC1Map[nByte - 0x80] : nByte));
    }

    return result;
}

QString XInnoSetup::_readAnsiString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset)
{
    // Delphi AnsiString format (Inno < 5.3.0): uint32 length_in_bytes, then single-byte chars.
    if (nOffset + 4 > baData.size()) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset;
        }

        return QString();
    }

    quint32 nByteLen = qFromLittleEndian<quint32>((const uchar *)(baData.constData() + nOffset));

    if (nByteLen == 0) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset + 4;
        }

        return QString();
    }

    if ((nByteLen > 0x1000000) || (nOffset + 4 + (qint32)nByteLen > baData.size())) {
        if (pnNewOffset) {
            *pnNewOffset = nOffset;
        }

        return QString();
    }

    // The default Inno ANSI code page is Windows-1252. Language-specific code pages require
    // parsing the selected language entry and are deliberately not guessed here.
    QString sResult = _decodeWindows1252(baData.constData() + nOffset + 4, (qint32)nByteLen);

    if (pnNewOffset) {
        *pnNewOffset = nOffset + 4 + nByteLen;
    }

    return sResult;
}

QString XInnoSetup::_readSetupString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset, bool bUnicode)
{
    if (bUnicode) {
        return _readWideString(baData, nOffset, pnNewOffset);
    }

    return _readAnsiString(baData, nOffset, pnNewOffset);
}

XInnoSetup::INNO_VERSION XInnoSetup::_parseVersionId(const QByteArray &baVersionId)
{
    INNO_VERSION result = {};

    if (baVersionId.size() != 64) return result;

    qint32 nLength = baVersionId.indexOf('\0');
    if (nLength < 0) nLength = baVersionId.size();

    for (qint32 i = nLength; i < baVersionId.size(); i++) {
        if (baVersionId.at(i) != '\0') return result;
    }

    const QByteArray baId = baVersionId.left(nLength);
    const QByteArray baPrefix("Inno Setup Setup Data (");

    if (!baId.startsWith(baPrefix)) return result;

    const qint32 nClose = baId.indexOf(')', baPrefix.size());
    if (nClose < 0) return result;

    const QByteArray baVersion = baId.mid(baPrefix.size(), nClose - baPrefix.size());
    const QByteArray baSuffix = baId.mid(nClose + 1);

    if (!baSuffix.isEmpty() && (baSuffix != " (u)") && (baSuffix != " (U)")) return result;

    const QList<QByteArray> listParts = baVersion.split('.');
    if ((listParts.count() != 3) && (listParts.count() != 4)) return result;

    quint16 anParts[4] = {};

    for (qint32 i = 0; i < listParts.count(); i++) {
        if (listParts.at(i).isEmpty()) return result;
        for (char ch : listParts.at(i)) {
            if ((ch < '0') || (ch > '9')) return result;
        }
        bool bOk = false;
        const uint nValue = listParts.at(i).toUInt(&bOk);
        if (!bOk || (nValue > 0xffff)) return result;
        anParts[i] = (quint16)nValue;
    }

    result.nMajor = anParts[0];
    result.nMinor = anParts[1];
    result.nPatch = anParts[2];
    result.nRevision = anParts[3];
    result.bUnicode = !baSuffix.isEmpty() || (result.nMajor >= 6);

    // This parser implements only the versioned 5.x through current revision-2 layouts.
    if ((result.nMajor < 5) || (result.nMajor > 7)) return INNO_VERSION();
    if ((result.nMajor == 7) && ((result.nMinor != 0) || (result.nPatch != 0) || (result.nRevision != 3))) return INNO_VERSION();

    result.bIsValid = true;
    return result;
}

XInnoSetup::HEADER_INFO XInnoSetup::_parseHeaderInfo(const QByteArray &baBlock1, const INNO_VERSION &version)
{
    HEADER_INFO result = {};
    result.compression = INNO_COMPRESSION_UNKNOWN;

    if (!version.bIsValid || baBlock1.isEmpty()) return result;

    const quint64 nVersion = innoVersionValue(version);

    // The 6.5/6.6 setup-data records are not described by the vendored schema. Do not
    // reinterpret them as either the 6.4 or 6.7 packed header.
    if ((version.nMajor == 6) && ((version.nMinor == 5) || (version.nMinor == 6))) return result;

    qint32 nOffset = 0;
    const auto skipBytes = [&](qint32 nSize, qint32 *pnOffset) -> bool {
        if (!pnOffset || (nSize < 0) || (*pnOffset < 0) || (*pnOffset > baBlock1.size()) ||
            (nSize > baBlock1.size() - *pnOffset)) return false;
        *pnOffset += nSize;
        return true;
    };
    const auto skipString = [&](qint32 *pnOffset) -> bool {
        if (!pnOffset || (*pnOffset < 0) || (*pnOffset > baBlock1.size() - 4)) return false;
        const quint32 nLength = qFromLittleEndian<quint32>(
            reinterpret_cast<const uchar *>(baBlock1.constData() + *pnOffset));
        if ((nLength > 0x10000000U) || (nLength > quint32(baBlock1.size() - *pnOffset - 4))) return false;
        *pnOffset += 4 + (qint32)nLength;
        return true;
    };
    const auto skipStrings = [&](qint32 nCount, qint32 *pnOffset) -> bool {
        for (qint32 i = 0; i < nCount; i++) {
            if (!skipString(pnOffset)) return false;
        }
        return true;
    };

    // TSetupHeader string fields, in their serialized order.
    if (!skipStrings(6, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 1, 13)) && !skipString(&nOffset)) return result;
    if (!skipStrings(6, &nOffset)) return result;  // support URL through base filename
    if ((nVersion < innoVersionValue(5, 2, 5)) && !skipStrings(3, &nOffset)) return result;
    if (!skipStrings(7, &nOffset)) return result;  // uninstall files through serial
    if ((nVersion < innoVersionValue(5, 2, 5)) && !skipString(&nOffset)) return result;
    if (!skipStrings(4, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 3, 8)) && !skipString(&nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 3, 10)) && !skipString(&nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 5, 0)) && !skipString(&nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 5, 6)) && !skipString(&nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 6, 1)) && !skipStrings(2, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(6, 3, 0)) && !skipStrings(2, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(6, 4, 0)) && !skipString(&nOffset)) return result;  // close-app excludes
    if ((nVersion >= innoVersionValue(6, 7, 0)) && !skipStrings(6, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 2, 5)) && !skipStrings(3, &nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 2, 1)) && (nVersion < innoVersionValue(5, 3, 10)) && !skipString(&nOffset)) return result;
    if ((nVersion >= innoVersionValue(5, 2, 5)) && !skipString(&nOffset)) return result;

    if (!version.bUnicode && !skipBytes(32, &nOffset)) return result;  // stored ANSI lead-byte set

    result.nCountCount = (nVersion >= innoVersionValue(6, 7, 0)) ? 17 : 16;
    if (!skipBytes(result.nCountCount * 4, &nOffset)) return result;

    const qint32 nCountsOffset = nOffset - result.nCountCount * 4;
    for (qint32 i = 0; i < result.nCountCount; i++) {
        const quint32 nCount = qFromLittleEndian<quint32>(
            reinterpret_cast<const uchar *>(baBlock1.constData() + nCountsOffset + i * 4));
        if (nCount > 1000000U) return HEADER_INFO();
        result.anCounts[i] = (qint32)nCount;
    }

    if (result.nCountCount == 17) {
        result.nFileCount = result.anCounts[8];
        result.nDataEntryCount = result.anCounts[9];
    } else {
        result.nFileCount = result.anCounts[7];
        result.nDataEntryCount = result.anCounts[8];
    }

    // FileCount and FileLocationCount are independent.  An all-external setup can
    // legally contain file records while carrying no embedded data locations.
    if (result.nFileCount <= 0) return HEADER_INFO();

    if (version.nMajor >= 7) {
        if (!skipBytes(4, &nOffset)) return HEADER_INFO();  // CompiledCodeVersion
    }

    if (nVersion >= innoVersionValue(6, 7, 0)) {
        // Current packed header: version range, wizard geometry/appearance, disk fields,
        // and six one-byte enums immediately precede CompressMethod.
        if (!skipBytes(75, &nOffset)) return HEADER_INFO();
    } else {
        if (!skipBytes(20, &nOffset)) return HEADER_INFO();  // MinVersion + OnlyBelowVersion
        if ((nVersion < innoVersionValue(6, 4, 0, 1)) && !skipBytes(4, &nOffset)) return HEADER_INFO();
        if ((nVersion < innoVersionValue(6, 4, 0, 1)) && !skipBytes(4, &nOffset)) return HEADER_INFO();
        if ((nVersion < innoVersionValue(5, 5, 7)) && !skipBytes(4, &nOffset)) return HEADER_INFO();
        if ((nVersion < innoVersionValue(5, 0, 4)) && !skipBytes(4, &nOffset)) return HEADER_INFO();
        if ((nVersion >= innoVersionValue(6, 0, 0)) && !skipBytes(9, &nOffset)) return HEADER_INFO();
        if ((nVersion >= innoVersionValue(5, 5, 7)) && !skipBytes(1, &nOffset)) return HEADER_INFO();

        const qint32 nPasswordSize = (nVersion >= innoVersionValue(6, 4, 0)) ? 48 :
                                     ((nVersion >= innoVersionValue(5, 3, 9)) ? 28 : 24);
        if (!skipBytes(nPasswordSize + 12, &nOffset)) return HEADER_INFO();
        if (!skipBytes(3, &nOffset)) return HEADER_INFO();  // log, dir warning, privileges
        if ((nVersion >= innoVersionValue(5, 7, 0)) && !skipBytes(1, &nOffset)) return HEADER_INFO();
        if (!skipBytes(2, &nOffset)) return HEADER_INFO();  // language dialog/detection
    }

    if ((nOffset < 0) || (nOffset >= baBlock1.size())) return HEADER_INFO();
    const quint8 nCompression = (quint8)baBlock1.at(nOffset++);
    const quint8 nMaxCompression = (nVersion >= innoVersionValue(5, 3, 9)) ? 4 : 3;
    if (nCompression > nMaxCompression) return HEADER_INFO();
    result.compression = (INNO_COMPRESSION)nCompression;

    if (nVersion >= innoVersionValue(6, 7, 0)) {
        if (!skipBytes(18, &nOffset)) return HEADER_INFO();  // page enums, display size, option flags
    } else {
        if ((nVersion >= innoVersionValue(5, 1, 0)) && (nVersion < innoVersionValue(6, 3, 0)) && !skipBytes(2, &nOffset)) return HEADER_INFO();
        if ((nVersion >= innoVersionValue(5, 2, 1)) && (nVersion < innoVersionValue(5, 3, 10)) && !skipBytes(8, &nOffset)) return HEADER_INFO();
        if ((nVersion >= innoVersionValue(5, 3, 3)) && !skipBytes(2, &nOffset)) return HEADER_INFO();
        if (nVersion >= innoVersionValue(5, 5, 0)) {
            if (!skipBytes(8, &nOffset)) return HEADER_INFO();
        } else if ((nVersion >= innoVersionValue(5, 3, 6)) && !skipBytes(4, &nOffset)) {
            return HEADER_INFO();
        }
        if (!skipBytes(6, &nOffset)) return HEADER_INFO();
    }

    result.nHeaderEndOffset = nOffset;
    result.bIsValid = true;
    return result;
}

QList<XInnoSetup::DATA_ENTRY> XInnoSetup::_parseDataEntries(const QByteArray &baBlock2, const INNO_VERSION &version,
                                                            bool bRev2, qint32 nExpectedCount,
                                                            INNO_COMPRESSION headerCompression)
{
    QList<DATA_ENTRY> listResult;

    if (!version.bIsValid || (nExpectedCount <= 0) || (headerCompression == INNO_COMPRESSION_UNKNOWN)) return listResult;

    const quint64 nVersion = innoVersionValue(version);
    qint32 nEntrySize = 0;
    qint32 nDigestOffset = 36;
    qint32 nDigestSize = 0;
    qint32 nTimeOffset = 0;
    qint32 nFlagsOffset = 0;
    qint32 nFlagsSize = 0;
    INNO_CHECKSUM checksumType = INNO_CHECKSUM_UNKNOWN;

    if (bRev2) {
        if (nVersion < innoVersionValue(6, 5, 0)) return listResult;
        nEntrySize = 89;
        nDigestOffset = 40;
        nDigestSize = 32;
        nTimeOffset = 72;
        nFlagsOffset = 88;
        nFlagsSize = 1;
        checksumType = INNO_CHECKSUM_SHA256;
    } else if (nVersion >= innoVersionValue(6, 4, 0)) {
        nEntrySize = 87;
        nDigestSize = 32;
        nTimeOffset = 68;
        nFlagsOffset = 84;
        nFlagsSize = 2;
        checksumType = INNO_CHECKSUM_SHA256;
    } else if (nVersion >= innoVersionValue(6, 3, 0)) {
        nEntrySize = 75;
        nDigestSize = 20;
        nTimeOffset = 56;
        nFlagsOffset = 72;
        nFlagsSize = 2;
        checksumType = INNO_CHECKSUM_SHA1;
    } else if (nVersion >= innoVersionValue(5, 3, 9)) {
        nEntrySize = 74;
        nDigestSize = 20;
        nTimeOffset = 56;
        nFlagsOffset = 72;
        nFlagsSize = 2;
        checksumType = INNO_CHECKSUM_SHA1;
    } else if (nVersion >= innoVersionValue(5, 1, 13)) {
        nEntrySize = 70;
        nDigestSize = 16;
        nTimeOffset = 52;
        nFlagsOffset = 68;
        nFlagsSize = 2;
        checksumType = INNO_CHECKSUM_MD5;
    } else if (nVersion >= innoVersionValue(5, 0, 0)) {
        nEntrySize = 69;
        nDigestSize = 16;
        nTimeOffset = 52;
        nFlagsOffset = 68;
        nFlagsSize = 1;
        checksumType = INNO_CHECKSUM_MD5;
    } else {
        return listResult;
    }

    if ((nExpectedCount > (std::numeric_limits<qint32>::max() / nEntrySize)) ||
        (baBlock2.size() != nExpectedCount * nEntrySize)) return listResult;

    const qint32 nShift = bRev2 ? 4 : 0;

    for (qint32 i = 0; i < nExpectedCount; i++) {
        const qint32 nBase = i * nEntrySize;
        const char *pEntry = baBlock2.constData() + nBase;
        DATA_ENTRY entry = {};

        entry.nFirstSlice = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(pEntry));
        entry.nLastSlice = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(pEntry + 4));
        entry.nChunkStartOffset = bRev2 ?
            qFromLittleEndian<qint64>(reinterpret_cast<const uchar *>(pEntry + 8)) :
            qint64(qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(pEntry + 8)));
        entry.nChunkSubOffset = qFromLittleEndian<qint64>(reinterpret_cast<const uchar *>(pEntry + 12 + nShift));
        entry.nOriginalSize = qFromLittleEndian<qint64>(reinterpret_cast<const uchar *>(pEntry + 20 + nShift));
        entry.nChunkCompressedSize = qFromLittleEndian<qint64>(reinterpret_cast<const uchar *>(pEntry + 28 + nShift));
        entry.baChecksum = baBlock2.mid(nBase + nDigestOffset, nDigestSize);
        entry.checksumType = checksumType;
        entry.nFileTime = qFromLittleEndian<quint64>(reinterpret_cast<const uchar *>(pEntry + nTimeOffset));
        entry.nFileVersionMS = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(pEntry + nTimeOffset + 8));
        entry.nFileVersionLS = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(pEntry + nTimeOffset + 12));
        entry.nFlags = (quint8)pEntry[nFlagsOffset];
        if (nFlagsSize == 2) entry.nFlags |= quint16((quint8)pEntry[nFlagsOffset + 1]) << 8;

        if ((entry.nFirstSlice != 0) || (entry.nLastSlice != 0) || (entry.nChunkStartOffset < 0) ||
            (entry.nChunkSubOffset < 0) || (entry.nOriginalSize < 0) || (entry.nChunkCompressedSize < 0) ||
            (entry.nChunkSubOffset > (std::numeric_limits<qint64>::max)() - entry.nOriginalSize) ||
            (entry.baChecksum.size() != nDigestSize)) return QList<DATA_ENTRY>();

        if (bRev2) {
            entry.bCallInstructionOptimized = (entry.nFlags & (1U << 2)) != 0;
            entry.bChunkEncrypted = (entry.nFlags & (1U << 3)) != 0;
            entry.bChunkCompressed = (entry.nFlags & (1U << 4)) != 0;
        } else {
            entry.bCallInstructionOptimized = (entry.nFlags & (1U << 4)) != 0;
            entry.bChunkEncrypted = (entry.nFlags & (1U << 6)) != 0;
            entry.bChunkCompressed = (entry.nFlags & (1U << 7)) != 0;
        }

        entry.compression = entry.bChunkCompressed ? headerCompression : INNO_COMPRESSION_STORE;
        if (entry.bChunkEncrypted || (entry.compression == INNO_COMPRESSION_UNKNOWN)) return QList<DATA_ENTRY>();

        listResult.append(entry);
    }

    return listResult;
}

QList<XInnoSetup::FILE_ENTRY> XInnoSetup::_parseFileEntries(const QByteArray &baBlock1, const HEADER_INFO &headerInfo,
                                                            const INNO_VERSION &version, bool bRev2)
{
    QList<FILE_ENTRY> listResult;

    if (!headerInfo.bIsValid || !version.bIsValid || (headerInfo.nHeaderEndOffset < 0)) return listResult;
    if (!version.bUnicode) return _parseFileEntriesAnsi(baBlock1, headerInfo, version);

    const quint64 nVersion = innoVersionValue(version);
    const bool bLegacySchema = !bRev2 &&
        ((version.nMajor == 5) || ((version.nMajor == 6) && (version.nMinor <= 4)));
    const bool bModernSchema = bRev2 &&
        (((version.nMajor == 6) && (version.nMinor >= 7)) || (version.nMajor == 7));

    // 6.5/6.6 have their own packed header revisions and are deliberately
    // rejected by _parseHeaderInfo. Any other unmodelled combination fails closed.
    if ((!bLegacySchema && !bModernSchema) ||
        (bLegacySchema && (headerInfo.nCountCount != 16)) ||
        (bModernSchema && (headerInfo.nCountCount != 17))) return listResult;

    qint32 nOffset = headerInfo.nHeaderEndOffset;
    const auto skipBytes = [&](qint32 nSize, qint32 *pnOffset) -> bool {
        if (!pnOffset || (nSize < 0) || (*pnOffset < 0) || (*pnOffset > baBlock1.size()) ||
            (nSize > baBlock1.size() - *pnOffset)) return false;
        *pnOffset += nSize;
        return true;
    };
    const auto readWide = [&](qint32 *pnOffset, QString *psValue) -> bool {
        if (!pnOffset) return false;
        qint32 nNewOffset = *pnOffset;
        const QString sValue = _readWideString(baBlock1, *pnOffset, &nNewOffset);
        if (nNewOffset <= *pnOffset) return false;
        *pnOffset = nNewOffset;
        if (psValue) *psValue = sValue;
        return true;
    };
    const auto readAnsi = [&](qint32 *pnOffset) -> bool {
        if (!pnOffset) return false;
        qint32 nNewOffset = *pnOffset;
        _readAnsiString(baBlock1, *pnOffset, &nNewOffset);
        if (nNewOffset <= *pnOffset) return false;
        *pnOffset = nNewOffset;
        return true;
    };
    const auto skipEntryArray = [&](qint32 nCount, qint32 nWideStrings, qint32 nAnsiStrings,
                                    qint32 nFixedSize, qint32 *pnOffset) -> bool {
        if ((nCount < 0) || !pnOffset) return false;
        for (qint32 i = 0; i < nCount; i++) {
            for (qint32 j = 0; j < nWideStrings; j++) {
                if (!readWide(pnOffset, nullptr)) return false;
            }
            for (qint32 j = 0; j < nAnsiStrings; j++) {
                if (!readAnsi(pnOffset)) return false;
            }
            if (!skipBytes(nFixedSize, pnOffset)) return false;
        }
        return true;
    };

    qint32 nFileWideStrings = 0;
    qint32 nFileAnsiStrings = 0;
    qint32 nFileFixedSize = 0;
    qint32 nLocationOffset = 0;
    qint32 nFileTypeOffset = 0;
    qint32 nVerificationTypeOffset = -1;
    qint32 nBitnessOffset = -1;

    if (bLegacySchema) {
        // Serialized 5.x-6.4 arrays from Shared.Struct/SECompressedBlockWrite.
        // Released Unicode setup-data uses 21 fixed bytes. The narrow 5.2.5
        // Unicode beta retained the legacy LanguageCodePage dword (25 bytes).
        if (nVersion < innoVersionValue(5, 2, 5)) return QList<FILE_ENTRY>();
        const qint32 nLanguageTail = (nVersion < innoVersionValue(5, 3, 0)) ? 25 : 21;
        if (!skipEntryArray(headerInfo.anCounts[0], 6, 4, nLanguageTail, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[1], 2, 0, 4, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[2], 0, 1, 0, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[3], 4, 0, 30, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[4], 5, 0, 42, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[5], 6, 0, 26, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[6], 7, 0, 27, &nOffset)) return QList<FILE_ENTRY>();

        nFileWideStrings = (nVersion >= innoVersionValue(5, 2, 5)) ? 10 : 9;
        nFileFixedSize = 43;
        nLocationOffset = 20;
        nFileTypeOffset = 42;
    } else {
        // 6.7/7.0 add the ISSig-key array and verification/download fields.
        if (!skipEntryArray(headerInfo.anCounts[0], 4, 4, 19, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[1], 2, 0, 4, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[2], 0, 1, 0, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[3], 4, 0, 30, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[4], 5, 0, 39, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[5], 6, 0, 23, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[6], 7, 0, 27, &nOffset) ||
            !skipEntryArray(headerInfo.anCounts[7], 3, 0, 0, &nOffset)) return QList<FILE_ENTRY>();

        nFileWideStrings = 15;
        nFileAnsiStrings = 1;
        nFileFixedSize = (version.nMajor >= 7) ? 81 : 80;
        nVerificationTypeOffset = 32;
        nLocationOffset = 53;
        nBitnessOffset = (version.nMajor >= 7) ? 71 : -1;
        nFileTypeOffset = nFileFixedSize - 1;
    }

    for (qint32 i = 0; i < headerInfo.nFileCount; i++) {
        QString sDestination;
        for (qint32 j = 0; j < nFileWideStrings; j++) {
            QString sValue;
            if (!readWide(&nOffset, &sValue)) return QList<FILE_ENTRY>();
            if (j == 1) sDestination = sValue;
        }
        for (qint32 j = 0; j < nFileAnsiStrings; j++) {
            if (!readAnsi(&nOffset)) return QList<FILE_ENTRY>();
        }

        const qint32 nFixedOffset = nOffset;
        if (!skipBytes(nFileFixedSize, &nOffset)) return QList<FILE_ENTRY>();

        const quint32 nLocation = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(
            baBlock1.constData() + nFixedOffset + nLocationOffset));
        const quint8 nFileType = (quint8)baBlock1.at(nFixedOffset + nFileTypeOffset);
        if ((nFileType > 1) ||
            ((nVerificationTypeOffset >= 0) &&
             ((quint8)baBlock1.at(nFixedOffset + nVerificationTypeOffset) > 2)) ||
            ((nBitnessOffset >= 0) && ((quint8)baBlock1.at(nFixedOffset + nBitnessOffset) > 4)) ||
            ((nLocation != 0xffffffffU) && (nLocation >= (quint32)headerInfo.nDataEntryCount))) {
            return QList<FILE_ENTRY>();
        }

        for (QChar ch : sDestination) {
            if ((ch.unicode() == 0) || (ch.unicode() < 0x20)) return QList<FILE_ENTRY>();
        }

        // LocationEntry=-1 denotes no data. Shared/reordered locations are valid:
        // traverse nFileCount records and preserve each serialized index.
        if (!sDestination.isEmpty() && (nLocation != 0xffffffffU)) {
            FILE_ENTRY fileEntry = {};
            fileEntry.sDestName = sDestination;
            fileEntry.nLocationEntry = (qint32)nLocation;
            listResult.append(fileEntry);
        }
    }

    return listResult;
}

QList<XInnoSetup::FILE_ENTRY> XInnoSetup::_parseFileEntriesAnsi(const QByteArray &baBlock1,
                                                                const HEADER_INFO &headerInfo,
                                                                const INNO_VERSION &version)
{
    QList<FILE_ENTRY> listResult;

    if (!headerInfo.bIsValid || !version.bIsValid || version.bUnicode ||
        (version.nMajor != 5) || (headerInfo.nHeaderEndOffset < 0)) return listResult;

    qint32 nOffset = headerInfo.nHeaderEndOffset;
    const quint64 nVersion = innoVersionValue(version);

    const auto skipBytes = [&](qint32 nSize, qint32 *pnOffset) -> bool {
        if (!pnOffset || (nSize < 0) || (*pnOffset < 0) || (*pnOffset > baBlock1.size()) ||
            (nSize > baBlock1.size() - *pnOffset)) return false;
        *pnOffset += nSize;
        return true;
    };
    const auto readString = [&](qint32 *pnOffset, QString *psValue) -> bool {
        if (!pnOffset) return false;
        qint32 nNewOffset = *pnOffset;
        const QString sValue = _readAnsiString(baBlock1, *pnOffset, &nNewOffset);
        if (nNewOffset <= *pnOffset) return false;
        *pnOffset = nNewOffset;
        if (psValue) *psValue = sValue;
        return true;
    };
    const auto skipEntryArray = [&](qint32 nCount, qint32 nStringCount, qint32 nFixedSize,
                                    qint32 *pnOffset) -> bool {
        if ((nCount < 0) || !pnOffset) return false;
        for (qint32 i = 0; i < nCount; i++) {
            for (qint32 j = 0; j < nStringCount; j++) {
                if (!readString(pnOffset, nullptr)) return false;
            }
            if (!skipBytes(nFixedSize, pnOffset)) return false;
        }
        return true;
    };

    // Arrays preceding TSetupFileEntry in setup-0. Their 5.x ANSI schemas are fixed
    // except for the language RTL byte introduced in 5.2.3.
    const qint32 nLanguageTail = 24 + ((nVersion >= innoVersionValue(5, 2, 3)) ? 1 : 0);
    if (!skipEntryArray(headerInfo.anCounts[0], 10, nLanguageTail, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[1], 2, 4, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[2], 1, 0, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[3], 4, 30, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[4], 5, 42, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[5], 6, 26, &nOffset) ||
        !skipEntryArray(headerInfo.anCounts[6], 7, 27, &nOffset)) return QList<FILE_ENTRY>();

    const qint32 nStringCount = (nVersion >= innoVersionValue(5, 2, 5)) ? 10 : 9;

    for (qint32 i = 0; i < headerInfo.nFileCount; i++) {
        QString sDestination;

        for (qint32 j = 0; j < nStringCount; j++) {
            QString sValue;
            if (!readString(&nOffset, &sValue)) return QList<FILE_ENTRY>();
            if (j == 1) sDestination = sValue;
        }

        const qint32 nTailOffset = nOffset;
        if (!skipBytes(43, &nOffset)) return QList<FILE_ENTRY>();

        const quint32 nLocation = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(
            baBlock1.constData() + nTailOffset + 20));
        const quint8 nFileType = (quint8)baBlock1.at(nTailOffset + 42);

        if ((nFileType > 1) || ((nLocation != 0xffffffffU) && (nLocation >= (quint32)headerInfo.nDataEntryCount))) {
            return QList<FILE_ENTRY>();
        }

        if (!sDestination.isEmpty()) {
            for (QChar ch : sDestination) {
                if ((ch.unicode() == 0) || (ch.unicode() < 0x20)) return QList<FILE_ENTRY>();
            }
        }

        if (!sDestination.isEmpty() && (nLocation != 0xffffffffU)) {
            FILE_ENTRY fileEntry = {};
            fileEntry.sDestName = sDestination;
            fileEntry.nLocationEntry = (qint32)nLocation;
            listResult.append(fileEntry);
        }
    }

    return listResult;
}

bool XInnoSetup::_parseRealInnoSetup(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    // Find the offset table (rDlPtS magic)
    OFFSET_TABLE offsetTable = _findOffsetTable(pPdStruct);

    if (!offsetTable.bIsValid) {
        return false;
    }

    // header_offset and data_offset are absolute file offsets
    qint64 nSetup0Offset = offsetTable.nHeaderOffset;
    qint64 nDataStreamOffset = offsetTable.nDataOffset;
    qint64 nFileSize = getSize();

    if ((nSetup0Offset >= nFileSize) || (nDataStreamOffset >= nFileSize)) {
        return false;
    }

    // Read the 64-byte version string at setup-0 header
    if (nSetup0Offset + 64 > nFileSize) {
        return false;
    }

    QByteArray baVersionId = read_array(nSetup0Offset, 64);
    const INNO_VERSION version = _parseVersionId(baVersionId);
    if (!version.bIsValid) return false;

    // Read Block Stream 1 (file entries + setup header)
    qint64 nBlock1Offset = nSetup0Offset + 64;
    const bool bRev2 = (offsetTable.nRevision == 2);
    const quint64 nVersion = innoVersionValue(version);

    // The loader-table revision changed at 6.5.0. Refuse mismatched pairs even
    // if their individual fields happen to look plausible.
    if (bRev2 != (nVersion >= innoVersionValue(6, 5, 0))) return false;

    if (bRev2) {
        // Inno Setup >= 6.5.0 (revision 2): the 64-byte version string is followed by a
        // fixed 53-byte block-stream prefix that begins with the 0xDC9289B2 signature
        // (magic + reserved fields, constant across 6.7.x / 7.0.x), before the first
        // compressed block. The subsequent blocks carry no such prefix. The block
        // headers themselves widen stored_size from 32-bit to 64-bit.
        static const quint32 nRev2BlockMagic = 0xDC9289B2;
        static const qint64 nRev2Prefix = 53;

        if ((nBlock1Offset + nRev2Prefix > nFileSize) || (read_uint32(nBlock1Offset, false) != nRev2BlockMagic)) {
            return false;
        }

        nBlock1Offset += nRev2Prefix;
    }

    qint64 nBlock1Consumed = 0;
    QByteArray baBlock1 = _readBlockStream(nBlock1Offset, &nBlock1Consumed, pPdStruct, bRev2);

    if (baBlock1.isEmpty()) {
        return false;
    }

    // Read Block Stream 2 (data entries)
    qint64 nBlock2Offset = nBlock1Offset + nBlock1Consumed;
    qint64 nBlock2Consumed = 0;
    QByteArray baBlock2 = _readBlockStream(nBlock2Offset, &nBlock2Consumed, pPdStruct, bRev2);

    if (baBlock2.isEmpty()) {
        return false;
    }

    const HEADER_INFO headerInfo = _parseHeaderInfo(baBlock1, version);
    if (!headerInfo.bIsValid) return false;

    // The version and header count choose one exact file-location layout. Divisibility is not
    // sufficient because several legitimate block lengths have multiple possible factors.
    QList<DATA_ENTRY> listDataEntries = _parseDataEntries(baBlock2, version, bRev2,
                                                          headerInfo.nDataEntryCount,
                                                          headerInfo.compression);

    if (listDataEntries.isEmpty()) {
        return false;
    }

    qint32 nNumDataEntries = listDataEntries.count();

    // Parse file entries from Block 1
    QList<FILE_ENTRY> listFileEntries = _parseFileEntries(baBlock1, headerInfo, version, bRev2);

    if (listFileEntries.isEmpty()) {
        return false;
    }

    pContext->listDataEntries = listDataEntries;
    pContext->listFileEntries = listFileEntries;
    pContext->nDataStreamOffset = nDataStreamOffset;
    pContext->version = version;

    // Validate every exact StartOffset. Solid members share a start; unrelated chunks may
    // legitimately have equal compressed sizes and must remain distinct.
    QMap<qint64, QPair<qint64, INNO_COMPRESSION> > mapChunks;

    for (const DATA_ENTRY &entry : listDataEntries) {
        if ((entry.nChunkStartOffset > nFileSize - nDataStreamOffset) ||
            (entry.nChunkCompressedSize > nFileSize - nDataStreamOffset - entry.nChunkStartOffset - 4)) return false;

        const qint64 nChunkOffset = nDataStreamOffset + entry.nChunkStartOffset;
        if ((nChunkOffset < 0) || (nChunkOffset > nFileSize - 4) ||
            (read_array(nChunkOffset, 4) != QByteArray("zlb\x1a", 4))) return false;

        if (mapChunks.contains(entry.nChunkStartOffset)) {
            const QPair<qint64, INNO_COMPRESSION> chunk = mapChunks.value(entry.nChunkStartOffset);
            if ((chunk.first != entry.nChunkCompressedSize) || (chunk.second != entry.compression)) return false;
        } else {
            mapChunks.insert(entry.nChunkStartOffset, qMakePair(entry.nChunkCompressedSize, entry.compression));
        }
    }

    // Build ARCHIVERECORDs matching file entries to file-location entries.
    for (qint32 i = 0; i < listFileEntries.count(); i++) {
        const FILE_ENTRY &fileEntry = listFileEntries.at(i);
        qint32 nLocIdx = fileEntry.nLocationEntry;

        if ((nLocIdx < 0) || (nLocIdx >= nNumDataEntries)) {
            continue;
        }

        const DATA_ENTRY &dataEntry = listDataEntries.at(nLocIdx);

        // Clean up the filename (remove backslashes)
        QString sFileName = fileEntry.sDestName;
        sFileName = sFileName.replace(QString("\\"), QString("/"));

        ARCHIVERECORD record = {};
        record.nStreamOffset = nDataStreamOffset + dataEntry.nChunkStartOffset;
        record.nStreamSize = dataEntry.nChunkCompressedSize;
        record.mapProperties.insert(FPART_PROP_ORIGINALNAME, sFileName);
        record.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, dataEntry.nOriginalSize);
        record.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, dataEntry.nChunkCompressedSize);
        record.mapProperties.insert(FPART_PROP_STREAMOFFSET, dataEntry.nChunkSubOffset);
        record.mapProperties.insert(FPART_PROP_STREAMSIZE, dataEntry.nOriginalSize);
        record.mapProperties.insert(FPART_PROP_ISFOLDER, false);
        record.mapProperties.insert(FPART_PROP_HANDLEMETHOD, (quint32)innoCompressionToHandleMethod(dataEntry.compression));
        if (dataEntry.bCallInstructionOptimized) {
            record.mapProperties.insert(FPART_PROP_HANDLEMETHOD2, (quint32)HANDLE_METHOD_BCJ);
        }

        if (!dataEntry.baChecksum.isEmpty()) {
            QString sChecksumType;
            if (dataEntry.checksumType == INNO_CHECKSUM_MD5) sChecksumType = QStringLiteral("MD5");
            else if (dataEntry.checksumType == INNO_CHECKSUM_SHA1) sChecksumType = QStringLiteral("SHA1");
            else if (dataEntry.checksumType == INNO_CHECKSUM_SHA256) sChecksumType = QStringLiteral("SHA256");
            else return false;

            record.mapProperties.insert(FPART_PROP_CHECKSUM, QString::fromLatin1(dataEntry.baChecksum.toHex()));
            record.mapProperties.insert(FPART_PROP_CHECKSUMTYPE, sChecksumType);
        }

        pContext->listAllRecords.append(record);
    }

    return !pContext->listAllRecords.isEmpty();
}

QByteArray XInnoSetup::_decompressDataChunk(qint64 nChunkOffset, qint64 nChunkCompressedSize,
                                            qint64 nOutputLimit, INNO_COMPRESSION compression, PDSTRUCT *pPdStruct)
{
    const qint64 nFileSize = getSize();

    if ((nChunkOffset < 0) || (nChunkCompressedSize < 0) || (nOutputLimit <= 0) ||
        (nOutputLimit > (std::numeric_limits<qint32>::max)()) || (nChunkOffset > nFileSize - 4) ||
        (nChunkCompressedSize > nFileSize - nChunkOffset - 4) ||
        (read_array(nChunkOffset, 4) != QByteArray("zlb\x1a", 4))) return QByteArray();

    qint64 nInputOffset = nChunkOffset + 4;
    qint64 nInputSize = nChunkCompressedSize;
    QByteArray baProperty;

    if (compression == INNO_COMPRESSION_LZMA1) {
        if (nInputSize < 5) return QByteArray();
        baProperty = read_array(nInputOffset, 5);
        if (baProperty.size() != 5) return QByteArray();
        nInputOffset += 5;
        nInputSize -= 5;
    } else if (compression == INNO_COMPRESSION_LZMA2) {
        if (nInputSize < 1) return QByteArray();
        baProperty = read_array(nInputOffset, 1);
        if (baProperty.size() != 1) return QByteArray();
        nInputOffset++;
        nInputSize--;
    } else if ((compression != INNO_COMPRESSION_STORE) && (compression != INNO_COMPRESSION_ZLIB) &&
               (compression != INNO_COMPRESSION_BZIP2)) {
        return QByteArray();
    }

    QBuffer bufOutput;
    // Zlib validation rereads the produced bytes to verify its Adler-32 trailer.
    if (!bufOutput.open(QIODevice::ReadWrite)) return QByteArray();

    XBinary::DATAPROCESS_STATE decompressState = {};
    decompressState.mapProperties.insert(FPART_PROP_HANDLEMETHOD, (quint32)innoCompressionToHandleMethod(compression));
    decompressState.pDeviceInput = getDevice();
    decompressState.pDeviceOutput = &bufOutput;
    decompressState.nInputOffset = nInputOffset;
    decompressState.nInputLimit = nInputSize;
    decompressState.nProcessedOffset = 0;
    decompressState.nProcessedLimit = nOutputLimit;

    bool bOk = false;

    switch (compression) {
        case INNO_COMPRESSION_STORE:
            bOk = XStoreDecoder::decompress(&decompressState, pPdStruct) &&
                  (decompressState.nCountInput == nInputSize) && (decompressState.nCountOutput == nInputSize);
            break;
        case INNO_COMPRESSION_ZLIB:
            bOk = XDeflateDecoder::decompress_zlib(&decompressState, pPdStruct);
            break;
        case INNO_COMPRESSION_BZIP2:
            bOk = XBZIP2Decoder::decompress(&decompressState, pPdStruct);
            break;
        case INNO_COMPRESSION_LZMA1:
            bOk = XLZMADecoder::decompress(&decompressState, baProperty, pPdStruct);
            break;
        case INNO_COMPRESSION_LZMA2:
            bOk = XLZMADecoder::decompressLZMA2(&decompressState, baProperty, pPdStruct);
            break;
        default:
            break;
    }

    bufOutput.close();
    if (!bOk || (decompressState.nCountOutput != nOutputLimit) || (bufOutput.data().size() != nOutputLimit)) return QByteArray();
    return bufOutput.data();
}
