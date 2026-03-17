/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinnosetup.h"

#include "xstoredecoder.h"
#include "xlzmadecoder.h"

#include <QBuffer>
#include <QtEndian>
#include <QCryptographicHash>
#include <QDebug>

XBinary::XCONVERT _TABLE_XINNOSETUP_STRUCTID[] = {
    {XInnoSetup::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XInnoSetup::STRUCTID_HEADER, "HEADER", QString("Header")},
};

// rDlPtS magic bytes for InnoSetup offset table (version 5.1.5+)
static const quint8 g_aRDlPtSMagic[] = {0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A};
static const qint32 g_nRDlPtSMagicSize = 12;

XInnoSetup::XInnoSetup(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XInnoSetup::~XInnoSetup()
{
}

QString XInnoSetup::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XINNOSETUP_STRUCTID, sizeof(_TABLE_XINNOSETUP_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XInnoSetup::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

XInnoSetup::INTERNAL_INFO XInnoSetup::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _analyse(pPdStruct);
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
        record.mapProperties.insert(FPART_PROP_ISFOLDER, false);
        record.mapProperties.insert(FPART_PROP_STREAMOFFSET, (qint64)nDataOffset);
        record.mapProperties.insert(FPART_PROP_STREAMSIZE, (qint64)nDataSize);

        listResult.append(record);
    }

    return listResult;
}

bool XInnoSetup::initUnpack(XBinary::UNPACK_STATE *pState, const QMap<XBinary::UNPACK_PROP, QVariant> &mapProperties, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(mapProperties)

    if (!pState) {
        return false;
    }

    INTERNAL_INFO info = _analyse(pPdStruct);

    if (!info.bIsValid) {
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->bIsRealFormat = false;
    pContext->nSignatureOffset = info.nSignatureOffset;
    pContext->nDataStreamOffset = 0;

    // Try real InnoSetup format first
    if (_parseRealInnoSetup(pContext, info.nSignatureOffset, pPdStruct)) {
        pContext->bIsRealFormat = true;
    } else {
        // Fallback to synthetic ISDF format
        QList<ARCHIVERECORD> listRecords = _parseSyntheticFileEntries(info.nSignatureOffset, pPdStruct);
        pContext->listAllRecords = listRecords;
        pContext->bIsRealFormat = false;
    }

    pState->pContext = pContext;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = pContext->listAllRecords.count();

    return true;
}

XBinary::ARCHIVERECORD XInnoSetup::infoCurrent(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};

    if (!pState || !pState->pContext) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if ((pState->nCurrentIndex >= 0) && (pState->nCurrentIndex < pContext->listAllRecords.count())) {
        result = pContext->listAllRecords.at(pState->nCurrentIndex);
    }

    return result;
}

bool XInnoSetup::unpackCurrent(XBinary::UNPACK_STATE *pState, QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listAllRecords.count())) {
        return false;
    }

    ARCHIVERECORD record = pContext->listAllRecords.at(pState->nCurrentIndex);

    qint64 nUncompressedSize = record.mapProperties.value(FPART_PROP_UNCOMPRESSEDSIZE).toLongLong();

    // Empty file — nothing to write
    if (nUncompressedSize == 0) {
        return true;
    }

    if (!pDevice) {
        return false;
    }

    if (pContext->bIsRealFormat) {
        // Real InnoSetup: solid LZMA decompression
        qint64 nStreamOffset = record.nStreamOffset;                                                       // Absolute offset of zlb chunk in file
        qint64 nStreamSize = record.nStreamSize;                                                           // Compressed size of the zlb chunk
        qint64 nDecompressedOffset = record.mapProperties.value(FPART_PROP_STREAMOFFSET).toLongLong();     // Offset within decompressed chunk
        qint64 nChunkCompressedSize = record.mapProperties.value(FPART_PROP_COMPRESSEDSIZE).toLongLong();  // Chunk ID

        // Check if we have this chunk cached
        if (pContext->chunkCache.nChunkCompressedSize != nChunkCompressedSize || pContext->chunkCache.baDecompressedData.isEmpty()) {
            // Decompress the entire zlb chunk
            QByteArray baDecompressed = _decompressDataChunk(nStreamOffset, nStreamSize, pPdStruct);

            if (baDecompressed.isEmpty()) {
                qWarning() << "[InnoSetup] Failed to decompress data chunk at offset" << nStreamOffset;
                return false;
            }

            pContext->chunkCache.nChunkCompressedSize = nChunkCompressedSize;
            pContext->chunkCache.baDecompressedData = baDecompressed;
        }

        // Extract this file's data from the decompressed chunk
        const QByteArray &baChunk = pContext->chunkCache.baDecompressedData;

        if (nDecompressedOffset + nUncompressedSize > baChunk.size()) {
            qWarning() << "[InnoSetup] File data exceeds chunk boundary: offset" << nDecompressedOffset << "size" << nUncompressedSize << "chunk size" << baChunk.size();
            return false;
        }

        qint64 nWritten = pDevice->write(baChunk.constData() + nDecompressedOffset, nUncompressedSize);

        return (nWritten == nUncompressedSize);
    } else {
        // Synthetic ISDF: stored data — direct copy using XStoreDecoder
        qint64 nStreamOffset = record.mapProperties.value(FPART_PROP_STREAMOFFSET).toLongLong();
        qint64 nStreamSize = record.mapProperties.value(FPART_PROP_STREAMSIZE).toLongLong();

        if (nStreamSize == 0) {
            return true;
        }

        // Clamp to file size
        qint64 nFileSize = getSize();

        if (nStreamOffset + nStreamSize > nFileSize) {
            nStreamSize = nFileSize - nStreamOffset;

            if (nStreamSize <= 0) {
                return false;
            }
        }

        XBinary::DATAPROCESS_STATE decompressState = {};
        decompressState.mapProperties.insert(XBinary::FPART_PROP_HANDLEMETHOD, XBinary::HANDLE_METHOD_STORE);
        decompressState.mapProperties.insert(XBinary::FPART_PROP_UNCOMPRESSEDSIZE, nStreamSize);
        decompressState.pDeviceInput = getDevice();
        decompressState.pDeviceOutput = pDevice;
        decompressState.nInputOffset = nStreamOffset;
        decompressState.nInputLimit = nStreamSize;
        decompressState.nProcessedOffset = 0;
        decompressState.nProcessedLimit = -1;

        return XStoreDecoder::decompress(&decompressState, pPdStruct);
    }
}

bool XInnoSetup::moveToNext(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    pState->nCurrentIndex++;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XInnoSetup::finishUnpack(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        pContext->listAllRecords.clear();
        pContext->listDataEntries.clear();
        pContext->listFileEntries.clear();
        pContext->chunkCache.baDecompressedData.clear();
        delete pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}

// ============================================================================
// Real InnoSetup format parsing methods
// ============================================================================

XInnoSetup::OFFSET_TABLE XInnoSetup::_findOffsetTable(PDSTRUCT *pPdStruct)
{
    OFFSET_TABLE result = {};
    result.bIsValid = false;

    qint64 nFileSize = getSize();

    // Search for the rDlPtS magic in the file
    // The offset table is typically in the PE resource section or near the end of the PE
    QByteArray baMagic((const char *)g_aRDlPtSMagic, g_nRDlPtSMagicSize);
    qint64 nTableOffset = find_array(0, nFileSize, baMagic.constData(), baMagic.size(), pPdStruct);

    if (nTableOffset == -1) {
        return result;
    }

    // Offset table layout after magic (12 bytes):
    // uint32 revision
    // uint32 unused (always 0)
    // uint32 exe_offset
    // uint32 exe_compressed_size
    // uint32 exe_uncompressed_size
    // uint32 exe_checksum
    // uint32 message_offset
    // uint32 header_offset
    // uint32 data_offset
    // uint32 table_crc

    qint64 nDataOffset = nTableOffset + g_nRDlPtSMagicSize;

    if (nDataOffset + 40 > nFileSize) {
        return result;
    }

    result.nTableOffset = nTableOffset;
    result.nRevision = read_uint32(nDataOffset + 0, false);
    // +4: unknown field
    // +8: exe compressed size or related
    // +12: exe uncompressed size or related
    // +16: checksum
    result.nHeaderOffset = read_uint32(nDataOffset + 20, false);  // Absolute offset of setup-0 header
    result.nDataOffset = read_uint32(nDataOffset + 24, false);    // Absolute offset of data stream
    result.bIsValid = true;

    return result;
}

QByteArray XInnoSetup::_stripCRCChunks(const QByteArray &baData)
{
    // Block stream data is split into chunks: [4-byte CRC32][up to 4096 bytes payload]
    // Strip the CRC32 prefixes and concatenate payloads
    QByteArray baResult;
    qint32 nPos = 0;
    qint32 nSize = baData.size();

    while (nPos < nSize) {
        if (nPos + 4 > nSize) {
            break;
        }

        nPos += 4;  // Skip chunk CRC32

        qint32 nChunkSize = qMin(4096, nSize - nPos);
        baResult.append(baData.constData() + nPos, nChunkSize);
        nPos += nChunkSize;
    }

    return baResult;
}

QByteArray XInnoSetup::_decompressLZMA1(const QByteArray &baData)
{
    // LZMA1 format: 1-byte props + 4-byte dict_size (LE) + raw stream
    if (baData.size() < 6) {
        return QByteArray();
    }

    QByteArray baProperty = baData.left(5);  // props byte + 4-byte dict_size
    QByteArray baCompressed = baData.mid(5);

    QBuffer bufInput;
    bufInput.setData(baCompressed);
    bufInput.open(QIODevice::ReadOnly);

    QBuffer bufOutput;
    bufOutput.open(QIODevice::WriteOnly);

    XBinary::DATAPROCESS_STATE decompressState = {};
    decompressState.pDeviceInput = &bufInput;
    decompressState.pDeviceOutput = &bufOutput;
    decompressState.nInputOffset = 0;
    decompressState.nInputLimit = baCompressed.size();
    decompressState.nProcessedOffset = 0;
    decompressState.nProcessedLimit = -1;

    bool bOk = XLZMADecoder::decompress(&decompressState, baProperty, nullptr);

    bufInput.close();
    bufOutput.close();

    if (!bOk) {
        return QByteArray();
    }

    return bufOutput.data();
}

QByteArray XInnoSetup::_readBlockStream(qint64 nOffset, qint64 *pnConsumed, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    // Block stream format:
    // uint32 CRC32 of (stored_size + compressed_flag)
    // uint32 stored_size
    // uint8  compressed_flag (1 = LZMA1 compressed)
    // <stored_size bytes of CRC-chunked data>

    qint64 nFileSize = getSize();

    if (nOffset + 9 > nFileSize) {
        if (pnConsumed) {
            *pnConsumed = 0;
        }

        return QByteArray();
    }

    // Read header
    // quint32 nHeaderCRC = read_uint32(nOffset, false);  // Not used for validation currently
    quint32 nStoredSize = read_uint32(nOffset + 4, false);
    quint8 nCompressedFlag = read_uint8(nOffset + 8);

    qint64 nConsumed = 9 + (qint64)nStoredSize;

    if (nOffset + nConsumed > nFileSize) {
        if (pnConsumed) {
            *pnConsumed = 0;
        }

        return QByteArray();
    }

    // Read the stored data
    QByteArray baStoredData = read_array(nOffset + 9, nStoredSize);

    // Strip per-chunk CRC32 prefixes
    QByteArray baPayload = _stripCRCChunks(baStoredData);

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

    QString sResult = QString::fromUtf16((const ushort *)(baData.constData() + nOffset + 4), nByteLen / 2);

    if (pnNewOffset) {
        *pnNewOffset = nOffset + 4 + nByteLen;
    }

    return sResult;
}

QList<XInnoSetup::DATA_ENTRY> XInnoSetup::_parseDataEntries(const QByteArray &baBlock2)
{
    QList<DATA_ENTRY> listResult;

    // Data entry layout (common fields at fixed offsets):
    //   [0-11]  3 x uint32 (FirstSlice, LastSlice, reserved = 12 bytes)
    //   [12-19] int64 ChunkSubOffset (offset within decompressed solid chunk)
    //   [20-27] int64 OriginalSize
    //   [28-35] int64 ChunkCompressedSize
    //   [36-67] SHA-256 hash (32 bytes)
    // Tail varies by version:
    //   v6.4.0.1: [68-75] FileTime, [76-83] FileVersion, [84-86] Flags = 87 bytes total
    //   v6.0.0:   [68-73] 6 bytes misc/flags = 74 bytes total

    // Auto-detect entry size: try known sizes and pick the one that divides evenly
    const qint32 anKnownSizes[] = {87, 74};
    const qint32 nKnownSizeCount = sizeof(anKnownSizes) / sizeof(qint32);
    qint32 nEntrySize = 0;
    qint32 nBlockSize = baBlock2.size();

    for (qint32 i = 0; i < nKnownSizeCount; i++) {
        if ((nBlockSize > 0) && (nBlockSize % anKnownSizes[i] == 0)) {
            qint32 nCandidateCount = nBlockSize / anKnownSizes[i];

            if (nCandidateCount > 0) {
                nEntrySize = anKnownSizes[i];
                break;
            }
        }
    }

    if (nEntrySize == 0) {
        return listResult;
    }

    qint32 nNumEntries = nBlockSize / nEntrySize;

    for (qint32 i = 0; i < nNumEntries; i++) {
        qint32 nBase = i * nEntrySize;
        const char *pEntry = baBlock2.constData() + nBase;

        DATA_ENTRY entry = {};
        entry.nChunkSubOffset = qFromLittleEndian<qint64>((const uchar *)(pEntry + 12));
        entry.nOriginalSize = qFromLittleEndian<qint64>((const uchar *)(pEntry + 20));
        entry.nChunkCompressedSize = qFromLittleEndian<qint64>((const uchar *)(pEntry + 28));
        entry.baSHA256 = baBlock2.mid(nBase + 36, 32);

        // Version-specific tail fields
        if (nEntrySize >= 87) {
            entry.nFileTime = qFromLittleEndian<quint64>((const uchar *)(pEntry + 68));
            entry.nFileVersionMS = qFromLittleEndian<quint32>((const uchar *)(pEntry + 76));
            entry.nFileVersionLS = qFromLittleEndian<quint32>((const uchar *)(pEntry + 80));
            entry.nFlags = (quint8)pEntry[84];
        }

        listResult.append(entry);
    }

    return listResult;
}

QList<XInnoSetup::FILE_ENTRY> XInnoSetup::_parseFileEntries(const QByteArray &baBlock1, qint32 nNumFiles)
{
    QList<FILE_ENTRY> listResult;

    // Strategy: search for {app}\ or {tmp}\ patterns in UTF-16LE, then score
    // each candidate by trial-parsing forward. The candidate producing the most
    // entries with valid location indices in [0, nNumFiles-1] wins.

    // Build UTF-16LE search patterns
    QByteArray baAppU16;
    {
        QString sApp = QString("{app}");

        for (qint32 i = 0; i < sApp.size(); i++) {
            baAppU16.append(sApp.at(i).toLatin1());
            baAppU16.append('\0');
        }
    }

    QByteArray baTmpU16;
    {
        QString sTmp = QString("{tmp}");

        for (qint32 i = 0; i < sTmp.size(); i++) {
            baTmpU16.append(sTmp.at(i).toLatin1());
            baTmpU16.append('\0');
        }
    }

    // Collect all {app}/{tmp} positions across the entire block
    QList<qint32> listPatternPositions;

    for (qint32 nPos = 0; nPos < baBlock1.size() - baAppU16.size(); nPos++) {
        if (memcmp(baBlock1.constData() + nPos, baAppU16.constData(), baAppU16.size()) == 0) {
            listPatternPositions.append(nPos);
        } else if (memcmp(baBlock1.constData() + nPos, baTmpU16.constData(), baTmpU16.size()) == 0) {
            listPatternPositions.append(nPos);
        }
    }

    if (listPatternPositions.isEmpty()) {
        return listResult;
    }

    // For each pattern position, resolve to entry start and score by trial-parsing
    const qint32 nDefaultNumericSize = 39;
    qint32 nBestScore = 0;
    qint32 nBestEntryStart = -1;
    qint32 nBestNumStrings = 0;
    qint32 nBestNumericSize = 0;

    // De-duplicate candidate entry starts
    QList<qint32> listTestedStarts;

    for (qint32 p = 0; p < listPatternPositions.count(); p++) {
        qint32 nPatternPos = listPatternPositions.at(p);

        // Walk back to find the WideString length prefix for DestName
        qint32 nDestNameOff = -1;

        for (qint32 nBack = 4; nBack < 500; nBack += 2) {
            qint32 nTestOff = nPatternPos - nBack;

            if (nTestOff < 4) {
                break;
            }

            quint32 nLen = qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nTestOff));

            if ((nLen > 0) && (nLen < 2000) && (nLen % 2 == 0) && (nTestOff + 4 + (qint32)nLen <= baBlock1.size())) {
                quint32 nPrevLen = qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nTestOff - 4));

                if (nPrevLen == 0) {
                    nDestNameOff = nTestOff;
                }

                break;
            }
        }

        if (nDestNameOff == -1) {
            continue;
        }

        qint32 nCandidateStart = nDestNameOff - 4;

        if (listTestedStarts.contains(nCandidateStart)) {
            continue;
        }

        listTestedStarts.append(nCandidateStart);

        // Count strings from this candidate entry start
        qint32 nOff = nCandidateStart;
        qint32 nStringCount = 0;

        for (qint32 s = 0; s < 20; s++) {
            qint32 nNewOff = 0;
            _readWideString(baBlock1, nOff, &nNewOff);

            if (nNewOff == nOff) {
                break;
            }

            nStringCount++;
            nOff = nNewOff;
        }

        if (nStringCount < 2) {
            continue;
        }

        // Probe numeric size by looking for next entry boundary
        qint32 nStringsEnd = nOff;
        qint32 nProbeNumericSize = 0;

        for (qint32 nProbe = nStringsEnd; nProbe < qMin(nStringsEnd + 200, baBlock1.size() - 8); nProbe++) {
            quint32 nVal1 = qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nProbe));

            if (nVal1 == 0) {
                quint32 nVal2 = qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nProbe + 4));

                if ((nVal2 > 4) && (nVal2 < 2000) && (nVal2 % 2 == 0) && (nProbe + 8 + (qint32)nVal2 <= baBlock1.size())) {
                    nProbeNumericSize = nProbe - nStringsEnd;
                    break;
                }
            }
        }

        if (nProbeNumericSize <= 0) {
            nProbeNumericSize = nDefaultNumericSize;
        }

        // Trial-parse forward: count entries with valid location indices
        qint32 nScore = 0;
        qint32 nTrialOff = nCandidateStart;

        for (qint32 nTrial = 0; nTrial < nNumFiles + 100; nTrial++) {
            if (nTrialOff + 4 > baBlock1.size()) {
                break;
            }

            qint32 nTrialStrOff = nTrialOff;
            qint32 nTrialStrings = 0;

            for (qint32 s = 0; s < nStringCount; s++) {
                qint32 nNewOff = 0;
                _readWideString(baBlock1, nTrialStrOff, &nNewOff);

                if (nNewOff == nTrialStrOff) {
                    break;
                }

                nTrialStrings++;
                nTrialStrOff = nNewOff;
            }

            if (nTrialStrings < 2) {
                break;
            }

            if (nTrialStrOff + 20 <= baBlock1.size()) {
                qint32 nLocIdx = (qint32)qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nTrialStrOff + 16));

                if ((nLocIdx >= 0) && (nLocIdx < nNumFiles)) {
                    nScore++;
                }
            }

            nTrialOff = nTrialStrOff + nProbeNumericSize;
        }

        if (nScore > nBestScore) {
            nBestScore = nScore;
            nBestEntryStart = nCandidateStart;
            nBestNumStrings = nStringCount;
            nBestNumericSize = nProbeNumericSize;
        }

        // Early exit if we have a strong candidate
        if (nBestScore >= 10) {
            break;
        }
    }

    if (nBestEntryStart == -1) {
        return listResult;
    }

    // Walk backwards from best candidate to find the true first entry
    qint32 nAnchor = nBestEntryStart;

    for (qint32 nAttempt = 0; nAttempt < 500; nAttempt++) {
        qint32 nPrevStringsEnd = nAnchor - nBestNumericSize;

        if (nPrevStringsEnd < 4) {
            break;
        }

        bool bFoundPrev = false;
        qint32 nMaxLookback = nBestNumStrings * 2004;
        qint32 nSearchFrom = qMax(0, nPrevStringsEnd - nMaxLookback);

        for (qint32 nTest = nPrevStringsEnd - (nBestNumStrings * 4); nTest >= nSearchFrom; nTest--) {
            if (nTest < 0) {
                break;
            }

            quint32 nFirstLen = qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nTest));

            if (nFirstLen != 0) {
                continue;
            }

            qint32 nCheckOff = nTest;
            qint32 nCheckCount = 0;

            for (qint32 s = 0; s < nBestNumStrings; s++) {
                qint32 nNewOff = 0;
                _readWideString(baBlock1, nCheckOff, &nNewOff);

                if (nNewOff == nCheckOff) {
                    break;
                }

                nCheckCount++;
                nCheckOff = nNewOff;
            }

            if ((nCheckCount == nBestNumStrings) && (nCheckOff == nPrevStringsEnd)) {
                if (nPrevStringsEnd + 20 <= baBlock1.size()) {
                    qint32 nLocIdx = (qint32)qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nPrevStringsEnd + 16));

                    if ((nLocIdx >= 0) && (nLocIdx < nNumFiles)) {
                        nAnchor = nTest;
                        bFoundPrev = true;
                        break;
                    }
                }
            }
        }

        if (!bFoundPrev) {
            break;
        }
    }

    // Parse all file entries forward from nAnchor
    qint32 nOff = nAnchor;

    for (qint32 nEntry = 0; nEntry < nNumFiles + 100; nEntry++) {
        if (nOff + 4 > baBlock1.size()) {
            break;
        }

        QStringList listStrings;
        qint32 nStrOff = nOff;

        for (qint32 i = 0; i < nBestNumStrings; i++) {
            qint32 nNewOff = 0;
            QString sStr = _readWideString(baBlock1, nStrOff, &nNewOff);

            if (nNewOff == nStrOff) {
                break;
            }

            listStrings.append(sStr);
            nStrOff = nNewOff;
        }

        if (listStrings.count() < 2) {
            break;
        }

        qint32 nNumOff = nStrOff;

        if (nNumOff + nBestNumericSize > baBlock1.size()) {
            break;
        }

        qint32 nLocationEntry = -1;

        if (nBestNumericSize >= 20) {
            nLocationEntry = (qint32)qFromLittleEndian<quint32>((const uchar *)(baBlock1.constData() + nNumOff + 16));
        }

        FILE_ENTRY fileEntry = {};
        fileEntry.sDestName = listStrings.at(1);
        fileEntry.nLocationEntry = nLocationEntry;

        listResult.append(fileEntry);

        nOff = nNumOff + nBestNumericSize;
    }

    return listResult;
}

bool XInnoSetup::_parseRealInnoSetup(UNPACK_CONTEXT *pContext, qint64 nSignatureOffset, PDSTRUCT *pPdStruct)
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

    // Read Block Stream 1 (file entries + setup header)
    qint64 nBlock1Offset = nSetup0Offset + 64;
    qint64 nBlock1Consumed = 0;
    QByteArray baBlock1 = _readBlockStream(nBlock1Offset, &nBlock1Consumed, pPdStruct);

    if (baBlock1.isEmpty()) {
        return false;
    }

    // Read Block Stream 2 (data entries)
    qint64 nBlock2Offset = nBlock1Offset + nBlock1Consumed;
    qint64 nBlock2Consumed = 0;
    QByteArray baBlock2 = _readBlockStream(nBlock2Offset, &nBlock2Consumed, pPdStruct);

    if (baBlock2.isEmpty()) {
        return false;
    }

    // Parse data entries from Block 2
    QList<DATA_ENTRY> listDataEntries = _parseDataEntries(baBlock2);

    if (listDataEntries.isEmpty()) {
        return false;
    }

    qint32 nNumDataEntries = listDataEntries.count();

    // Parse file entries from Block 1
    QList<FILE_ENTRY> listFileEntries = _parseFileEntries(baBlock1, nNumDataEntries);

    if (listFileEntries.isEmpty()) {
        return false;
    }

    pContext->listDataEntries = listDataEntries;
    pContext->listFileEntries = listFileEntries;
    pContext->nDataStreamOffset = nDataStreamOffset;

    // Build a mapping of LocationEntry index -> file entry
    // Group data entries by ChunkCompressedSize to identify solid chunks
    // and compute file offsets within the data stream

    // Step 1: Group data entries by chunk (same ChunkCompressedSize = same chunk)
    struct ChunkInfo {
        qint64 nChunkCompressedSize;
        qint64 nChunkFileOffset;  // Absolute file offset of zlb chunk
        QList<qint32> listEntryIndices;
    };

    QList<ChunkInfo> listChunks;
    qint64 nCurrentChunkOffset = nDataStreamOffset;

    for (qint32 i = 0; i < nNumDataEntries; i++) {
        qint64 nCCS = listDataEntries.at(i).nChunkCompressedSize;
        bool bFound = false;

        for (qint32 j = 0; j < listChunks.count(); j++) {
            if (listChunks.at(j).nChunkCompressedSize == nCCS) {
                listChunks[j].listEntryIndices.append(i);
                bFound = true;
                break;
            }
        }

        if (!bFound) {
            ChunkInfo chunk;
            chunk.nChunkCompressedSize = nCCS;
            chunk.nChunkFileOffset = nCurrentChunkOffset;
            chunk.listEntryIndices.append(i);
            listChunks.append(chunk);
            // zlb chunk: 4 bytes magic + compressed data = ChunkCompressedSize + 4
            nCurrentChunkOffset += nCCS + 4;
        }
    }

    // Step 2: Build per-entry maps for chunk file offset and chunk compressed size
    QMap<qint32, qint64> mapEntryChunkFileOffset;      // data entry index -> abs file offset of chunk
    QMap<qint32, qint64> mapEntryChunkCompressedSize;  // data entry index -> chunk compressed size

    for (qint32 cIdx = 0; cIdx < listChunks.count(); cIdx++) {
        const ChunkInfo &chunk = listChunks.at(cIdx);

        for (qint32 j = 0; j < chunk.listEntryIndices.count(); j++) {
            qint32 nEntryIdx = chunk.listEntryIndices.at(j);
            mapEntryChunkFileOffset.insert(nEntryIdx, chunk.nChunkFileOffset);
            mapEntryChunkCompressedSize.insert(nEntryIdx, chunk.nChunkCompressedSize);
        }
    }

    // Step 3: Build ARCHIVERECORD list matching file entries to data entries
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
        record.nStreamOffset = mapEntryChunkFileOffset.value(nLocIdx, 0);        // Abs offset of zlb chunk
        record.nStreamSize = mapEntryChunkCompressedSize.value(nLocIdx, 0) + 4;  // Chunk size including 4-byte zlb magic
        record.mapProperties.insert(FPART_PROP_ORIGINALNAME, sFileName);
        record.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, dataEntry.nOriginalSize);
        record.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, dataEntry.nChunkCompressedSize);  // Used as chunk ID
        record.mapProperties.insert(FPART_PROP_STREAMOFFSET, dataEntry.nChunkSubOffset);         // Decompressed offset within chunk
        record.mapProperties.insert(FPART_PROP_STREAMSIZE, dataEntry.nOriginalSize);
        record.mapProperties.insert(FPART_PROP_ISFOLDER, false);

        // Store SHA-256 hash
        record.mapProperties.insert(FPART_PROP_RESULTCRC, QString::fromLatin1(dataEntry.baSHA256.toHex()));

        pContext->listAllRecords.append(record);
    }

    return !pContext->listAllRecords.isEmpty();
}

QByteArray XInnoSetup::_decompressDataChunk(qint64 nChunkOffset, qint64 nChunkCompressedSize, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    qint64 nFileSize = getSize();

    // Data chunk format: "zlb\x1a" magic (4 bytes) + compressed data
    // v6.4.0.1+: LZMA1 (5-byte header: 1 props + 4 dict_size + raw stream)
    // v6.0.0: LZMA2 (1-byte dict property + raw stream)

    if (nChunkOffset + 4 > nFileSize) {
        return QByteArray();
    }

    QByteArray baMagic = read_array(nChunkOffset, 4);

    if (baMagic.size() != 4) {
        return QByteArray();
    }

    // Verify zlb magic
    if ((baMagic.at(0) != 'z') || (baMagic.at(1) != 'l') || (baMagic.at(2) != 'b') || ((quint8)baMagic.at(3) != 0x1A)) {
        return QByteArray();
    }

    // The caller passes nChunkCompressedSize which is the total data AFTER the zlb magic
    // (In _parseRealInnoSetup, nStreamSize = ChunkCompressedSize + 4, but here we
    //  need the size AFTER the 4-byte magic, so subtract 4 if it was included)
    qint64 nDataAfterMagic = nChunkCompressedSize;

    if (nDataAfterMagic > 4) {
        // Heuristic: if this looks like ChunkCompressedSize+4 was passed, adjust
        // The raw data size field from data entries is ChunkCompressedSize
        // The caller passes nStreamSize = ChunkCompressedSize + 4
        // We need ChunkCompressedSize (after zlb magic)
        nDataAfterMagic -= 4;
    }

    qint64 nAfterMagicOffset = nChunkOffset + 4;

    if (nAfterMagicOffset + nDataAfterMagic > nFileSize) {
        nDataAfterMagic = nFileSize - nAfterMagicOffset;
    }

    if (nDataAfterMagic <= 5) {
        return QByteArray();
    }

    // Read the first 5 bytes to determine compression method
    QByteArray baHeader = read_array(nAfterMagicOffset, 5);

    if (baHeader.size() != 5) {
        return QByteArray();
    }

    // Check if this is LZMA1: 5-byte header where dict_size is a reasonable value
    quint32 nDictSize = qFromLittleEndian<quint32>((const uchar *)(baHeader.constData() + 1));
    bool bIsLzma1 = (nDictSize > 0) && (nDictSize <= 0x10000000);  // dict <= 256MB

    QBuffer bufOutput;
    bufOutput.open(QIODevice::WriteOnly);

    XBinary::DATAPROCESS_STATE decompressState = {};
    decompressState.pDeviceInput = getDevice();
    decompressState.pDeviceOutput = &bufOutput;
    decompressState.nProcessedOffset = 0;
    decompressState.nProcessedLimit = -1;

    bool bOk = false;

    if (bIsLzma1) {
        // LZMA1: 5-byte property header + compressed data
        QByteArray baLzmaProps = baHeader;
        qint64 nDataOffset = nAfterMagicOffset + 5;
        qint64 nDataSize = nDataAfterMagic - 5;

        decompressState.nInputOffset = nDataOffset;
        decompressState.nInputLimit = nDataSize;

        bOk = XLZMADecoder::decompress(&decompressState, baLzmaProps, nullptr);
    } else {
        // LZMA2: 1-byte dict property + compressed data
        QByteArray baLzma2Prop = baHeader.left(1);
        qint64 nDataOffset = nAfterMagicOffset + 1;
        qint64 nDataSize = nDataAfterMagic - 1;

        decompressState.nInputOffset = nDataOffset;
        decompressState.nInputLimit = nDataSize;

        bOk = XLZMADecoder::decompressLZMA2(&decompressState, baLzma2Prop, nullptr);
    }

    bufOutput.close();

    if (!bOk) {
        return QByteArray();
    }

    return bufOutput.data();
}
