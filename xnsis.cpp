/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xnsis.h"

#include <QByteArray>
#include <QBuffer>
#include "../XArchive/xdecompress.h"
#include "../XArchive/Algos/xlzmadecoder.h"

XBinary::XCONVERT _TABLE_XNSIS_STRUCTID[] = {
    {XNSIS::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XNSIS::STRUCTID_HEADER, "HEADER", QString("Header")},
    {XNSIS::STRUCTID_FILEENTRY, "FILEENTRY", QString("File Entry")},
};

XNSIS::XNSIS(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XNSIS::~XNSIS()
{
}

QString XNSIS::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XNSIS_STRUCTID, sizeof(_TABLE_XNSIS_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XNSIS::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

XNSIS::INTERNAL_INFO XNSIS::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _analyse(pPdStruct);
}

XNSIS::INTERNAL_INFO XNSIS::_analyse(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    qint64 nFileSize = getSize();

    if (nFileSize < 0) {
        nFileSize = 0;
    }

    // Search for NullsoftInst first as it's the most reliable marker for the actual NSIS data
    const char *apszSignatures[] = {"NullsoftInst", "Nullsoft.NSIS", ";!@Install@!UTF-8!", ";!@Install@!UTF-16LE", ";!@Install@!"};
    const qint32 nSignatureCount = sizeof(apszSignatures) / sizeof(const char *);

    for (qint32 i = 0; (i < nSignatureCount) && (!result.bIsValid); i++) {
        QString sSignatureCandidate = QString::fromLatin1(apszSignatures[i]);
        qint64 nOffset = find_ansiString(0, nFileSize, sSignatureCandidate, pPdStruct);

        if (nOffset != -1) {
            result.bIsValid = true;
            result.nSignatureOffset = nOffset;
            result.sSignature = sSignatureCandidate;

            const qint64 nWindowSize = 0x200;
            qint64 nRemainingSize = nFileSize - nOffset;
            if (nRemainingSize < 0) {
                nRemainingSize = 0;
            }

            qint64 nBytesToRead = qMin(nWindowSize, nRemainingSize);

            if (nBytesToRead > 0) {
                QByteArray baWindow = read_array_process(nOffset, nBytesToRead, pPdStruct);

                if (!baWindow.isEmpty()) {
                    QString sWindow = QString::fromLatin1(baWindow.constData(), baWindow.size());

                    if ((sWindow.contains("UTF-8")) || (sWindow.contains("UTF-16"))) {
                        result.bIsUnicode = true;
                    }

                    qint32 nWindowLength = sWindow.length();
                    for (qint32 j = 0; (j < nWindowLength) && result.sVersion.isEmpty(); j++) {
                        QChar cCurrent = sWindow.at(j);
                        if ((cCurrent == QChar('v')) || (cCurrent == QChar('V'))) {
                            qint32 nPos = j + 1;
                            while ((nPos < nWindowLength) && sWindow.at(nPos).isSpace()) {
                                nPos++;
                            }
                            qint32 nVersionStart = nPos;
                            while ((nPos < nWindowLength) && (sWindow.at(nPos).isDigit() || (sWindow.at(nPos) == QChar('.')) || (sWindow.at(nPos) == QChar('_')))) {
                                nPos++;
                            }
                            if (nPos > nVersionStart) {
                                result.sVersion = sWindow.mid(nVersionStart, nPos - nVersionStart).trimmed();
                            }
                        }
                    }

                    if (result.sVersion.isEmpty()) {
                        qint32 nWindowIndex = 0;
                        while ((nWindowIndex < nWindowLength) && result.sVersion.isEmpty()) {
                            QChar cSymbol = sWindow.at(nWindowIndex);
                            if (cSymbol.isDigit()) {
                                qint32 nStartIndex = nWindowIndex;
                                qint32 nEndIndex = nWindowIndex;
                                while ((nEndIndex < nWindowLength) && (sWindow.at(nEndIndex).isDigit() || (sWindow.at(nEndIndex) == QChar('.')))) {
                                    nEndIndex++;
                                }
                                if (nEndIndex > nStartIndex) {
                                    QString sCandidate = sWindow.mid(nStartIndex, nEndIndex - nStartIndex).trimmed();
                                    if (sCandidate.count('.') >= 1) {
                                        result.sVersion = sCandidate;
                                    }
                                }
                                nWindowIndex = nEndIndex;
                            } else {
                                nWindowIndex++;
                            }
                        }
                    }
                }
            }
        }
    }

    if ((!result.bIsValid) && (nFileSize > 16)) {
        qint64 nOverlayOffset = getOverlayOffset();

        if ((nOverlayOffset != -1) && (nOverlayOffset < nFileSize)) {
            qint64 nOverlaySize = nFileSize - nOverlayOffset;
            qint64 nBytesToRead = qMin((qint64)0x40, nOverlaySize);

            if (nBytesToRead > 0) {
                QByteArray baOverlay = read_array_process(nOverlayOffset, nBytesToRead, pPdStruct);

                if (baOverlay.size() >= 16) {
                    const char *pOverlayData = baOverlay.constData();

                    if (((quint8)pOverlayData[8] == 0xDE) && ((quint8)pOverlayData[9] == 0xAD) && ((quint8)pOverlayData[10] == 0xBE) &&
                        ((quint8)pOverlayData[11] == 0xEF)) {
                        QByteArray baSignature = baOverlay.mid(12);
                        qint32 nLocalOffset = baSignature.indexOf("NullsoftInst");

                        if (nLocalOffset != -1) {
                            result.bIsValid = true;
                            result.nSignatureOffset = nOverlayOffset + 12 + nLocalOffset;
                            result.sSignature = QString::fromLatin1("NullsoftInst");
                        }
                    }
                }
            }
        }
    }

    return result;
}

XNSIS::NSIS_HEADER XNSIS::_readHeader(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    NSIS_HEADER result = {};

    result.nFlags = read_uint32(nOffset);
    result.nHeaderSize = read_uint32(nOffset + 0x14);
    result.nArchiveSize = read_uint32(nOffset + 0x18);

    return result;
}

XBinary::HANDLE_METHOD XNSIS::_detectCompression(const char *pData)
{
    if (!pData) {
        return HANDLE_METHOD_UNKNOWN;
    }

    // Check for BZip2 (starts with '1')
    if (pData[0] == '1') {
        return HANDLE_METHOD_BZIP2;
    }

    // Check for LZMA (has specific size field)
    quint32 nValue = *((const quint32 *)pData);
    quint32 nMasked = nValue & ~0x80000000;
    if (nMasked == 0x5d) {
        return HANDLE_METHOD_LZMA;
    }

    // Default to Deflate/zlib
    return HANDLE_METHOD_DEFLATE;
}

qint32 XNSIS::_countFiles(qint64 nArchiveOffset, qint64 nArchiveSize, bool *pbIsSolid, PDSTRUCT *pPdStruct)
{
    qint32 nCount = 0;
    qint64 nPos = 0;
    bool bIsSolid = false;
    qint32 nCompressionCounts[4] = {0};  // [0]=unknown, [1]=bzip2, [2]=lzma, [3]=deflate
    bool bTruncated = false;

    // Guess if solid by attempting to parse as non-solid
    while ((nPos < nArchiveSize - 4) && isPdStructNotCanceled(pPdStruct)) {
        quint32 nNextSize = read_uint32(nArchiveOffset + nPos, false);

        // First entry detection for compression method
        if (nCount == 0) {
            QByteArray baFirstData = read_array(nArchiveOffset + nPos + 4, qMin((qint64)4, nArchiveSize - nPos - 4));
            if (!baFirstData.isEmpty()) {
                // Store first compression method
            }
        }

        nPos += 4;

        // Check for CRC field at end (archive size = 4 bytes left)
        if (nPos >= nArchiveSize - 4) {
            break;
        }

        // Check if compressed (high bit set)
        if (nNextSize & 0x80000000) {
            nNextSize &= ~0x80000000;
            // Read compression method
            if (nPos + 4 <= nArchiveSize) {
                QByteArray baCompMethod = read_array(nArchiveOffset + nPos, 4);
                if (!baCompMethod.isEmpty()) {
                    HANDLE_METHOD cm = _detectCompression(baCompMethod.constData());
                    if (cm == HANDLE_METHOD_BZIP2) nCompressionCounts[1]++;
                    else if (cm == HANDLE_METHOD_LZMA) nCompressionCounts[2]++;
                    else if (cm == HANDLE_METHOD_DEFLATE) nCompressionCounts[3]++;
                }
                nPos += 4;
                nNextSize -= 4;
            }
        }

        // Check if this block goes beyond archive
        if (nPos + nNextSize > nArchiveSize) {
            bIsSolid = true;
            break;
        }

        nPos += nNextSize;
        nCount++;

        // Safety limit
        if (nCount > 100000) {
            break;
        }
    }

    // If truncated and count >= 2, assume non-solid
    if (bTruncated && nCount >= 2) {
        bIsSolid = false;
    }

    if (pbIsSolid) {
        *pbIsSolid = bIsSolid;
    }

    return nCount;
}

bool XNSIS::_parseArchive(UNPACK_CONTEXT *pContext, qint64 nArchiveOffset, qint64 nArchiveSize, PDSTRUCT *pPdStruct)
{
    if (!pContext) {
        return false;
    }

    pContext->nDataOffset = nArchiveOffset;
    pContext->nDataSize = nArchiveSize;
    pContext->nCurrentOffset = nArchiveOffset;
    pContext->nCurrentFileIndex = 0;
    pContext->nDecompressedOffset = 0;
    pContext->nDecompressedSize = 0;

    // Initialize compression counts
    for (qint32 i = 0; i < 4; i++) {
        pContext->nCompressionCounts[i] = 0;
    }

    // Count files and detect if solid
    bool bIsSolid = false;
    qint32 nFileCount = _countFiles(nArchiveOffset, nArchiveSize, &bIsSolid, pPdStruct);

    pContext->bIsSolid = bIsSolid;
    pContext->nTotalFiles = nFileCount;

    if (pContext->bIsSolid) {
        // Solid compression - read all compressed data at once
        if (nArchiveSize > 0 && nArchiveSize < 1024 * 1024 * 1024) {  // Limit to 1GB
            pContext->baCompressedData = read_array_process(nArchiveOffset, nArchiveSize, pPdStruct);
        }

        // Detect compression method from actual data for solid archives
        if (!pContext->baCompressedData.isEmpty()) {
            pContext->compressMethod = _detectCompression(pContext->baCompressedData.constData());
        } else {
            pContext->compressMethod = HANDLE_METHOD_DEFLATE;  // Default fallback
        }

        // Parse files from solid archive
        if (!_parseSolidFiles(pContext, pPdStruct)) {
            // If parsing fails, treat as single file
            pContext->nTotalFiles = 1;
        }
    } else {
        // For non-solid, determine from file entries
        pContext->compressMethod = _determineCompressionMethod(pContext);
        // Non-solid compression - parse individual file entries
        if (!_parseFileEntries(pContext, pPdStruct)) {
            return false;
        }
    }

    return true;
}

bool XNSIS::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(mapProperties)

    if (!pState) {
        return false;
    }

    // Initialize state
    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;

    // Validate archive
    INTERNAL_INFO info = getInternalInfo(pPdStruct);
    if (!info.bIsValid) {
        return false;
    }

    // Create context
    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->nHeaderOffset = 0;
    pContext->nDataOffset = 0;
    pContext->nDataSize = 0;
    pContext->bIsSolid = false;
    pContext->nCurrentFileIndex = 0;
    pContext->nTotalFiles = 0;
    pContext->nCurrentOffset = 0;
    pContext->compressMethod = HANDLE_METHOD_UNKNOWN;
    pContext->nDecompressedOffset = 0;
    pContext->nDecompressedSize = 0;

    for (qint32 i = 0; i < 4; i++) {
        pContext->nCompressionCounts[i] = 0;
    }

    // Find the NSIS header by looking for the marker 0xefbeadde
    // The header structure is: [4 bytes flags] [ef be ad de] [signature string] ...
    qint64 nSignatureOffset = info.nSignatureOffset;

    // The marker (0xdeadbeef in LE) should be 4 bytes before the signature
    qint64 nSearchStart = qMax((qint64)0, nSignatureOffset - 16);
    qint64 nSearchEnd = nSignatureOffset;

    qint64 nActualHeaderOffset = -1;
    for (qint64 i = nSearchStart; i < nSearchEnd; i++) {
        // Look for the magic marker 0xdeadbeef (little-endian: ef be ad de)
        quint32 nMarker = read_uint32(i, false);  // Read as little-endian
        if (nMarker == 0xdeadbeef) {
            // Found the marker at offset i
            // Header starts 4 bytes before the marker
            nActualHeaderOffset = i - 4;

            NSIS_HEADER header = _readHeader(nActualHeaderOffset, pPdStruct);

            // Validate header - archive size should be reasonable
            if (header.nArchiveSize > 0x1c && header.nArchiveSize < (quint32)pState->nTotalSize) {
                qint64 nArchiveOffset = nActualHeaderOffset + 0x1c;

                // Check if archive data is within file bounds
                // Allow for slightly truncated files (common with NSIS installers)
                qint64 nAvailableSize = pState->nTotalSize - nArchiveOffset;
                if (nAvailableSize > 0 && nArchiveOffset < pState->nTotalSize) {
                    qint64 nArchiveDataOffset = nArchiveOffset;
                    // Use available size if file is truncated
                    qint64 nArchiveDataSize = qMin((qint64)(header.nArchiveSize - 0x1c), nAvailableSize);

                    pContext->nHeaderOffset = nActualHeaderOffset;

                    if (_parseArchive(pContext, nArchiveDataOffset, nArchiveDataSize, pPdStruct)) {
                        pState->nNumberOfRecords = pContext->nTotalFiles;
                        break;
                    }
                }
            }

            break;  // Found the marker, stop searching even if validation fails
        }
    }

    if (nActualHeaderOffset == -1) {
        // Header not found, fall back to simple extraction
        pContext->nDataOffset = info.nSignatureOffset;
        pContext->nDataSize = pState->nTotalSize - info.nSignatureOffset;
        pContext->bIsSolid = true;
        pContext->nTotalFiles = 0;
        pState->nNumberOfRecords = 0;
    }

    pState->pContext = pContext;

    return true;
}

XBinary::ARCHIVERECORD XNSIS::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};

    if (!pState || !pState->pContext) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    // Check if we're within valid range
    if (pState->nCurrentIndex >= pState->nNumberOfRecords) {
        return result;
    }

    qint32 nCurrentIndex = (qint32)pState->nCurrentIndex;

    if (pContext->bIsSolid) {
        // Solid compression - use parsed file entries if available
        if (!pContext->listEntries.isEmpty() && nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size()) {
            const FILE_ENTRY &entry = pContext->listEntries.at(nCurrentIndex);

            result.nStreamOffset = pContext->nDataOffset;
            result.nStreamSize = pContext->nDataSize;

            result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = entry.nUncompressedSize;
            result.mapProperties[FPART_PROP_ORIGINALNAME] = entry.sFileName;
        } else {
            // Fallback for unparsed solid archives
            result.nStreamOffset = pContext->nDataOffset;
            result.nStreamSize = pContext->nDataSize;

            result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = 0;  // Unknown until decompression
        }
    } else {
        // Non-solid - use file entry list
        if (nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size()) {
            const FILE_ENTRY &entry = pContext->listEntries.at(nCurrentIndex);

            result.nStreamOffset = entry.nOffset;
            result.nStreamSize = entry.nCompressedSize + 4;  // Include size field

            if (entry.bIsCompressed) {
                result.nStreamSize += 4;  // Include compression method field
            }

            result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = entry.nUncompressedSize;
            result.mapProperties[FPART_PROP_HANDLEMETHOD1] = entry.compressMethod;
        }
    }

    // Set file properties
    QString sFileName;
    if (pContext->bIsSolid && !pContext->listEntries.isEmpty() && nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size()) {
        sFileName = pContext->listEntries.at(nCurrentIndex).sFileName;
    } else if (!pContext->bIsSolid && nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size() &&
               !pContext->listEntries.at(nCurrentIndex).sFileName.isEmpty()) {
        sFileName = pContext->listEntries.at(nCurrentIndex).sFileName;
    } else {
        sFileName = QString("content.%1").arg(pState->nCurrentIndex, 3, 10, QChar('0'));
    }

    result.mapProperties[FPART_PROP_ORIGINALNAME] = sFileName;
    result.mapProperties[FPART_PROP_COMPRESSEDSIZE] = result.nStreamSize;

    if (!pContext->bIsSolid) {
        qint32 nCurrentIndex = (qint32)pState->nCurrentIndex;
        if (nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size()) {
            result.mapProperties[FPART_PROP_HANDLEMETHOD1] = pContext->listEntries.at(nCurrentIndex).compressMethod;
        }
    } else {
        result.mapProperties[FPART_PROP_HANDLEMETHOD1] = pContext->compressMethod;
    }

    return result;
}

bool XNSIS::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    // Check if we're within valid range
    if (pState->nCurrentIndex >= pState->nNumberOfRecords) {
        return false;
    }

    qint32 nCurrentIndex = (qint32)pState->nCurrentIndex;

    if (pContext->bIsSolid) {
        // Solid compression - extract file from parsed entries

        // Ensure decompressed data is available
        if (pContext->baDecompressedData.isEmpty()) {
            if (!_decompressSolidBlock(pContext, pPdStruct)) {
                return false;
            }
        }

        if (pContext->baDecompressedData.isEmpty()) {
            return false;
        }

        // Use parsed file entries if available
        if (!pContext->listEntries.isEmpty() && nCurrentIndex >= 0 && nCurrentIndex < pContext->listEntries.size()) {
            const FILE_ENTRY &entry = pContext->listEntries.at(nCurrentIndex);

            // Extract file from decompressed data using entry info
            if (entry.nDataOffset + entry.nUncompressedSize <= pContext->baDecompressedData.size()) {
                QByteArray baFileData = pContext->baDecompressedData.mid(entry.nDataOffset, entry.nUncompressedSize);

                if (!baFileData.isEmpty()) {
                    qint64 nWritten = pDevice->write(baFileData);
                    return (nWritten == baFileData.size());
                }
            }

            return false;
        } else {
            // Fallback: sequential extraction using size fields
            qint32 nFileSize = _readFileSizeFromSolid(pContext, pPdStruct);

            if (nFileSize == 0) {
                return true;  // Empty file
            }

            if (nFileSize < 0 || nFileSize > 1024 * 1024 * 1024) {
                // Invalid size
                return false;
            }

            // Check if we have enough data
            if (pContext->nDecompressedOffset + nFileSize > pContext->nDecompressedSize) {
                // Not enough data in decompressed buffer
                qint64 nAvailable = pContext->nDecompressedSize - pContext->nDecompressedOffset;
                if (nAvailable <= 0) {
                    return false;
                }
                nFileSize = (qint32)nAvailable;
            }

            // Extract file data from decompressed buffer
            QByteArray baFileData = pContext->baDecompressedData.mid(pContext->nDecompressedOffset, nFileSize);

            if (!baFileData.isEmpty()) {
                qint64 nWritten = pDevice->write(baFileData);

                // Update offset for next file
                pContext->nDecompressedOffset += nFileSize;

                return (nWritten == baFileData.size());
            }

            return false;
        }
    } else {
        // Non-solid compression - each file is independently compressed

        if (nCurrentIndex < 0 || nCurrentIndex >= pContext->listEntries.size()) {
            return false;
        }

        const FILE_ENTRY &entry = pContext->listEntries.at(nCurrentIndex);

        // Read size field
        qint64 nDataOffset = entry.nOffset + 4;
        qint32 nSize = entry.nCompressedSize;

        if (entry.bIsCompressed) {
            // Skip compression method field
            nDataOffset += 4;

            // Read compressed data
            QByteArray baCompressed = read_array_process(nDataOffset, nSize, pPdStruct);
            if (baCompressed.isEmpty() && nSize > 0) {
                return false;
            }

            // Decompress using NSIS-aware decompression
            QByteArray baDecompressed = _decompressBlock(baCompressed, entry.compressMethod, pPdStruct);

            if (baDecompressed.isEmpty() && baCompressed.size() > 0) {
                // Decompression failed, try writing raw data
                baDecompressed = baCompressed;
            }

            if (!baDecompressed.isEmpty()) {
                qint64 nWritten = pDevice->write(baDecompressed);
                return (nWritten == baDecompressed.size());
            }
        } else {
            // Uncompressed data
            if (nSize == 0) {
                return true;  // Empty file
            }

            QByteArray baData = read_array_process(nDataOffset, nSize, pPdStruct);
            if (!baData.isEmpty()) {
                qint64 nWritten = pDevice->write(baData);
                return (nWritten == baData.size());
            }
        }
    }

    return false;
}

bool XNSIS::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    // Move to next record
    pState->nCurrentIndex++;

    // Check if we've reached the end
    if (pState->nCurrentIndex >= pState->nNumberOfRecords) {
        return false;
    }

    // Update current offset for non-solid archives
    if (!pContext->bIsSolid) {
        // The current offset is managed by the file entry list
        // No need to manually track position
    }

    pContext->nCurrentFileIndex++;

    return true;
}

bool XNSIS::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

    // Clean up context
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        pContext->listEntries.clear();
        pContext->baCompressedData.clear();
        pContext->baDecompressedData.clear();
        delete pContext;
        pState->pContext = nullptr;
    }

    // Reset state
    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}

bool XNSIS::_parseFileEntries(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext) {
        return false;
    }

    pContext->listEntries.clear();

    qint64 nPos = 0;
    qint32 nFileIndex = 0;

    while ((nPos < pContext->nDataSize - 4) && isPdStructNotCanceled(pPdStruct)) {
        FILE_ENTRY entry = {};

        quint32 nSize = read_uint32(pContext->nDataOffset + nPos, false);

        entry.nOffset = pContext->nDataOffset + nPos;
        entry.nFileIndex = nFileIndex;
        nPos += 4;

        // Check if this is the CRC at the end
        if (pContext->nDataSize - nPos == 4) {
            // This is the CRC field, stop parsing
            break;
        }

        // Check if uncompressed (size without high bit) is 0
        quint32 nRawSize = nSize & ~0x80000000;
        if (nRawSize == 0) {
            // Empty file
            entry.bIsCompressed = false;
            entry.compressMethod = HANDLE_METHOD_STORE;
            entry.nCompressedSize = 0;
            entry.nUncompressedSize = 0;
            pContext->listEntries.append(entry);
            nFileIndex++;
            continue;
        }

        // Check compression flag (high bit)
        entry.bIsCompressed = (nSize & 0x80000000) != 0;
        nSize = nRawSize;

        if (entry.bIsCompressed) {
            // Read compression method
            if (nPos + 4 <= pContext->nDataSize) {
                QByteArray baCompMethod = read_array(pContext->nDataOffset + nPos, 4);
                if (!baCompMethod.isEmpty()) {
                    entry.compressMethod = _detectCompression(baCompMethod.constData());

                    // Track compression counts
                    if (entry.compressMethod == HANDLE_METHOD_BZIP2) pContext->nCompressionCounts[1]++;
                    else if (entry.compressMethod == HANDLE_METHOD_LZMA) pContext->nCompressionCounts[2]++;
                    else if (entry.compressMethod == HANDLE_METHOD_DEFLATE) pContext->nCompressionCounts[3]++;
                } else {
                    entry.compressMethod = HANDLE_METHOD_DEFLATE;
                }
                nPos += 4;
                if (nSize >= 4) {
                    nSize -= 4;
                } else {
                    break;  // Invalid data
                }
            } else {
                break;
            }
        } else {
            entry.compressMethod = HANDLE_METHOD_STORE;
        }

        entry.nCompressedSize = nSize;
        entry.nUncompressedSize = 0;  // Unknown until decompression

        pContext->listEntries.append(entry);

        nPos += nSize;
        nFileIndex++;

        // Check bounds
        if (nPos > pContext->nDataSize) {
            break;
        }

        // Safety limit
        if (nFileIndex > 100000) {
            break;
        }
    }

    return true;
}

XBinary::HANDLE_METHOD XNSIS::_determineCompressionMethod(UNPACK_CONTEXT *pContext)
{
    if (!pContext) {
        return HANDLE_METHOD_UNKNOWN;
    }

    // For solid archives, detect from first data block
    if (pContext->bIsSolid) {
        if (pContext->nDataSize >= 4) {
            QByteArray baHeader = read_array(pContext->nDataOffset, 4);
            if (!baHeader.isEmpty()) {
                return _detectCompression(baHeader.constData());
            }
        }
        return HANDLE_METHOD_DEFLATE;  // Default
    }

    // For non-solid archives, use most common compression method
    qint32 nMaxCount = 0;
    HANDLE_METHOD result = HANDLE_METHOD_DEFLATE;

    if (pContext->nCompressionCounts[1] > nMaxCount) {
        nMaxCount = pContext->nCompressionCounts[1];
        result = HANDLE_METHOD_BZIP2;
    }
    if (pContext->nCompressionCounts[2] > nMaxCount) {
        nMaxCount = pContext->nCompressionCounts[2];
        result = HANDLE_METHOD_LZMA;
    }
    if (pContext->nCompressionCounts[3] > nMaxCount) {
        nMaxCount = pContext->nCompressionCounts[3];
        result = HANDLE_METHOD_DEFLATE;
    }

    return result;
}

bool XNSIS::_decompressSolidBlock(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext || pContext->baCompressedData.isEmpty()) {
        return false;
    }

    // If already decompressed, return success
    if (!pContext->baDecompressedData.isEmpty()) {
        return true;
    }

    bool bSuccess = false;

    // Use NSIS-specific decompression methods based on detected compression
    if (pContext->compressMethod == HANDLE_METHOD_LZMA) {
        bSuccess = _decompressNSISLZMA(pContext, pPdStruct);
    } else if (pContext->compressMethod == HANDLE_METHOD_BZIP2) {
        bSuccess = _decompressNSISBZIP2(pContext, pPdStruct);
    } else if (pContext->compressMethod == HANDLE_METHOD_DEFLATE) {
        bSuccess = _decompressNSISZLIB(pContext, pPdStruct);
    } else {
        // Fallback to standard decompression
        QBuffer inputBuffer(&pContext->baCompressedData);
        inputBuffer.open(QIODevice::ReadOnly);

        XDecompress decompressor;

        pContext->baDecompressedData = decompressor.decomressToByteArray(&inputBuffer, 0, pContext->baCompressedData.size(), pContext->compressMethod, pPdStruct);

        inputBuffer.close();

        bSuccess = !pContext->baDecompressedData.isEmpty();
    }

    if (bSuccess && !pContext->baDecompressedData.isEmpty()) {
        pContext->nDecompressedSize = pContext->baDecompressedData.size();
        pContext->nDecompressedOffset = 0;
        return true;
    }

    return false;
}

bool XNSIS::_decompressNSISLZMA(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext || pContext->baCompressedData.isEmpty()) {
        return false;
    }

    // NSIS LZMA format: uses raw LZMA stream
    // Try standard LZMA decompression first
    QBuffer inputBuffer(&pContext->baCompressedData);
    inputBuffer.open(QIODevice::ReadOnly);

    XDecompress decompressor;
    pContext->baDecompressedData = decompressor.decomressToByteArray(&inputBuffer, 0, pContext->baCompressedData.size(), HANDLE_METHOD_LZMA, pPdStruct);

    inputBuffer.close();

    if (!pContext->baDecompressedData.isEmpty()) {
        return true;
    }

    // If standard LZMA failed, try custom NSIS LZMA format
    // NSIS sometimes uses raw LZMA with 5-byte properties header
    const quint8 *pCompData = (const quint8 *)pContext->baCompressedData.constData();
    qint64 nCompSize = pContext->baCompressedData.size();

    if (nCompSize < 5) {
        return false;
    }

    // Extract LZMA properties (5 bytes)
    QByteArray baProperties = pContext->baCompressedData.left(5);

    // Try decompression using XArchive's LZMA decoder with properties
    inputBuffer.setData(pContext->baCompressedData);
    inputBuffer.open(QIODevice::ReadOnly);
    inputBuffer.seek(5);  // Skip properties

    QBuffer outputBuffer;
    outputBuffer.open(QIODevice::WriteOnly);

    DATAPROCESS_STATE state = {};
    state.pDeviceInput = &inputBuffer;
    state.pDeviceOutput = &outputBuffer;
    state.nInputOffset = 5;  // Start after properties
    state.nInputLimit = nCompSize;
    state.nCountInput = 0;
    state.nCountOutput = 0;

    // Use XArchive's LZMA decoder with custom properties
    bool bResult = XLZMADecoder::decompress(&state, baProperties, pPdStruct);

    inputBuffer.close();
    outputBuffer.close();

    if (bResult) {
        pContext->baDecompressedData = outputBuffer.data();
        return true;
    }

    return false;
}

bool XNSIS::_decompressNSISBZIP2(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext || pContext->baCompressedData.isEmpty()) {
        return false;
    }

    // NSIS BZIP2 format: uses raw bzip2 stream without BZ header
    // Try standard BZIP2 decompression
    QBuffer inputBuffer(&pContext->baCompressedData);
    inputBuffer.open(QIODevice::ReadOnly);

    XDecompress decompressor;
    pContext->baDecompressedData = decompressor.decomressToByteArray(&inputBuffer, 0, pContext->baCompressedData.size(), HANDLE_METHOD_BZIP2, pPdStruct);

    inputBuffer.close();

    return !pContext->baDecompressedData.isEmpty();
}

bool XNSIS::_decompressNSISZLIB(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext || pContext->baCompressedData.isEmpty()) {
        return false;
    }

    // NSIS ZLIB format: uses deflate/zlib compression
    // Try standard DEFLATE decompression
    QBuffer inputBuffer(&pContext->baCompressedData);
    inputBuffer.open(QIODevice::ReadOnly);

    XDecompress decompressor;
    pContext->baDecompressedData = decompressor.decomressToByteArray(&inputBuffer, 0, pContext->baCompressedData.size(), HANDLE_METHOD_DEFLATE, pPdStruct);

    inputBuffer.close();

    return !pContext->baDecompressedData.isEmpty();
}

QByteArray XNSIS::_decompressBlock(const QByteArray &baCompressed, HANDLE_METHOD method, PDSTRUCT *pPdStruct)
{
    if (baCompressed.isEmpty()) {
        return QByteArray();
    }

    QBuffer inputBuffer;
    inputBuffer.setData(baCompressed);
    inputBuffer.open(QIODevice::ReadOnly);

    XDecompress decompressor;
    QByteArray baDecompressed = decompressor.decomressToByteArray(&inputBuffer, 0, baCompressed.size(), method, pPdStruct);

    inputBuffer.close();

    return baDecompressed;
}

bool XNSIS::_parseSolidFiles(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext) {
        return false;
    }

    // Decompress the solid block first
    if (!_decompressSolidBlock(pContext, pPdStruct)) {
        return false;
    }

    if (pContext->baDecompressedData.isEmpty()) {
        return false;
    }

    pContext->listEntries.clear();

    const quint8 *pData = (const quint8 *)pContext->baDecompressedData.constData();
    qint64 nDecompSize = pContext->baDecompressedData.size();
    qint64 nPos = 0;
    qint32 nFileIndex = 0;

    // Parse files from decompressed stream
    // Each file is prefaced with a 4-byte size (little-endian)
    while (nPos + 4 <= nDecompSize && isPdStructNotCanceled(pPdStruct)) {
        // Read file size
        quint32 nFileSize = pData[nPos] | (pData[nPos + 1] << 8) | (pData[nPos + 2] << 16) | (pData[nPos + 3] << 24);

        nPos += 4;

        // Check for end marker or invalid size
        if (nFileSize == 0 || nFileSize > (quint32)(nDecompSize - nPos)) {
            break;
        }

        // Check if this looks like the end of files (CRC or other marker)
        if (nFileSize == 0xffffffff || nFileSize > 100 * 1024 * 1024) {
            break;
        }

        // Create file entry
        FILE_ENTRY entry;
        entry.nOffset = 0;          // Not used for solid
        entry.nCompressedSize = 0;  // Already decompressed
        entry.nUncompressedSize = nFileSize;
        entry.bIsCompressed = false;  // Already decompressed
        entry.compressMethod = HANDLE_METHOD_UNKNOWN;
        entry.nFileIndex = nFileIndex;
        entry.sFileName = QString("file_%1.bin").arg(nFileIndex, 3, 10, QChar('0'));
        entry.nDataOffset = nPos;

        pContext->listEntries.append(entry);

        nPos += nFileSize;
        nFileIndex++;

        // Safety limit
        if (nFileIndex > 10000) {
            break;
        }
    }

    pContext->nTotalFiles = pContext->listEntries.size();

    return pContext->nTotalFiles > 0;
}

qint32 XNSIS::_readFileSizeFromSolid(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pContext || pContext->baDecompressedData.isEmpty()) {
        return 0;
    }

    qint64 nOffset = pContext->nDecompressedOffset;

    // Check if we have 4 bytes available for size
    if (nOffset + 4 > pContext->nDecompressedSize) {
        return 0;
    }

    // Read 4-byte size (little-endian)
    const quint8 *pData = (const quint8 *)pContext->baDecompressedData.constData();
    quint32 nSize = pData[nOffset] | (pData[nOffset + 1] << 8) | (pData[nOffset + 2] << 16) | (pData[nOffset + 3] << 24);

    // Update offset past the size field
    pContext->nDecompressedOffset += 4;

    return (qint32)nSize;
}
