/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinnosetup.h"

#include <QBuffer>
#include "../XArchive/xdecompress.h"

XBinary::XCONVERT _TABLE_XINNOSETUP_STRUCTID[] = {
    {XInnoSetup::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XInnoSetup::STRUCTID_HEADER, "HEADER", QString("Header")},
};

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

// NOTE: Native InnoSetup parsing is NOT fully implemented.
//
// The InnoSetup format is extremely complex with:
// - Version-specific structure layouts (dozens of versions from 1.x to 6.x)
// - Multiple header sections (setup, files, dirs, components, tasks, registry, etc.)
// - Compressed and uncompressed metadata blocks
// - Solid compression with data slices and chunk mapping
// - Complex file-to-chunk mapping with multiple compression methods
//
// Full implementation requires ~4000+ lines of version-specific parsing code
// (see innoextract reference implementation in Formats/inbox/innoextract/).
//
// For production use, please use the external innoextract tool:
// https://constexpr.org/innoextract/
//
// This function returns false to indicate that native extraction is not available.

bool XInnoSetup::initUnpack(XBinary::UNPACK_STATE *pState, const QMap<XBinary::UNPACK_PROP, QVariant> &mapProperties, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(mapProperties)
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

    // Create empty context
    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->bParsed = false;
    pContext->nCurrentIndex = 0;
    pContext->nDataOffset = 0;
    pContext->nHeaderOffset = 0;

    pState->pContext = pContext;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    // Return false - parsing not implemented
    return false;
}

XBinary::ARCHIVERECORD XInnoSetup::infoCurrent(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XBinary::ARCHIVERECORD result = {};

    if (!pState || !pState->pContext) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if (pState->nCurrentIndex < 0 || pState->nCurrentIndex >= pContext->listFiles.size()) {
        return result;
    }

    const FILE_ENTRY &entry = pContext->listFiles.at(pState->nCurrentIndex);

    // Fill in archive record
    result.mapProperties.insert(XBinary::FPART_PROP_ORIGINALNAME, entry.sDestination);
    result.mapProperties.insert(XBinary::FPART_PROP_COMPRESSEDSIZE, entry.nCompressedSize);
    result.mapProperties.insert(XBinary::FPART_PROP_UNCOMPRESSEDSIZE, entry.nUncompressedSize);
    result.mapProperties.insert(XBinary::FPART_PROP_CRC_VALUE, entry.nCRC32);
    result.mapProperties.insert(XBinary::FPART_PROP_ISFOLDER, false);

    return result;
}

bool XInnoSetup::unpackCurrent(XBinary::UNPACK_STATE *pState, QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext || !pDevice) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if (pState->nCurrentIndex < 0 || pState->nCurrentIndex >= pContext->listFiles.size()) {
        return false;
    }

    const FILE_ENTRY &entry = pContext->listFiles.at(pState->nCurrentIndex);

    // Read compressed data from file
    QByteArray baCompressed = read_array_process(entry.nFileOffset, entry.nCompressedSize, pPdStruct);
    if (baCompressed.size() != entry.nCompressedSize) {
        return false;
    }

    // Decompress data
    QByteArray baUncompressed = _decompressData(baCompressed, entry.nCompressionMethod, entry.nUncompressedSize);
    if (baUncompressed.isEmpty() && entry.nUncompressedSize > 0) {
        return false;
    }

    // Write to device
    qint64 nWritten = pDevice->write(baUncompressed);
    return (nWritten == baUncompressed.size());
}

bool XInnoSetup::moveToNext(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if (pState->nCurrentIndex >= pContext->listFiles.size() - 1) {
        return false;  // No more records
    }

    pState->nCurrentIndex++;
    return true;
}

bool XInnoSetup::finishUnpack(XBinary::UNPACK_STATE *pState, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    // Clean up context
    pContext->listFiles.clear();

    delete pContext;
    pState->pContext = nullptr;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}

bool XInnoSetup::_parseInnoSetupStructure(UNPACK_CONTEXT *pContext, XBinary::PDSTRUCT *pPdStruct)
{
    // Simplified InnoSetup 6.x parser
    // This handles the basic structure of InnoSetup 6.0-6.2 installers

    // Find setup data block
    qint64 nSetupOffset = 0;
    qint64 nSetupSize = 0;

    if (!_findSetupData(&nSetupOffset, &nSetupSize, pPdStruct)) {
        return false;
    }

    pContext->nHeaderOffset = nSetupOffset;

    // Skip signature and version string
    qint64 nOffset = nSetupOffset;

    // Find the end of signature line (null terminated)
    while (nOffset < getSize() && read_uint8(nOffset) != 0) {
        nOffset++;
    }
    nOffset++;  // Skip null terminator

    // Align to 4-byte boundary
    if (nOffset % 4 != 0) {
        nOffset += (4 - (nOffset % 4));
    }

    // Read version (InnoSetup 6.x format: 4 bytes version number)
    if (nOffset + 4 > getSize()) {
        return false;
    }
    quint32 nVersionRaw = read_uint32(nOffset, true);  // Big endian
    nOffset += 4;

    quint8 nMajor = (nVersionRaw >> 24) & 0xFF;
    quint8 nMinor = (nVersionRaw >> 16) & 0xFF;

    // Only support version 6.x
    if (nMajor != 6 && nMajor != 5) {
        return false;
    }

    // Read compression flag (1 byte)
    quint8 nCompressFlag = read_uint8(nOffset++);
    bool bIsCompressed = (nCompressFlag != 0);

    // Read CRC32 (4 bytes)
    quint32 nHeaderCRC = read_uint32(nOffset);
    nOffset += 4;

    // Read compressed size (4 bytes)
    quint32 nCompressedSize = read_uint32(nOffset);
    nOffset += 4;

    // Read uncompressed size (4 bytes)
    quint32 nUncompressedSize = read_uint32(nOffset);
    nOffset += 4;

    // Read compressed header data
    if (nOffset + nCompressedSize > getSize()) {
        return false;
    }

    QByteArray baHeaderData;

    if (bIsCompressed) {
        // Read compressed data
        QByteArray baCompressed = read_array_process(nOffset, nCompressedSize, pPdStruct);
        nOffset += nCompressedSize;

        // Decompress using ZLIB (most common for InnoSetup 6.x)
        baHeaderData = _decompressData(baCompressed, 1, nUncompressedSize);

        if (baHeaderData.isEmpty() || baHeaderData.size() != (qint64)nUncompressedSize) {
            return false;
        }
    } else {
        // Read uncompressed data
        baHeaderData = read_array_process(nOffset, nCompressedSize, pPdStruct);
        nOffset += nCompressedSize;
    }

    // NOTE: The decompressed header data contains multiple sections in a complex binary format
    // Each section has: magic, version, count, and entries
    // Full parsing requires implementing the complete innoextract logic (~4000+ lines)

    // For demonstration, we show that decompression works and the structure can be accessed
    // A production implementation would need to:
    // 1. Parse multiple header sections (setup, files, dirs, components, tasks, etc.)
    // 2. Handle version-specific structure layouts
    // 3. Parse compressed and uncompressed data location entries
    // 4. Map files to data slices (handling solid compression)
    // 5. Parse all file attributes, flags, and metadata

    // Since this is a simplified implementation for InnoSetup 6.x only,
    // and the actual format is extremely complex with many variations,
    // we return false to indicate that full parsing is not implemented.
    //
    // Users should use the external innoextract tool for production extraction,
    // or implement the complete parsing logic following the innoextract reference.

    Q_UNUSED(baHeaderData)
    Q_UNUSED(nOffset)

    pContext->nDataOffset = nOffset;
    pContext->bParsed = false;

    // Uncomment this for debugging to see header data size:
    // qDebug() << "Header decompressed successfully:" << baHeaderData.size() << "bytes";

    return false;  // Parsing not fully implemented - use innoextract tool
}

bool XInnoSetup::_findSetupData(qint64 *pnOffset, qint64 *pnSize, XBinary::PDSTRUCT *pPdStruct)
{
    // Find the "Inno Setup Setup Data" or "Inno Setup: Setup Data" signature
    INTERNAL_INFO info = _analyse(pPdStruct);

    if (!info.bIsValid) {
        return false;
    }

    *pnOffset = info.nSignatureOffset;

    // The actual structured data follows the signature
    // Size calculation requires parsing the header blocks
    *pnSize = getSize() - info.nSignatureOffset;

    return true;
}

QByteArray XInnoSetup::_decompressData(const QByteArray &baCompressed, qint32 nMethod, qint64 nUncompressedSize)
{
    // InnoSetup compression methods:
    // 0 = Stored (no compression)
    // 1 = ZLIB
    // 2 = BZ2
    // 3 = LZMA
    // 4 = LZMA2

    if (nMethod == 0) {
        // Stored - no decompression needed
        return baCompressed;
    }

    // Map InnoSetup compression method to XBinary compression method
    XBinary::HANDLE_METHOD xMethod = XBinary::HANDLE_METHOD_UNKNOWN;

    switch (nMethod) {
        case 1: xMethod = XBinary::HANDLE_METHOD_ZLIB; break;
        case 2: xMethod = XBinary::HANDLE_METHOD_BZIP2; break;
        case 3: xMethod = XBinary::HANDLE_METHOD_LZMA; break;
        case 4: xMethod = XBinary::HANDLE_METHOD_LZMA2; break;
        default: return QByteArray();
    }

    // Create temporary buffer for compressed data
    QBuffer bufferInput;
    bufferInput.setData(baCompressed);
    if (!bufferInput.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }

    // Decompress using XDecompress
    XDecompress decompress;
    QByteArray baResult = decompress.decomressToByteArray(&bufferInput, 0, baCompressed.size(), xMethod, nullptr);

    bufferInput.close();

    // Verify size if specified
    if (nUncompressedSize > 0 && baResult.size() != nUncompressedSize) {
        // Size mismatch - may indicate error, but some formats may not match exactly
        // For now, return what we got
    }

    return baResult;
}
