/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XNSIS_H
#define XNSIS_H

#include <QString>

#include "xbinary.h"

class XNSIS : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
        STRUCTID_FILEENTRY,
    };

    struct INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sSignature;
        QString sVersion;
        bool bIsUnicode;
    };

    struct NSIS_HEADER {
        quint32 nFlags;
        quint32 nHeaderSize;
        quint32 nArchiveSize;
    };

    struct FILE_ENTRY {
        qint64 nOffset;                           // Offset in archive
        qint32 nCompressedSize;                   // Size of compressed data (or uncompressed if not compressed)
        qint32 nUncompressedSize;                 // Size after decompression (if known)
        bool bIsCompressed;                       // Whether this entry is compressed
        XBinary::COMPRESS_METHOD compressMethod;  // Compression method for this entry
        qint32 nFileIndex;                        // Sequential file index
        QString sFileName;                        // File name (if available)
        qint64 nDataOffset;                       // Offset in decompressed stream (for solid)
    };

    struct UNPACK_CONTEXT {
        qint64 nHeaderOffset;                     // Offset to NSIS header
        qint64 nDataOffset;                       // Offset to archive data (after header)
        qint64 nDataSize;                         // Size of archive data
        bool bIsSolid;                            // True if solid compression
        qint32 nCurrentFileIndex;                 // Current file being processed
        qint32 nTotalFiles;                       // Total number of files in archive
        qint64 nCurrentOffset;                    // Current read position
        XBinary::COMPRESS_METHOD compressMethod;  // Primary compression method
        QByteArray baCompressedData;              // Cached compressed data (for solid archives)
        QByteArray baDecompressedData;            // Cached decompressed data (for solid archives)
        qint64 nDecompressedOffset;               // Current offset in decompressed data
        qint64 nDecompressedSize;                 // Size of decompressed data
        QList<FILE_ENTRY> listEntries;            // List of file entries (non-solid)
        qint32 nCompressionCounts[4];             // Count of each compression type detected
    };

    explicit XNSIS(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XNSIS() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual QString structIDToString(quint32 nID) override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
    NSIS_HEADER _readHeader(qint64 nOffset, PDSTRUCT *pPdStruct);
    XBinary::COMPRESS_METHOD _detectCompression(const char *pData);
    bool _parseArchive(UNPACK_CONTEXT *pContext, qint64 nArchiveOffset, qint64 nArchiveSize, PDSTRUCT *pPdStruct);
    qint32 _countFiles(qint64 nArchiveOffset, qint64 nArchiveSize, bool *pbIsSolid, PDSTRUCT *pPdStruct);
    bool _parseFileEntries(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    XBinary::COMPRESS_METHOD _determineCompressionMethod(UNPACK_CONTEXT *pContext);
    bool _decompressSolidBlock(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    bool _decompressNSISLZMA(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    bool _decompressNSISBZIP2(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    bool _decompressNSISZLIB(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    QByteArray _decompressBlock(const QByteArray &baCompressed, COMPRESS_METHOD method, PDSTRUCT *pPdStruct);
    bool _parseSolidFiles(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    qint32 _readFileSizeFromSolid(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
};

#endif  // XNSIS_H
