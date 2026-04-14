/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINNOSETUP_H
#define XINNOSETUP_H

#include <QString>
#include <QBuffer>

#include "xbinary.h"

class XInnoSetup : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
    };
    struct INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sVersion;
    };

    // Real InnoSetup offset table parsed from rDlPtS magic
    struct OFFSET_TABLE {
        bool bIsValid;
        qint64 nTableOffset;  // Absolute offset of the rDlPtS magic
        quint32 nRevision;
        quint32 nExeOffset;
        quint32 nExeCompressedSize;
        quint32 nExeUncompressedSize;
        quint32 nExeChecksum;
        quint32 nMessageOffset;
        quint32 nHeaderOffset;  // Relative to signature
        quint32 nDataOffset;    // Relative to signature
    };

    // Data entry from Block Stream 2 (data locations)
    struct DATA_ENTRY {
        qint64 nChunkSubOffset;  // Offset within decompressed chunk (stored at entry+12)
        qint64 nOriginalSize;
        qint64 nChunkCompressedSize;  // Identifies which solid chunk this belongs to
        QByteArray baSHA256;          // 32-byte SHA-256 hash
        quint64 nFileTime;            // NTFS FileTime
        quint32 nFileVersionMS;
        quint32 nFileVersionLS;
        quint8 nFlags;  // Bit flags (0x80 = normal, 0x90 = BCJ x86)
    };

    // File entry from Block Stream 1 (file metadata)
    struct FILE_ENTRY {
        QString sDestName;      // Destination path (e.g., {app}\file.txt)
        qint32 nLocationEntry;  // Index into DATA_ENTRY array (-1 if none)
    };

    // Decompressed chunk cache for solid compression
    struct CHUNK_CACHE {
        qint64 nChunkCompressedSize;    // Key identifying which chunk
        QByteArray baDecompressedData;  // Full decompressed chunk content
    };

    struct UNPACK_CONTEXT {
        QList<ARCHIVERECORD> listAllRecords;
        bool bIsRealFormat;  // true = real InnoSetup, false = synthetic ISDF
        qint64 nSignatureOffset;
        qint64 nDataStreamOffset;  // Absolute offset of data overlay (zlb chunks)
        QList<DATA_ENTRY> listDataEntries;
        QList<FILE_ENTRY> listFileEntries;
        CHUNK_CACHE chunkCache;  // Cached decompressed chunk
    };

    explicit XInnoSetup(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInnoSetup() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual QString structIDToString(quint32 nID) override;
    virtual QString structIDToFtString(quint32 nID) override;
    virtual quint32 ftStringToStructID(const QString &sFtString) override;

    // Streaming unpacking API
    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
    QList<ARCHIVERECORD> _parseSyntheticFileEntries(qint64 nSignatureOffset, PDSTRUCT *pPdStruct);

    // Real InnoSetup format parsing
    OFFSET_TABLE _findOffsetTable(PDSTRUCT *pPdStruct);
    QByteArray _readBlockStream(qint64 nOffset, qint64 *pnConsumed, PDSTRUCT *pPdStruct);
    QByteArray _stripCRCChunks(const QByteArray &baData);
    QByteArray _decompressLZMA1(const QByteArray &baData);
    QList<DATA_ENTRY> _parseDataEntries(const QByteArray &baBlock2);
    QList<FILE_ENTRY> _parseFileEntries(const QByteArray &baBlock1, qint32 nNumFiles);
    bool _parseRealInnoSetup(UNPACK_CONTEXT *pContext, qint64 nSignatureOffset, PDSTRUCT *pPdStruct);
    QByteArray _decompressDataChunk(qint64 nChunkOffset, qint64 nChunkCompressedSize, PDSTRUCT *pPdStruct);
    static QString _readWideString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset);
};

#endif  // XINNOSETUP_H
