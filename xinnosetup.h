/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINNOSETUP_H
#define XINNOSETUP_H

#include <QString>
#include <QBuffer>

#include "xbinary.h"

class XArchive;

class XInnoSetup : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
    };
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sVersion;
    };

    // Real InnoSetup offset table parsed from rDlPtS magic
    struct OFFSET_TABLE {
        bool bIsValid;
        qint64 nTableOffset;  // Absolute offset of the rDlPtS magic
        quint32 nRevision;
        quint64 nTotalSize;
        qint64 nExeOffset;
        quint32 nExeUncompressedSize;
        quint32 nExeChecksum;
        qint64 nHeaderOffset;  // Absolute offset of setup-0.bin
        qint64 nDataOffset;    // Absolute offset of setup-1.bin/data stream
    };

    enum INNO_COMPRESSION {
        INNO_COMPRESSION_UNKNOWN = -1,
        INNO_COMPRESSION_STORE = 0,
        INNO_COMPRESSION_ZLIB,
        INNO_COMPRESSION_BZIP2,
        INNO_COMPRESSION_LZMA1,
        INNO_COMPRESSION_LZMA2,
    };

    enum INNO_CHECKSUM {
        INNO_CHECKSUM_UNKNOWN = 0,
        INNO_CHECKSUM_MD5,
        INNO_CHECKSUM_SHA1,
        INNO_CHECKSUM_SHA256,
    };

    struct INNO_VERSION {
        bool bIsValid;
        bool bUnicode;
        quint16 nMajor;
        quint16 nMinor;
        quint16 nPatch;
        quint16 nRevision;
    };

    struct HEADER_INFO {
        bool bIsValid;
        qint32 nFileCount;
        qint32 nDataEntryCount;
        qint32 nHeaderEndOffset;
        qint32 nCountCount;
        qint32 anCounts[17];
        INNO_COMPRESSION compression;
    };

    // Data entry from Block Stream 2 (data locations)
    struct DATA_ENTRY {
        quint32 nFirstSlice;
        quint32 nLastSlice;
        qint64 nChunkStartOffset;  // Offset of the zlb chunk in the data stream
        qint64 nChunkSubOffset;    // Offset within the decompressed solid chunk
        qint64 nOriginalSize;
        qint64 nChunkCompressedSize;
        QByteArray baChecksum;
        INNO_CHECKSUM checksumType;
        INNO_COMPRESSION compression;
        quint64 nFileTime;
        quint32 nFileVersionMS;
        quint32 nFileVersionLS;
        quint16 nFlags;
        bool bCallInstructionOptimized;
        bool bChunkEncrypted;
        bool bChunkCompressed;
    };

    // File entry from Block Stream 1 (file metadata)
    struct FILE_ENTRY {
        QString sDestName;      // Destination path (e.g., {app}\file.txt)
        qint32 nLocationEntry;  // Index into DATA_ENTRY array (-1 if none)
    };

    // Decompressed chunk cache for solid compression
    struct CHUNK_CACHE {
        qint64 nChunkOffset;             // Absolute offset identifying the chunk
        INNO_COMPRESSION compression;
        QByteArray baDecompressedData;  // Full decompressed chunk content
    };

    struct UNPACK_CONTEXT {
        QPointer<QIODevice> pOuterSourceDevice;
        quint64 nOwnerDeviceGeneration;
        UNPACK_STATE *pOwnerState = nullptr;
        XArchive *pSourceValidator;
        UNPACK_STATE sourceValidationState;
        QList<ARCHIVERECORD> listAllRecords;
        bool bIsRealFormat;  // true = real InnoSetup, false = synthetic ISDF
        INNO_VERSION version;
        qint64 nSignatureOffset;
        qint64 nDataStreamOffset;  // Absolute offset of data overlay (zlb chunks)
        QList<DATA_ENTRY> listDataEntries;
        QList<FILE_ENTRY> listFileEntries;
        CHUNK_CACHE chunkCache;  // Cached decompressed chunk
    };

    struct UNPACK_LIFETIME_STATE {
        UNPACK_LIFETIME_STATE() : bOperationInProgress(false), bOwnerAlive(true) {}
        ~UNPACK_LIFETIME_STATE();
        bool bOperationInProgress;
        bool bOwnerAlive;
        QSet<UNPACK_CONTEXT *> setContexts;
    };

    static void deleteUnpackContext(UNPACK_CONTEXT *pContext);

    explicit XInnoSetup(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInnoSetup() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    virtual FT getFileType() override;
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual QString structIDToString(quint32 nID) override;
    virtual QString structIDToFtString(quint32 nID) override;
    virtual quint32 ftStringToStructID(const QString &sFtString) override;

    // Streaming unpacking API
    virtual QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

protected:
    bool isDeviceReplacementAllowed() const override
    {
        return m_pUnpackLifetimeState && m_pUnpackLifetimeState->bOwnerAlive &&
               !m_pUnpackLifetimeState->bOperationInProgress && m_pUnpackLifetimeState->setContexts.isEmpty();
    }

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
    QList<ARCHIVERECORD> _parseSyntheticFileEntries(qint64 nSignatureOffset, PDSTRUCT *pPdStruct);

    // Real InnoSetup format parsing
    OFFSET_TABLE _findOffsetTable(PDSTRUCT *pPdStruct);
    QByteArray _readBlockStream(qint64 nOffset, qint64 *pnConsumed, PDSTRUCT *pPdStruct, bool b64BitStoredSize = false);
    QByteArray _stripCRCChunks(const QByteArray &baData, bool *pbValid);
    QByteArray _decompressLZMA1(const QByteArray &baData);
    QList<DATA_ENTRY> _parseDataEntries(const QByteArray &baBlock2, const INNO_VERSION &version, bool bRev2,
                                        qint32 nExpectedCount, INNO_COMPRESSION headerCompression);
    // bUnicode selects UTF-16 WideString (Inno >= 5.3.0 Unicode builds, all 6.x) vs single-byte
    // AnsiString (Inno < 5.3.0, e.g. 5.1.x) parsing of the setup-0 file-entry array.
    QList<FILE_ENTRY> _parseFileEntries(const QByteArray &baBlock1, const HEADER_INFO &headerInfo,
                                        const INNO_VERSION &version, bool bRev2 = false);
    QList<FILE_ENTRY> _parseFileEntriesAnsi(const QByteArray &baBlock1, const HEADER_INFO &headerInfo,
                                            const INNO_VERSION &version);
    bool _parseRealInnoSetup(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    QByteArray _decompressDataChunk(qint64 nChunkOffset, qint64 nChunkCompressedSize,
                                    qint64 nOutputLimit, INNO_COMPRESSION compression, PDSTRUCT *pPdStruct);
    static INNO_VERSION _parseVersionId(const QByteArray &baVersionId);
    static HEADER_INFO _parseHeaderInfo(const QByteArray &baBlock1, const INNO_VERSION &version);
    static QString _readWideString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset);
    static QString _readAnsiString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset);
    static QString _readSetupString(const QByteArray &baData, qint32 nOffset, qint32 *pnNewOffset, bool bUnicode);
    static QString _decodeWindows1252(const char *pData, qint32 nSize);
    QSharedPointer<UNPACK_LIFETIME_STATE> m_pUnpackLifetimeState;
};

#endif  // XINNOSETUP_H
