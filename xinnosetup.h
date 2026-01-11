/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINNOSETUP_H
#define XINNOSETUP_H

#include <QString>

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

    struct FILE_ENTRY {
        QString sDestination;       // Destination path
        QString sSource;            // Source filename
        qint64 nFileOffset;         // Offset in data area
        qint64 nCompressedSize;     // Compressed size
        qint64 nUncompressedSize;   // Uncompressed size
        quint32 nCRC32;             // CRC32 checksum
        quint32 nFlags;             // File flags
        quint32 nLocation;          // Location index
        qint32 nCompressionMethod;  // Compression method (0=stored, 1=zlib, 2=bz2, 3=lzma)
    };

    struct UNPACK_CONTEXT {
        QList<FILE_ENTRY> listFiles;  // List of file entries
        qint64 nDataOffset;           // Offset to compressed data area
        qint64 nHeaderOffset;         // Offset to setup header
        qint32 nCurrentIndex;         // Current file index
        bool bParsed;                 // Whether structure has been parsed
    };

    explicit XInnoSetup(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInnoSetup() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual QString structIDToString(quint32 nID) override;

    // Streaming unpacking API
    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
    bool _parseInnoSetupStructure(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct);
    bool _findSetupData(qint64 *pnOffset, qint64 *pnSize, PDSTRUCT *pPdStruct);
    QByteArray _decompressData(const QByteArray &baCompressed, qint32 nMethod, qint64 nUncompressedSize);
};

#endif  // XINNOSETUP_H
