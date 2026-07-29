/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XCLICKTEAM_H
#define XCLICKTEAM_H

#include "xbinary.h"

/* Detector + extractor for Clickteam Install Creator (Install Creator 2 /
 * Patch Maker). The PE stub keeps its installer payload in the overlay, tagged
 * with the literal marker "wwgT)" at the overlay start, followed by a chunk
 * table [u32 compSize][u32 uncompSize][u8 method][data][u32 trailer]. The last
 * top-level chunk is a "compound" region holding the installed user files as
 * bare [u8 method][stream] entries. Every user file uses method 1 = zlib, so
 * they are extracted here with stock zlib; method 2 (bzip2) is used only for a
 * UI resource chunk and is skipped. Separate-data builds use the identical
 * bare stream sequence in a sibling .D01 volume. */

class XClickteam : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        qint64 nContainerOffset;
    };

    struct FILE_ENTRY {
        QString sName;
        QByteArray baData;  // decompressed content
    };

    struct UNPACK_CONTEXT {
        UNPACK_CONTEXT() : nTotalOutput(0) {}

        QList<FILE_ENTRY> listEntries;
        qint64 nTotalOutput;
    };

    explicit XClickteam(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XClickteam() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual FT getFileType() override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _buildEntries(UNPACK_CONTEXT *pContext, qint64 nContainerOffset, PDSTRUCT *pPdStruct);
};

#endif  // XCLICKTEAM_H
