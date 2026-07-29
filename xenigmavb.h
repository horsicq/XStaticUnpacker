/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XENIGMAVB_H
#define XENIGMAVB_H

#include "xbinary.h"

/* Detector + extractor for Enigma Virtual Box (the Enigma Protector team's free
 * file bundler / application virtualizer). The wrapped PE carries two dedicated
 * sections, ".enigma1" (the EVB virtual-filesystem directory) and ".enigma2"
 * (the embedded loader DLL + bulk file data), and an "EVB\0" package header
 * inside .enigma1. The VFS tree is walked and the bundled files are extracted:
 * stored files are carved verbatim, aPLib-compressed files are depacked. */

class XEnigmaVB : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;     // EVB package-format version
        qint64 nMagicOffset;  // file offset of the "EVB\0" package header
        qint64 nBaseOffset;   // file offset of the .enigma1 section raw data
        qint64 nBaseSize;     // bounded package span from .enigma1 through .enigma2
        qint64 nTreeSize;     // physical .enigma1 size (tree boundary)
    };

    struct FILE_ENTRY {
        QString sName;
        QByteArray baData;  // decoded content (stored verbatim or aPLib-depacked)
    };

    struct UNPACK_CONTEXT {
        QList<FILE_ENTRY> listEntries;
    };

    explicit XEnigmaVB(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XEnigmaVB() override;

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
};

#endif  // XENIGMAVB_H
