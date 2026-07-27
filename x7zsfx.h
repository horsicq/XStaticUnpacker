/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef X7ZSFX_H
#define X7ZSFX_H

#include "xbinary.h"

class SubDevice;
class XArchive;

/* Detector + extractor for 7-Zip self-extracting archives (7z.sfx / 7zCon.sfx
 * GUI/console modules and the 7zSD.sfx installer SFX). The PE stub is followed
 * by a 7z archive in the overlay, optionally preceded by a ";!@Install@!UTF-8!"
 * config block. Detection keys on the overlay marker; extraction delegates to
 * the XArchive 7z handler on the located archive region. */

class X7ZSFX : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        qint64 nArchiveOffset;
        qint64 nArchiveSize;
    };

    struct UNPACK_CONTEXT {
        SubDevice *pSubDevice;
        XArchive *pArchive;
        UNPACK_STATE innerState;
    };

    explicit X7ZSFX(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~X7ZSFX() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // X7ZSFX_H
