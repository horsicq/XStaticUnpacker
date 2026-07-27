/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XWINRARSFX_H
#define XWINRARSFX_H

#include "xbinary.h"

class SubDevice;
class XArchive;

/* Detector + extractor for WinRAR self-extracting archives (sfxrar/sfxcon
 * modules). The PE stub is followed by a RAR4/RAR5 archive at the overlay
 * start; attribution to WinRAR is via the RT_MANIFEST name="WinRAR marker.
 * Extraction delegates to the XArchive RAR handler on the overlay region. */

class XWinRarSfx : public XBinary {
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

    explicit XWinRarSfx(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XWinRarSfx() override;

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

#endif  // XWINRARSFX_H
