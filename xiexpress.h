/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XIEXPRESS_H
#define XIEXPRESS_H

#include "xbinary.h"

class SubDevice;
class XArchive;

/* Detector + extractor for IExpress / Wextract self-extractors (Win32 Cabinet
 * Self-Extractor). The wextract stub stores a Microsoft cabinet (MSCF) in an
 * RT_RCDATA resource named "CABINET", plus behaviour metadata in sibling
 * RT_RCDATA resources (RUNPROGRAM, TITLE, ...). Extraction delegates to the
 * XArchive CAB handler on the CABINET resource region. */

class XIExpress : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;  // wextract stub version
        qint64 nArchiveOffset;
        qint64 nArchiveSize;
    };

    struct UNPACK_CONTEXT {
        SubDevice *pSubDevice;
        XArchive *pArchive;
        UNPACK_STATE innerState;
    };

    explicit XIExpress(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XIExpress() override;

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

#endif  // XIEXPRESS_H
