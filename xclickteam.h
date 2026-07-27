/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XCLICKTEAM_H
#define XCLICKTEAM_H

#include "xbinary.h"

/* Detector for Clickteam Install Creator (Install Creator 2 / Patch Maker).
 * The PE stub keeps its installer payload in the overlay, tagged with the
 * literal marker "wwgT)" at the overlay start. Payload chunks are proprietary
 * (custom container wrapping zlib streams), so this is a detect + version-only
 * class; the tool version comes from the PE VS_VERSION_INFO. */

class XClickteam : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
    };

    explicit XClickteam(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XClickteam() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XCLICKTEAM_H
