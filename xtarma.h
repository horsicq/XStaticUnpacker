/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XTARMA_H
#define XTARMA_H

#include "xbinary.h"

/* Detector for Tarma InstallMate installers.
 *
 * Tarma InstallMate (Setup Utility) marks its PE with two dedicated sections,
 * ".tsustub" (the loader) and ".tsuarch" (the packed payload), and stores a
 * proprietary "TIZ" container inside .tsuarch: at section raw + 0x10 the bytes
 * are "tiz" + <generation digit> + "z" + 00 + <version word>. The v9 container
 * ("tiz3z"/"tiz2z") is a scrambled + LZMA-like stream that XArchive cannot
 * parse, so this is a detect + version-only class (no extraction). */

class XTarma : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        bool bIsLegacy;  // legacy tiz1 overlay layout
    };

    explicit XTarma(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XTarma() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XTARMA_H
