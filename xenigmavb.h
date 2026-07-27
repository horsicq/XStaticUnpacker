/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XENIGMAVB_H
#define XENIGMAVB_H

#include "xbinary.h"

/* Detector for Enigma Virtual Box (the Enigma Protector team's free file
 * bundler / application virtualizer). The wrapped PE carries two dedicated
 * sections, ".enigma1" (the EVB virtual-filesystem directory) and ".enigma2"
 * (the embedded loader DLL + bulk file data), and an "EVB\0" package header
 * inside .enigma1. The package is a proprietary virtual FS, optionally
 * compressed, so this is a detect + version-only class. */

class XEnigmaVB : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;  // EVB package-format version
    };

    explicit XEnigmaVB(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XEnigmaVB() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XENIGMAVB_H
