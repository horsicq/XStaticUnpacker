/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINSTALLSIMPLE_H
#define XINSTALLSIMPLE_H

#include "xbinary.h"

/* Detector for Install Simple (InstallSimple) installers. The (UPX-packed,
 * MASM32) PE stub stores a proprietary, obfuscated container in the overlay,
 * whose fixed 16-byte header is the family marker. The container is not a
 * standard archive, so this is a detect + version-only class; the builder
 * revision is distinguished by the fixed entry-point RVA. */

class XInstallSimple : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
    };

    explicit XInstallSimple(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInstallSimple() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XINSTALLSIMPLE_H
