/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XADVANCEDINSTALLER_H
#define XADVANCEDINSTALLER_H

#include "xbinary.h"

/* Detector for Advanced Installer (Caphyon) output. Two shapes:
 *  - the bootstrapper .exe, marked by the 10-byte EOF trailer "ADVINSTSFX";
 *  - the authored .msi, an MSI database carrying the "aicustact.dll" custom
 *    action + the "AI_" property namespace + "Advanced Installer" strings.
 * This is a detect + version class; MSI extraction is available through XMSI,
 * while the self-contained ExeInside bootstrapper uses a proprietary container. */

class XAdvancedInstaller : public XBinary {
    Q_OBJECT

public:
    enum SUBTYPE {
        SUBTYPE_UNKNOWN = 0,
        SUBTYPE_EXE,
        SUBTYPE_MSI
    };

    struct INTERNAL_INFO {
        bool bIsValid;
        SUBTYPE subType;
        QString sVersion;
    };

    explicit XAdvancedInstaller(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XAdvancedInstaller() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XADVANCEDINSTALLER_H
