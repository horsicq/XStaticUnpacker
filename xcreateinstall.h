/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XCREATEINSTALL_H
#define XCREATEINSTALL_H

#include "xbinary.h"

/* Detector for CreateInstall (Gentee-engine) installers. The self-extracting
 * PE carries a ".gentee" section plus the Gentee runtime strings
 * ("genteert.dll" / "gentee_init" / "lzge_decode") and stores its payload as a
 * proprietary "GEA" container (lzge / PPMd / store) in the overlay and in the
 * RT_RCDATA "SETUP_TEMP" resource. The container is proprietary, so this is a
 * detect + version-only class. */

class XCreateInstall : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;  // GEA container format version, if readable
    };

    explicit XCreateInstall(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XCreateInstall() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XCREATEINSTALL_H
