/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XWIX_H
#define XWIX_H

#include "xbinary.h"

/* Detector for WiX Toolset-authored installers. WiX emits a Windows Installer
 * (MSI) database whose SummaryInformation "Creating Application" is
 * "Windows Installer XML Toolset (x.y.z)" (or, on v4/v5, "WiX Toolset (...)").
 * This class identifies the authoring tool + its version on top of the MSI
 * container; MSI extraction is available through XMSI. */

class XWiX : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
    };

    explicit XWiX(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XWiX() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XWIX_H
