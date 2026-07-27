/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XSMARTINSTALL_H
#define XSMARTINSTALL_H

#include "xbinary.h"

/* Detector for Smart Install Maker installers. The Delphi PE stub stores its
 * installer payload in the overlay, prefixed with the literal product tag
 * "Smart Install Maker v. <version>". The payload is a proprietary,
 * possibly multi-volume container, so this is a detect + version-only class;
 * the version is read straight from the overlay tag. */

class XSmartInstall : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
    };

    explicit XSmartInstall(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XSmartInstall() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XSMARTINSTALL_H
