/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XBOXEDAPP_H
#define XBOXEDAPP_H

#include "xbinary.h"

/* Detector for BoxedApp Packer (Softanics) application-virtualizer output.
 * The wrapped PE carries a ".bxpck" control section followed by a ".main"
 * section that holds the BoxedApp engine + the sandboxed virtual filesystem,
 * identified by the "BoxedApp::" C++ symbol strings. The VFS is proprietary
 * (no standard archive), so this is a detect + version-only class; trial
 * builds are flagged via the embedded demo nag ("demo"). */

class XBoxedApp : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;  // "demo" for trial builds, otherwise empty
    };

    explicit XBoxedApp(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XBoxedApp() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XBOXEDAPP_H
