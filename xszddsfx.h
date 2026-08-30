/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XSZDDSFX_H
#define XSZDDSFX_H

#include "xsfx.h"

class XSzddSFX : public XSFX {
    Q_OBJECT

public:
    explicit XSzddSFX(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
};

#endif  // XSZDDSFX_H
