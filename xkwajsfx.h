/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XKWAJSFX_H
#define XKWAJSFX_H

#include "xsfx.h"

class XKwajSFX : public XSFX {
    Q_OBJECT

public:
    explicit XKwajSFX(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
};

#endif  // XKWAJSFX_H
