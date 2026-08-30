/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xkwajsfx.h"

XKwajSFX::XKwajSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XSFX(pDevice, bIsImage, nModuleAddress, ARC_KWAJ)
{
}

bool XKwajSFX::isValid(PDSTRUCT *pPdStruct)
{
    return XSFX::isValid(pPdStruct);
}

bool XKwajSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XKwajSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}
