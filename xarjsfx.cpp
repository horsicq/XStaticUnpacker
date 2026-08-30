/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xarjsfx.h"

XArjSFX::XArjSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XSFX(pDevice, bIsImage, nModuleAddress, ARC_ARJ)
{
}

bool XArjSFX::isValid(PDSTRUCT *pPdStruct)
{
    return XSFX::isValid(pPdStruct);
}

bool XArjSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XArjSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}
