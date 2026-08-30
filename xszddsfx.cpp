/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xszddsfx.h"

XSzddSFX::XSzddSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XSFX(pDevice, bIsImage, nModuleAddress, ARC_SZDD)
{
}

bool XSzddSFX::isValid(PDSTRUCT *pPdStruct)
{
    return XSFX::isValid(pPdStruct);
}

bool XSzddSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSzddSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}
