/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xupx.h"

XUPX::XUPX(QIODevice *pDevice) : XBinary(pDevice) {}

XUPX::~XUPX()
{

}

bool XUPX::isValid(PDSTRUCT *pPdStruct)
{
    return getUnpackInfo(pPdStruct).bIsValid;
}

XUPX::UNPACK_INFO XUPX::getUnpackInfo(PDSTRUCT *pPdStruct)
{
    XUPX::UNPACK_INFO info = {};

    // TODO

    return info;
}
