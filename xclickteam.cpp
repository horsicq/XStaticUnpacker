/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xclickteam.h"

#include "xpe.h"

XClickteam::XClickteam(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XClickteam::~XClickteam()
{
}

bool XClickteam::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XClickteam::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XClickteam x(pDevice);
    return x.isValid(pPdStruct);
}

XClickteam::INTERNAL_INFO XClickteam::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XClickteam::getFileType()
{
    return FT_ARCHIVE;
}

XClickteam::INTERNAL_INFO XClickteam::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= getSize())) return result;

    // "wwgT)" tag at the overlay start (Install Creator 2 payload container).
    QByteArray baTag = read_array_process(nOverlayOffset, 5, pPdStruct);
    if (baTag != QByteArray("\x77\x77\x67\x54\x29", 5)) return result;

    result.bIsValid = true;
    result.sVersion = pe.getFileVersion().trimmed();

    return result;
}
