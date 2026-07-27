/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xsmartinstall.h"

#include "xpe.h"

XSmartInstall::XSmartInstall(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XSmartInstall::~XSmartInstall()
{
}

bool XSmartInstall::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XSmartInstall::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSmartInstall x(pDevice);
    return x.isValid(pPdStruct);
}

XSmartInstall::INTERNAL_INFO XSmartInstall::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XSmartInstall::getFileType()
{
    return FT_ARCHIVE;
}

XSmartInstall::INTERNAL_INFO XSmartInstall::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= getSize())) return result;

    // Literal product tag "Smart Install Maker v" at the overlay start.
    QByteArray baTag = read_array_process(nOverlayOffset, 21, pPdStruct);
    if (baTag != QByteArray("Smart Install Maker v", 21)) return result;

    result.bIsValid = true;

    // Version digits: NUL-terminated ASCII at overlay + 0x17 ("v. <ver>\0").
    QString sVer = read_ansiString(nOverlayOffset + 0x17, 32).trimmed();
    if (!sVer.isEmpty()) {
        result.sVersion = sVer;
    }

    return result;
}
