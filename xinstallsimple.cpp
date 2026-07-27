/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinstallsimple.h"

#include "xpe.h"

XInstallSimple::XInstallSimple(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XInstallSimple::~XInstallSimple()
{
}

bool XInstallSimple::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XInstallSimple::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XInstallSimple x(pDevice);
    return x.isValid(pPdStruct);
}

XInstallSimple::INTERNAL_INFO XInstallSimple::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XInstallSimple::getFileType()
{
    return FT_ARCHIVE;
}

XInstallSimple::INTERNAL_INFO XInstallSimple::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= getSize())) return result;

    // Fixed 16-byte InstallSimple container header at the overlay start.
    static const char kMarker[16] = {0x6E, 0x01, 0x00, 0x00, (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF,
                                     0x00, 0x00, (char)0x9E, 0x7F, (char)0xFF, (char)0xFF, (char)0xFF, 0x57};
    QByteArray baMarker = read_array_process(nOverlayOffset, 16, pPdStruct);
    if (baMarker != QByteArray(kMarker, 16)) return result;

    result.bIsValid = true;

    // The pre-built engine stub is fixed per builder revision -> AEP identifies it.
    quint32 nAEP = (quint32)pe.getOptionalHeader_AddressOfEntryPoint();
    if (nAEP == 0xE830) {
        result.sVersion = "3.5.2";
    } else if (nAEP == 0xE860) {
        result.sVersion = "3.5";
    }

    return result;
}
