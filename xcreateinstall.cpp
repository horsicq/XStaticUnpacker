/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xcreateinstall.h"

#include "xpe.h"

XCreateInstall::XCreateInstall(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XCreateInstall::~XCreateInstall()
{
}

bool XCreateInstall::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XCreateInstall::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XCreateInstall x(pDevice);
    return x.isValid(pPdStruct);
}

XCreateInstall::INTERNAL_INFO XCreateInstall::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XCreateInstall::getFileType()
{
    return FT_ARCHIVE;
}

XCreateInstall::INTERNAL_INFO XCreateInstall::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    bool bGentee = false;
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".gentee") {
            bGentee = true;
            break;
        }
    }

    if (!bGentee) return result;

    // Corroborate with the Gentee runtime strings (unique to the engine).
    const qint64 nSize = getSize();
    bool bMarker = (find_ansiString(0, nSize, "lzge_decode", pPdStruct) != -1) || (find_ansiString(0, nSize, "genteert.dll", pPdStruct) != -1) ||
                   (find_ansiString(0, nSize, "gentee_init", pPdStruct) != -1);
    if (!bMarker) return result;

    result.bIsValid = true;

    // GEA container format version: "GEA" + 00 00 00 + dword + version word (02 00).
    qint64 nGea = find_array(0, nSize, "\x47\x45\x41\x00\x00\x00", 6, pPdStruct);
    if (nGea != -1) {
        QByteArray baVer = read_array_process(nGea + 0x0A, 2, pPdStruct);
        if (baVer.size() == 2) {
            quint16 nVer = (quint16)((quint8)baVer.at(0) | ((quint16)(quint8)baVer.at(1) << 8));
            if (nVer && (nVer < 0x100)) {
                result.sVersion = QString("GEA v%1").arg(nVer);
            }
        }
    }

    return result;
}
