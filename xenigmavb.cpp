/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xenigmavb.h"

#include "xpe.h"

XEnigmaVB::XEnigmaVB(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XEnigmaVB::~XEnigmaVB()
{
}

bool XEnigmaVB::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XEnigmaVB::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XEnigmaVB x(pDevice);
    return x.isValid(pPdStruct);
}

XEnigmaVB::INTERNAL_INFO XEnigmaVB::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XEnigmaVB::getFileType()
{
    return FT_ARCHIVE;
}

XEnigmaVB::INTERNAL_INFO XEnigmaVB::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    bool bEnigma1 = false, bEnigma2 = false;
    qint64 nE1Raw = -1, nE1Size = 0;
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".enigma1") {
            bEnigma1 = true;
            nE1Raw = (qint64)listSections.at(i).PointerToRawData;
            nE1Size = (qint64)listSections.at(i).SizeOfRawData;
        } else if (baName == ".enigma2") {
            bEnigma2 = true;
        }
    }

    if (!bEnigma1 || !bEnigma2 || (nE1Raw < 0) || (nE1Size <= 0)) return result;

    // "EVB\0" package header inside .enigma1.
    qint64 nMagic = find_array(nE1Raw, nE1Size, "\x45\x56\x42\x00", 4, pPdStruct);
    if (nMagic == -1) return result;

    result.bIsValid = true;

    // Package-format version: little-endian dword at EVB magic + 0x14.
    QByteArray baVer = read_array_process(nMagic + 0x14, 4, pPdStruct);
    if (baVer.size() == 4) {
        const quint8 *p = (const quint8 *)baVer.constData();
        quint32 nFmt = (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
        if (nFmt && (nFmt < 0x1000)) {
            result.sVersion = QString("package v%1").arg(nFmt);
        }
    }

    return result;
}
