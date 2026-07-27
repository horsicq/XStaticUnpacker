/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xboxedapp.h"

#include "xpe.h"

XBoxedApp::XBoxedApp(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XBoxedApp::~XBoxedApp()
{
}

bool XBoxedApp::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XBoxedApp::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XBoxedApp x(pDevice);
    return x.isValid(pPdStruct);
}

XBoxedApp::INTERNAL_INFO XBoxedApp::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XBoxedApp::getFileType()
{
    return FT_ARCHIVE;
}

XBoxedApp::INTERNAL_INFO XBoxedApp::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    bool bBxpck = false;
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".bxpck") {
            bBxpck = true;
            break;
        }
    }

    if (!bBxpck) return result;

    // BoxedApp-exclusive C++ symbol strings live in the ".main" engine section.
    const qint64 nSize = getSize();
    if (find_ansiString(0, nSize, "BoxedApp::", pPdStruct) == -1) return result;

    result.bIsValid = true;

    // Trial builds embed a UTF-16LE demo nag screen ("...demo version of BoxedApp...").
    QByteArray baNeedle;
    const char *pszDemo = "demo version of BoxedApp";
    for (const char *q = pszDemo; *q; ++q) {
        baNeedle.append(*q);
        baNeedle.append('\0');
    }
    if (find_array(0, nSize, baNeedle.constData(), baNeedle.size(), pPdStruct) != -1) {
        result.sVersion = "demo";
    }

    return result;
}
