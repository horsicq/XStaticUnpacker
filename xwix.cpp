/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xwix.h"

#include "xmsi.h"

XWiX::XWiX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XWiX::~XWiX()
{
}

bool XWiX::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XWiX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XWiX x(pDevice);
    return x.isValid(pPdStruct);
}

XWiX::INTERNAL_INFO XWiX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XWiX::getFileType()
{
    return FT_ARCHIVE;
}

XWiX::INTERNAL_INFO XWiX::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    // Must be an MSI container.
    if (!XMSI::isValid(getDevice(), pPdStruct)) return result;

    const qint64 nSize = getSize();

    // WiX authoring marker (SummaryInformation "Creating Application").
    qint64 nPos = find_ansiString(0, nSize, "Windows Installer XML", pPdStruct);
    if (nPos == -1) nPos = find_ansiString(0, nSize, "WiX Toolset (", pPdStruct);
    if (nPos == -1) return result;

    result.bIsValid = true;

    // Version = the dotted number in parentheses after the app name.
    QString sApp = read_ansiString(nPos, 128);
    int nOpen = sApp.indexOf('(');
    int nClose = sApp.indexOf(')', nOpen + 1);
    if ((nOpen >= 0) && (nClose > nOpen)) {
        QString sFull = sApp.mid(nOpen + 1, nClose - nOpen - 1).trimmed();
        QStringList listParts = sFull.split('.');
        if (listParts.size() >= 2) {
            result.sVersion = listParts.at(0) + "." + listParts.at(1);
        } else {
            result.sVersion = sFull;
        }
    }

    return result;
}
