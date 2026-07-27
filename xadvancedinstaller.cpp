/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xadvancedinstaller.h"

#include "xmsi.h"

XAdvancedInstaller::XAdvancedInstaller(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XAdvancedInstaller::~XAdvancedInstaller()
{
}

bool XAdvancedInstaller::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XAdvancedInstaller::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XAdvancedInstaller x(pDevice);
    return x.isValid(pPdStruct);
}

XAdvancedInstaller::INTERNAL_INFO XAdvancedInstaller::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XAdvancedInstaller::getFileType()
{
    return FT_ARCHIVE;
}

XAdvancedInstaller::INTERNAL_INFO XAdvancedInstaller::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.subType = SUBTYPE_UNKNOWN;

    const qint64 nSize = getSize();
    if (nSize < 0x40) return result;

    // Read the version token after the "Advanced Installer " string (e.g. "23.9").
    auto readVersion = [&]() -> QString {
        qint64 nPos = find_ansiString(0, nSize, "Advanced Installer ", pPdStruct);
        if (nPos == -1) return QString();
        QString sTail = read_ansiString(nPos + 19, 32).trimmed();  // after "Advanced Installer "
        QString sVer;
        for (int i = 0; i < sTail.size(); i++) {
            QChar ch = sTail.at(i);
            if (ch.isDigit() || (ch == '.')) {
                sVer += ch;
            } else {
                break;
            }
        }
        return sVer;
    };

    // EXE bootstrapper: 10-byte EOF trailer "ADVINSTSFX".
    QByteArray baTrailer = read_array_process(nSize - 10, 10, pPdStruct);
    if (baTrailer == QByteArray("ADVINSTSFX", 10)) {
        result.bIsValid = true;
        result.subType = SUBTYPE_EXE;
        result.sVersion = readVersion();
        return result;
    }

    // MSI authored by Advanced Installer.
    if (XMSI::isValid(getDevice(), pPdStruct)) {
        bool bAI = (find_ansiString(0, nSize, "aicustact.dll", pPdStruct) != -1) && (find_ansiString(0, nSize, "Advanced Installer", pPdStruct) != -1);
        if (bAI) {
            result.bIsValid = true;
            result.subType = SUBTYPE_MSI;
            result.sVersion = readVersion();
            return result;
        }
    }

    return result;
}
