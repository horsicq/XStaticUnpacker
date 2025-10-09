/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinnosetup.h"

XBinary::XCONVERT _TABLE_XINNOSETUP_STRUCTID[] = {
    {XInnoSetup::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XInnoSetup::STRUCTID_HEADER, "HEADER", QString("Header")},
};

XInnoSetup::XInnoSetup(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XInnoSetup::~XInnoSetup()
{
}

QString XInnoSetup::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XINNOSETUP_STRUCTID, sizeof(_TABLE_XINNOSETUP_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XInnoSetup::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

XInnoSetup::INTERNAL_INFO XInnoSetup::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _analyse(pPdStruct);
}

XInnoSetup::INTERNAL_INFO XInnoSetup::_analyse(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    const char *apszSignatures[] = {"Inno Setup Setup Data", "Inno Setup: Setup Data"};
    const qint32 nSignatureCount = sizeof(apszSignatures) / sizeof(const char *);
    qint64 nFileSize = getSize();

    for (qint32 i = 0; (i < nSignatureCount) && (!result.bIsValid); i++) {
        QString sSignature = QString::fromLatin1(apszSignatures[i]);
        qint64 nOffset = find_utf8String(0, nFileSize, sSignature, pPdStruct);

        if (nOffset != -1) {
            result.bIsValid = true;
            result.nSignatureOffset = nOffset;

            const qint32 nWindowSize = 0x80;
            qint64 nRemaining = nFileSize - nOffset;
            if (nRemaining < 0) {
                nRemaining = 0;
            }
            qint64 nBytesToRead = qMin((qint64)nWindowSize, nRemaining);

            if (nBytesToRead > 0) {
                QByteArray baData = read_array(nOffset, nBytesToRead, pPdStruct);
                QString sWindow = QString::fromLatin1(baData.constData(), baData.size());

                qint32 nLeftBracket = sWindow.indexOf('(');
                if (nLeftBracket != -1) {
                    qint32 nRightBracket = sWindow.indexOf(')', nLeftBracket + 1);
                    if ((nRightBracket != -1) && (nRightBracket > nLeftBracket)) {
                        QString sVersionCandidate = sWindow.mid(nLeftBracket + 1, nRightBracket - nLeftBracket - 1).trimmed();
                        result.sVersion = sVersionCandidate;
                    }
                }

                if (result.sVersion.isEmpty()) {
                    qint32 nSignaturePos = sWindow.indexOf(sSignature);
                    if (nSignaturePos != -1) {
                        qint32 nSearchPos = nSignaturePos + sSignature.size();
                        while ((nSearchPos < sWindow.size()) && sWindow.at(nSearchPos).isSpace()) {
                            nSearchPos++;
                        }
                        if ((nSearchPos < sWindow.size()) && (sWindow.at(nSearchPos) == QChar('v'))) {
                            nSearchPos++;
                        }
                        qint32 nVersionStart = nSearchPos;
                        while ((nSearchPos < sWindow.size()) &&
                               ((sWindow.at(nSearchPos).isDigit()) || (sWindow.at(nSearchPos) == QChar('.')) || (sWindow.at(nSearchPos) == QChar('_')))) {
                            nSearchPos++;
                        }
                        if (nSearchPos > nVersionStart) {
                            result.sVersion = sWindow.mid(nVersionStart, nSearchPos - nVersionStart).trimmed();
                        }
                    }
                }
            }
        }
    }

    return result;
}
