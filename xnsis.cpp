/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xnsis.h"

#include <QByteArray>

XBinary::XCONVERT _TABLE_XNSIS_STRUCTID[] = {
    {XNSIS::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XNSIS::STRUCTID_HEADER, "HEADER", QString("Header")},
};

XNSIS::XNSIS(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XNSIS::~XNSIS()
{
}

QString XNSIS::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XNSIS_STRUCTID, sizeof(_TABLE_XNSIS_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XNSIS::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

XNSIS::INTERNAL_INFO XNSIS::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _analyse(pPdStruct);
}

XNSIS::INTERNAL_INFO XNSIS::_analyse(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    qint64 nFileSize = getSize();

    if (nFileSize < 0) {
        nFileSize = 0;
    }

    const char *apszSignatures[] = {"Nullsoft.NSIS", "NullsoftInst", ";!@Install@!UTF-8!", ";!@Install@!UTF-16LE", ";!@Install@!"};
    const qint32 nSignatureCount = sizeof(apszSignatures) / sizeof(const char *);

    for (qint32 i = 0; (i < nSignatureCount) && (!result.bIsValid); i++) {
        QString sSignatureCandidate = QString::fromLatin1(apszSignatures[i]);
        qint64 nOffset = find_ansiString(0, nFileSize, sSignatureCandidate, pPdStruct);

        if (nOffset != -1) {
            result.bIsValid = true;
            result.nSignatureOffset = nOffset;
            result.sSignature = sSignatureCandidate;

            const qint64 nWindowSize = 0x200;
            qint64 nRemainingSize = nFileSize - nOffset;
            if (nRemainingSize < 0) {
                nRemainingSize = 0;
            }

            qint64 nBytesToRead = qMin(nWindowSize, nRemainingSize);

            if (nBytesToRead > 0) {
                QByteArray baWindow = read_array(nOffset, nBytesToRead, pPdStruct);

                if (!baWindow.isEmpty()) {
                    QString sWindow = QString::fromLatin1(baWindow.constData(), baWindow.size());

                    if ((sWindow.contains("UTF-8")) || (sWindow.contains("UTF-16"))) {
                        result.bIsUnicode = true;
                    }

                    qint32 nWindowLength = sWindow.length();
                    for (qint32 j = 0; (j < nWindowLength) && result.sVersion.isEmpty(); j++) {
                        QChar cCurrent = sWindow.at(j);
                        if ((cCurrent == QChar('v')) || (cCurrent == QChar('V'))) {
                            qint32 nPos = j + 1;
                            while ((nPos < nWindowLength) && sWindow.at(nPos).isSpace()) {
                                nPos++;
                            }
                            qint32 nVersionStart = nPos;
                            while ((nPos < nWindowLength) && (sWindow.at(nPos).isDigit() || (sWindow.at(nPos) == QChar('.')) || (sWindow.at(nPos) == QChar('_')))) {
                                nPos++;
                            }
                            if (nPos > nVersionStart) {
                                result.sVersion = sWindow.mid(nVersionStart, nPos - nVersionStart).trimmed();
                            }
                        }
                    }

                    if (result.sVersion.isEmpty()) {
                        qint32 nWindowIndex = 0;
                        while ((nWindowIndex < nWindowLength) && result.sVersion.isEmpty()) {
                            QChar cSymbol = sWindow.at(nWindowIndex);
                            if (cSymbol.isDigit()) {
                                qint32 nStartIndex = nWindowIndex;
                                qint32 nEndIndex = nWindowIndex;
                                while ((nEndIndex < nWindowLength) && (sWindow.at(nEndIndex).isDigit() || (sWindow.at(nEndIndex) == QChar('.')))) {
                                    nEndIndex++;
                                }
                                if (nEndIndex > nStartIndex) {
                                    QString sCandidate = sWindow.mid(nStartIndex, nEndIndex - nStartIndex).trimmed();
                                    if (sCandidate.count('.') >= 1) {
                                        result.sVersion = sCandidate;
                                    }
                                }
                                nWindowIndex = nEndIndex;
                            } else {
                                nWindowIndex++;
                            }
                        }
                    }
                }
            }
        }
    }

    if ((!result.bIsValid) && (nFileSize > 16)) {
        qint64 nOverlayOffset = getOverlayOffset();

        if ((nOverlayOffset != -1) && (nOverlayOffset < nFileSize)) {
            qint64 nOverlaySize = nFileSize - nOverlayOffset;
            qint64 nBytesToRead = qMin((qint64)0x40, nOverlaySize);

            if (nBytesToRead > 0) {
                QByteArray baOverlay = read_array(nOverlayOffset, nBytesToRead, pPdStruct);

                if (baOverlay.size() >= 16) {
                    const char *pOverlayData = baOverlay.constData();

                    if (((quint8)pOverlayData[8] == 0xDE) && ((quint8)pOverlayData[9] == 0xAD) && ((quint8)pOverlayData[10] == 0xBE) &&
                        ((quint8)pOverlayData[11] == 0xEF)) {
                        QByteArray baSignature = baOverlay.mid(12);
                        qint32 nLocalOffset = baSignature.indexOf("NullsoftInst");

                        if (nLocalOffset != -1) {
                            result.bIsValid = true;
                            result.nSignatureOffset = nOverlayOffset + 12 + nLocalOffset;
                            result.sSignature = QString::fromLatin1("NullsoftInst");
                        }
                    }
                }
            }
        }
    }

    return result;
}
