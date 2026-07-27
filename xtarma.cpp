/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xtarma.h"

#include "xpe.h"

XTarma::XTarma(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XTarma::~XTarma()
{
}

bool XTarma::isValid(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct).bIsValid;
}

bool XTarma::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XTarma x(pDevice);
    return x.isValid(pPdStruct);
}

XTarma::INTERNAL_INFO XTarma::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

XBinary::FT XTarma::getFileType()
{
    return FT_ARCHIVE;
}

// Match a PE section by exact name (8-byte COFF field, NUL-padded).
static qint64 tarmaSectionRaw(const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, const char *pszName)
{
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == pszName) {
            return (qint64)listSections.at(i).PointerToRawData;
        }
    }
    return -1;
}

XTarma::INTERNAL_INFO XTarma::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    qint64 nStubRaw = tarmaSectionRaw(listSections, ".tsustub");
    qint64 nArchRaw = tarmaSectionRaw(listSections, ".tsuarch");

    // Primary (v9): both .tsu* sections + the "tiz" container magic at raw+0x10.
    if ((nStubRaw >= 0) && (nArchRaw >= 0)) {
        QByteArray baMagic = read_array_process(nArchRaw + 0x10, 8, pPdStruct);
        if (baMagic.size() == 8) {
            const quint8 *p = (const quint8 *)baMagic.constData();
            // "tiz" <digit> 'z' 00 <version word 09 00>
            if ((p[0] == 0x74) && (p[1] == 0x69) && (p[2] == 0x7A) && (p[3] >= 0x30) && (p[3] <= 0x39) && (p[4] == 0x7A) && (p[5] == 0x00)) {
                result.bIsValid = true;
                quint16 nVer = (quint16)(p[6] | ((quint16)p[7] << 8));
                result.sVersion = QString::number(nVer);  // container version word (9)
                return result;
            }
        }
    }

    // Legacy: the payload sits in the overlay as "tiz1" + raw zlib (78 DA).
    qint64 nOverlayOffset = getOverlayOffset(pPdStruct);
    if ((nOverlayOffset > 0) && (nOverlayOffset < getSize())) {
        QByteArray baOv = read_array_process(nOverlayOffset, 10, pPdStruct);
        if (baOv.size() >= 10) {
            const quint8 *p = (const quint8 *)baOv.constData();
            if ((p[0] == 0x74) && (p[1] == 0x69) && (p[2] == 0x7A) && (p[3] == 0x31) && (p[8] == 0x78) && (p[9] == 0xDA)) {
                result.bIsValid = true;
                result.bIsLegacy = true;
                result.sVersion = QString();
                return result;
            }
        }
    }

    return result;
}
