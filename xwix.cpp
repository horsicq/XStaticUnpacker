/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xwix.h"

#include <QBuffer>
#include <QSet>
#include <algorithm>
#if (QT_VERSION_MAJOR < 6) || defined(QT_CORE5COMPAT_LIB)
#include <QTextCodec>
#else
#include <QStringConverter>
#endif

#include "../XArchive/xcfbf.h"
#include "xmsi.h"

namespace {
struct WIX_PROPERTY_ENTRY {
    quint32 nID;
    quint32 nOffset;
    quint32 nEnd;
};

static quint16 wixReadLE16(const QByteArray &baData, qint32 nOffset)
{
    return (quint8)baData.at(nOffset) | ((quint16)(quint8)baData.at(nOffset + 1) << 8);
}

static quint32 wixReadLE32(const QByteArray &baData, qint32 nOffset)
{
    return (quint32)(quint8)baData.at(nOffset) | ((quint32)(quint8)baData.at(nOffset + 1) << 8) |
           ((quint32)(quint8)baData.at(nOffset + 2) << 16) | ((quint32)(quint8)baData.at(nOffset + 3) << 24);
}

static bool wixIsZeroRange(const QByteArray &baData, quint32 nOffset, quint32 nEnd)
{
    if ((nOffset > nEnd) || (nEnd > (quint32)baData.size())) return false;
    for (quint32 i = nOffset; i < nEnd; i++) {
        if (baData.at((qint32)i) != 0) return false;
    }
    return true;
}

static QString wixCodePageName(quint16 nCodePage)
{
    switch (nCodePage) {
        case 65001: return QStringLiteral("UTF-8");
        case 932: return QStringLiteral("Shift-JIS");
        case 936: return QStringLiteral("GBK");
        case 949: return QStringLiteral("CP949");
        case 950: return QStringLiteral("Big5");
        case 28591: return QStringLiteral("ISO-8859-1");
        case 28592: return QStringLiteral("ISO-8859-2");
        case 28593: return QStringLiteral("ISO-8859-3");
        case 28594: return QStringLiteral("ISO-8859-4");
        case 28595: return QStringLiteral("ISO-8859-5");
        case 28596: return QStringLiteral("ISO-8859-6");
        case 28597: return QStringLiteral("ISO-8859-7");
        case 28598: return QStringLiteral("ISO-8859-8");
        case 28599: return QStringLiteral("ISO-8859-9");
        case 28603: return QStringLiteral("ISO-8859-13");
        case 28605: return QStringLiteral("ISO-8859-15");
        default: return QStringLiteral("Windows-%1").arg(nCodePage);
    }
}

static bool wixIsAsciiInvariantCodePage(quint16 nCodePage)
{
    return ((nCodePage >= 1250) && (nCodePage <= 1258)) || ((nCodePage >= 28591) && (nCodePage <= 28599)) ||
           (nCodePage == 28603) || (nCodePage == 28605) || (nCodePage == 874) || (nCodePage == 932) ||
           (nCodePage == 936) || (nCodePage == 949) || (nCodePage == 950) || (nCodePage == 20127) ||
           (nCodePage == 65001);
}

static bool wixDecodeUtf16(const QByteArray &baData, QString *pResult, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pResult || (baData.size() & 1) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    QString sResult;
    sResult.reserve(baData.size() / 2);
    for (qint32 i = 0; i < baData.size(); i += 2) {
        if (((i & 0x1FFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        const quint16 nCharacter = wixReadLE16(baData, i);
        if ((nCharacter >= 0xD800) && (nCharacter <= 0xDBFF)) {
            if ((i + 3) >= baData.size()) return false;
            const quint16 nLow = wixReadLE16(baData, i + 2);
            if ((nLow < 0xDC00) || (nLow > 0xDFFF)) return false;
            sResult.append(QChar(nCharacter));
            sResult.append(QChar(nLow));
            i += 2;
        } else {
            if ((nCharacter == 0) || ((nCharacter >= 0xDC00) && (nCharacter <= 0xDFFF))) return false;
            sResult.append(QChar(nCharacter));
        }
    }

    *pResult = sResult;
    return true;
}

static bool wixDecodeAnsi(const QByteArray &baData, quint16 nCodePage, QString *pResult, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pResult || !nCodePage || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    if (nCodePage == 1200) return false;  // Unicode property sets must use VT_LPWSTR.

#if (QT_VERSION_MAJOR < 6) || defined(QT_CORE5COMPAT_LIB)
    QList<QByteArray> listNames;
    listNames.append(wixCodePageName(nCodePage).toLatin1());
    listNames.append(QByteArrayLiteral("CP") + QByteArray::number(nCodePage));
    for (const QByteArray &baName : listNames) {
        QTextCodec *pCodec = QTextCodec::codecForName(baName);
        if (!pCodec) continue;
        QTextCodec::ConverterState state(QTextCodec::ConvertInvalidToNull);
        const QString sResult = pCodec->toUnicode(baData.constData(), baData.size(), &state);
        if ((state.invalidChars == 0) && !sResult.contains(QChar(0))) {
            *pResult = sResult;
            return true;
        }
    }
#else
    if (nCodePage == 65001) {
        QStringDecoder decoder(QStringDecoder::Utf8);
        const QString sResult = decoder.decode(baData);
        if (!decoder.hasError() && !sResult.contains(QChar(0))) {
            *pResult = sResult;
            return true;
        }
    }
#endif

    // The WiX creating-application strings are ASCII. For explicitly known
    // ASCII-invariant code pages this remains an exact decode even in Qt 6
    // builds that do not provide QtCore5Compat.
    if (!wixIsAsciiInvariantCodePage(nCodePage)) return false;
    for (char ch : baData) {
        if ((quint8)ch > 0x7F) return false;
    }
    *pResult = QString::fromLatin1(baData);
    return true;
}

static bool wixReadCreatingApplication(const QByteArray &baSummary, QString *pResult, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pResult || !XBinary::isPdStructNotCanceled(pPdStruct) || (baSummary.size() < 48)) return false;
    pResult->clear();

    // PropertySetStream header, followed by exactly one SummaryInformation
    // FMTID/offset pair. SummaryInformation streams are single-property-set
    // streams; accepting additional sets would make PID 18 ambiguous.
    if ((wixReadLE16(baSummary, 0) != 0xFFFE) || (wixReadLE16(baSummary, 2) > 1) ||
        (wixReadLE32(baSummary, 24) != 1)) {
        return false;
    }
    const QByteArray baSummaryFmtid = QByteArray::fromHex("e0859ff2f94f6810ab9108002b27b3d9");
    if (baSummary.mid(28, 16) != baSummaryFmtid) return false;

    const quint32 nSetOffset = wixReadLE32(baSummary, 44);
    if ((nSetOffset < 48) || (nSetOffset & 3) || ((quint64)nSetOffset + 8 > (quint64)baSummary.size())) return false;

    const quint32 nSetSize = wixReadLE32(baSummary, (qint32)nSetOffset);
    const quint32 nProperties = wixReadLE32(baSummary, (qint32)nSetOffset + 4);
    const quint64 nDirectoryEnd = 8ull + (quint64)nProperties * 8ull;
    if ((nSetSize < 8) || (nSetSize & 3) || ((quint64)nSetOffset + nSetSize > (quint64)baSummary.size()) ||
        (nProperties > 65536) || (nDirectoryEnd > nSetSize)) {
        return false;
    }

    QList<WIX_PROPERTY_ENTRY> listProperties;
    QSet<quint32> setIDs;
    QSet<quint32> setOffsets;
    listProperties.reserve((qint32)nProperties);
    for (quint32 i = 0; i < nProperties; i++) {
        if (((i & 0x3FF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        const qint32 nEntryOffset = (qint32)((quint64)nSetOffset + 8 + (quint64)i * 8);
        WIX_PROPERTY_ENTRY entry = {};
        entry.nID = wixReadLE32(baSummary, nEntryOffset);
        entry.nOffset = wixReadLE32(baSummary, nEntryOffset + 4);
        if (setIDs.contains(entry.nID) || setOffsets.contains(entry.nOffset) || (entry.nOffset & 3) ||
            (entry.nOffset < nDirectoryEnd) || ((quint64)entry.nOffset + 4 > nSetSize)) {
            return false;
        }
        setIDs.insert(entry.nID);
        setOffsets.insert(entry.nOffset);
        listProperties.append(entry);
    }

    std::sort(listProperties.begin(), listProperties.end(), [](const WIX_PROPERTY_ENTRY &a, const WIX_PROPERTY_ENTRY &b) {
        return a.nOffset < b.nOffset;
    });

    qint32 nApplicationIndex = -1;
    qint32 nCodePageIndex = -1;
    for (qint32 i = 0; i < listProperties.size(); i++) {
        listProperties[i].nEnd = ((i + 1) < listProperties.size()) ? listProperties.at(i + 1).nOffset : nSetSize;
        if (listProperties.at(i).nID == 1) nCodePageIndex = i;   // PID_CODEPAGE
        if (listProperties.at(i).nID == 18) nApplicationIndex = i;  // PIDSI_APPNAME
    }
    if (nApplicationIndex < 0) return false;

    quint16 nCodePage = 0;
    if (nCodePageIndex >= 0) {
        const WIX_PROPERTY_ENTRY &entry = listProperties.at(nCodePageIndex);
        const quint32 nAbsolute = nSetOffset + entry.nOffset;
        if (((entry.nEnd - entry.nOffset) != 8) || (wixReadLE16(baSummary, (qint32)nAbsolute) != 2) ||
            (wixReadLE16(baSummary, (qint32)nAbsolute + 2) != 0) ||
            (wixReadLE16(baSummary, (qint32)nAbsolute + 6) != 0)) {
            return false;
        }
        nCodePage = wixReadLE16(baSummary, (qint32)nAbsolute + 4);
    }

    const WIX_PROPERTY_ENTRY &application = listProperties.at(nApplicationIndex);
    const quint32 nAbsolute = nSetOffset + application.nOffset;
    const quint32 nSpan = application.nEnd - application.nOffset;
    if ((nSpan < 12) || (wixReadLE16(baSummary, (qint32)nAbsolute + 2) != 0)) return false;

    const quint16 nType = wixReadLE16(baSummary, (qint32)nAbsolute);
    const quint32 nCharacters = wixReadLE32(baSummary, (qint32)nAbsolute + 4);
    if (!nCharacters) return false;

    if (nType == 30) {  // VT_LPSTR
        const quint64 nRawEnd = 8ull + nCharacters;
        const quint64 nPaddedEnd = (nRawEnd + 3) & ~3ull;
        if ((nPaddedEnd != nSpan) || !nCodePage || (baSummary.at((qint32)(nAbsolute + 8 + nCharacters - 1)) != 0) ||
            !wixIsZeroRange(baSummary, nAbsolute + 8 + nCharacters, nAbsolute + nSpan)) {
            return false;
        }
        const QByteArray baValue = baSummary.mid((qint32)nAbsolute + 8, (qint32)nCharacters - 1);
        if (baValue.contains('\0') || !wixDecodeAnsi(baValue, nCodePage, pResult, pPdStruct)) return false;
    } else if (nType == 31) {  // VT_LPWSTR
        const quint64 nBytes = (quint64)nCharacters * 2;
        const quint64 nRawEnd = 8ull + nBytes;
        const quint64 nPaddedEnd = (nRawEnd + 3) & ~3ull;
        if ((nPaddedEnd != nSpan) || (nBytes > 0x7FFFFFFF) ||
            (wixReadLE16(baSummary, (qint32)(nAbsolute + 8 + nBytes - 2)) != 0) ||
            !wixIsZeroRange(baSummary, nAbsolute + 8 + (quint32)nBytes, nAbsolute + nSpan)) {
            return false;
        }
        const QByteArray baValue = baSummary.mid((qint32)nAbsolute + 8, (qint32)nBytes - 2);
        if (!wixDecodeUtf16(baValue, pResult, pPdStruct)) return false;
    } else {
        return false;
    }

    return !pResult->isEmpty() && XBinary::isPdStructNotCanceled(pPdStruct);
}
}  // namespace

XWiX::XWiX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XWiX::~XWiX()
{
}

bool XWiX::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XWiX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XWiX x(pDevice);
    return x.isValid(pPdStruct);
}

XWiX::INTERNAL_INFO XWiX::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XWiX::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = INTERNAL_INFO();
        m_internalInfo = _getInternalInfo(pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            m_internalInfo = INTERNAL_INFO();
            return false;
        }
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            m_internalInfo = INTERNAL_INFO();
            return false;
        }
        setIsInternalInfoHandled(true);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XWiX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XWiX::setInternalInfo(void *pInternalInfo)
{
    if (pInternalInfo) {
        m_internalInfo = *static_cast<INTERNAL_INFO *>(pInternalInfo);
        setIsInternalInfoHandled(true);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    } else {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(false);
        XBinary::setInternalInfo(nullptr);
    }
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

    // Authenticate the authoring marker inside the one SummaryInformation
    // stream.  A raw whole-file search also sees strings in embedded cabinets
    // and lets an unrelated MSI payload impersonate WiX.
    QByteArray baSummary;
    XCFBF cfbf(getDevice());
    UNPACK_STATE state = {};
    if (!cfbf.initUnpack(&state, cfbf.getDefaultUnpackProperties(), pPdStruct)) return result;

    bool bSummaryFound = false;
    bool bStreamsValid = true;
    const QString sSummaryName = QString(QChar(5)) + QStringLiteral("SummaryInformation");
    for (qint32 i = 0; (i < state.nNumberOfRecords) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        ARCHIVERECORD record = cfbf.infoCurrent(&state, pPdStruct);
        const QString sName = record.mapProperties.value(FPART_PROP_ORIGINALNAME).toString();
        if (sName.compare(sSummaryName, Qt::CaseInsensitive) == 0) {
            if (bSummaryFound || (record.nStreamSize <= 0) || (record.nStreamSize > (16ll << 20))) {
                bStreamsValid = false;
                break;
            }

            QBuffer buffer(&baSummary);
            if (!buffer.open(QIODevice::ReadWrite) || !cfbf.unpackCurrent(&state, &buffer, pPdStruct) ||
                (baSummary.size() != record.nStreamSize)) {
                bStreamsValid = false;
                break;
            }
            bSummaryFound = true;
        }

        if (((i + 1) < state.nNumberOfRecords) && !cfbf.moveToNext(&state, pPdStruct)) {
            bStreamsValid = false;
            break;
        }
    }

    if (!cfbf.finishUnpack(&state, pPdStruct)) bStreamsValid = false;
    if (!bStreamsValid || !bSummaryFound || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    QString sApp;
    if (!wixReadCreatingApplication(baSummary, &sApp, pPdStruct) ||
        !(sApp.startsWith(QStringLiteral("Windows Installer XML")) || sApp.startsWith(QStringLiteral("WiX Toolset (")))) {
        return result;
    }

    result.bIsValid = true;

    // Version = the dotted number in parentheses after the app name.
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

QMap<XBinary::UNPACK_PROP, QVariant> XWiX::getDefaultUnpackProperties()
{
    return XBinary::getDefaultUnpackProperties();
}

bool XWiX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    if (pState->pContext && !finishUnpack(pState, pPdStruct)) return false;
    if (!XBinary::isPdStructNotCanceled(pPdStruct) || !_detect(pPdStruct).bIsValid) return false;

    *pState = UNPACK_STATE();
    pState->nTotalSize = getSize();
    pState->mapUnpackProperties = mapProperties;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pMSI = new XMSI(getDevice());
    pContext->state = UNPACK_STATE();

    if (!pContext->pMSI->initUnpack(&pContext->state, mapProperties, pPdStruct)) {
        delete pContext->pMSI;
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->state.nNumberOfRecords;
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XWiX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pMSI->infoCurrent(&pContext->state, pPdStruct);
}

bool XWiX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !XBinary::isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    return pContext->pMSI->unpackCurrent(&pContext->state, pDevice, pPdStruct);
}

bool XWiX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    pContext->state.nCurrentIndex = pState->nCurrentIndex;
    bool bResult = pContext->pMSI->moveToNext(&pContext->state, pPdStruct);
    pState->nCurrentIndex = pContext->state.nCurrentIndex;
    pState->nCurrentOffset = pContext->state.nCurrentOffset;
    return bResult;
}

bool XWiX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pContext->pMSI->finishUnpack(&pContext->state, pPdStruct)) {
            bResult = false;
        }
        delete pContext->pMSI;
        delete pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();
    return bResult;
}
