/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xboxedapp.h"

#include <cstring>
#include <zlib.h>

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
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XBoxedApp::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XBoxedApp x(pDevice);
    return x.isValid(pPdStruct);
}

XBoxedApp::INTERNAL_INFO XBoxedApp::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XBoxedApp::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(true);
        m_internalInfo = _getInternalInfo(pPdStruct);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XBoxedApp::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XBoxedApp::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XBoxedApp::getFileType()
{
    return FT_ARCHIVE;
}

XBoxedApp::INTERNAL_INFO XBoxedApp::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nBxpckOffset = -1;
    result.nMainOffset = -1;

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
            result.nBxpckOffset = (qint64)listSections.at(i).PointerToRawData;
            result.nBxpckSize = (qint64)listSections.at(i).SizeOfRawData;
        } else if (baName == ".main") {
            result.nMainOffset = (qint64)listSections.at(i).PointerToRawData;
            result.nMainSize = (qint64)listSections.at(i).SizeOfRawData;
        }
    }

    const qint64 nSize = getSize();
    if (!bBxpck || (result.nBxpckOffset < 0) || (result.nBxpckSize <= 0) ||
        (result.nBxpckOffset > nSize) || (result.nBxpckSize > nSize - result.nBxpckOffset) ||
        (result.nMainOffset < 0) || (result.nMainSize <= 0) ||
        (result.nMainOffset > nSize) || (result.nMainSize > nSize - result.nMainOffset)) {
        return result;
    }

    // BoxedApp-exclusive C++ symbol strings live in the ".main" engine section.
    if (find_ansiString(result.nMainOffset, result.nMainSize, "BoxedApp::", pPdStruct) == -1) return result;

    result.bIsValid = true;

    // Trial builds embed a UTF-16LE demo nag screen ("...demo version of BoxedApp...").
    QByteArray baNeedle;
    const char *pszDemo = "demo version of BoxedApp";
    for (const char *q = pszDemo; *q; ++q) {
        baNeedle.append(*q);
        baNeedle.append('\0');
    }
    if (find_array(result.nBxpckOffset, result.nBxpckSize, baNeedle.constData(), baNeedle.size(), pPdStruct) != -1) result.sVersion = "demo";

    return result;
}

static const qint64 BA_MAX_CONTAINER_SIZE = 512ll << 20;
static const qint64 BA_MAX_FILE_SIZE = 256ll << 20;
static const qint64 BA_MAX_TOTAL_OUTPUT = 512ll << 20;
static const qint32 BA_MAX_FILE_COUNT = 65536;

// zlib (78 xx) inflate bounded to the exact stored and expected output sizes.
static bool baInflate(const quint8 *pSrc, qint64 nSrcLen, qint64 nExpectedOutput, QByteArray *pOut, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || !pOut || (nSrcLen <= 0) || (nSrcLen > 0x7FFFFFFF) || (nExpectedOutput < 0) ||
        (nExpectedOutput > BA_MAX_FILE_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    z_stream s;
    memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, 15) != Z_OK) return false;
    s.next_in = (Bytef *)pSrc;
    s.avail_in = (uInt)nSrcLen;
    pOut->clear();
    char aBuf[65536];
    bool bOk = false;
    while (XBinary::isPdStructNotCanceled(pPdStruct)) {
        s.next_out = (Bytef *)aBuf;
        s.avail_out = sizeof(aBuf);
        int rc = inflate(&s, Z_NO_FLUSH);
        qint64 nProduced = (qint64)sizeof(aBuf) - s.avail_out;
        if ((nProduced < 0) || (nProduced > nExpectedOutput - pOut->size())) break;
        if (nProduced) pOut->append(aBuf, (int)nProduced);
        if (rc == Z_STREAM_END) {
            bOk = ((qint64)s.total_in == nSrcLen) && ((qint64)pOut->size() == nExpectedOutput);
            break;
        }
        if (rc != Z_OK) break;
        if ((s.avail_in == 0) && (s.avail_out == sizeof(aBuf))) break;
    }
    inflateEnd(&s);
    return bOk && XBinary::isPdStructNotCanceled(pPdStruct);
}

static inline quint32 baRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint16 baRd16(const quint8 *p)
{
    return (quint16)(p[0] | ((quint16)p[1] << 8));
}

static bool baIsSafeBaseName(const QString &sName)
{
    if (sName.isEmpty() || (sName.size() > 255) || (sName == ".") || (sName == "..") || sName.endsWith(' ') || sName.endsWith('.')) {
        return false;
    }

    static const QString sForbidden = QStringLiteral("<>:\"/\\|?*");
    for (QChar character : sName) {
        if (sForbidden.contains(character) || !character.isPrint()) return false;
    }

    const QString sStem = sName.section('.', 0, 0).toUpper();
    static const QSet<QString> setReserved = {
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),  QStringLiteral("NUL"),  QStringLiteral("COM1"),
        QStringLiteral("COM2"), QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"), QStringLiteral("COM6"),
        QStringLiteral("COM7"), QStringLiteral("COM8"), QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"), QStringLiteral("LPT6"), QStringLiteral("LPT7"),
        QStringLiteral("LPT8"), QStringLiteral("LPT9")};
    return !setReserved.contains(sStem);
}

static QString baReadName(const quint8 *p, qint64 nStart, qint64 nLimit)
{
    QString sResult;
    bool bTerminated = false;
    for (qint64 i = nStart; i + 2 <= nLimit; i += 2) {
        quint16 nChar = baRd16(p + i);
        if (nChar == 0) {
            bTerminated = true;
            break;
        }
        if ((nChar < 0x20) || (nChar == 0x7F)) return QString();
        sResult.append(QChar(nChar));
        if (sResult.size() > 260) return QString();
    }

    if (!bTerminated) return QString();
    int nSlash = qMax(sResult.lastIndexOf('/'), sResult.lastIndexOf('\\'));
    if (nSlash >= 0) sResult = sResult.mid(nSlash + 1);
    return baIsSafeBaseName(sResult) ? sResult : QString();
}

// Scan a VFS region for file nodes. Each node has a small offset table; the
// final two offsets point to the UTF-16 file name and its data slot. Compressed
// nodes put a 32-byte identity hash, a padding WORD, and the familiar
// [WORD 0x0010][DWORD method][DWORD 0][DWORD size] record in that slot. STORE
// nodes put the raw bytes directly at the slot.
bool XBoxedApp::_scanRecords(const QByteArray &baRegion, UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext || (baRegion.size() > BA_MAX_CONTAINER_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    const quint8 *p = (const quint8 *)baRegion.constData();
    const qint64 n = baRegion.size();

    for (qint64 pos = 0; pos + 0x56 <= n;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        quint32 nNodeSize = baRd32(p + pos);
        if ((baRd16(p + pos + 4) != 5) || (baRd32(p + pos + 6) != 0xFFFFFFFFU) || (nNodeSize < 0x56) ||
            ((qint64)nNodeSize > n - pos)) {
            pos++;
            continue;
        }

        quint32 nOriginalSize = baRd32(p + pos + 0x2A);
        quint32 anOffsets[5];
        bool bOffsetsValid = (nOriginalSize <= (quint32)BA_MAX_FILE_SIZE);
        for (int i = 0; i < 5; i++) {
            anOffsets[i] = baRd32(p + pos + 0x3E + i * 4);
            if ((anOffsets[i] < 0x50) || ((i < 4) && (anOffsets[i] >= nNodeSize)) ||
                ((i == 4) && (anOffsets[i] > nNodeSize)) || ((i > 0) && (anOffsets[i] < anOffsets[i - 1]))) {
                bOffsetsValid = false;
            }
        }
        if (!bOffsetsValid) {
            pos++;
            continue;
        }

        QString sName = baReadName(p, pos + anOffsets[3], pos + anOffsets[4]);
        if (sName.isEmpty()) {
            pos++;
            continue;
        }

        qint64 nNodeEnd = pos + nNodeSize;
        qint64 nDataSlot = pos + anOffsets[4];
        QByteArray baOut;
        bool bOk = false;

        qint64 nMarker = nDataSlot + 34;
        bool bCompressedRecord = false;
        if ((nMarker + 14 <= nNodeEnd) && (baRd16(p + nMarker) == 0x0010)) {
            quint32 nMethod = baRd32(p + nMarker + 2);
            quint32 nReserved = baRd32(p + nMarker + 6);
            quint32 nStoredSize = baRd32(p + nMarker + 10);
            qint64 nContent = nMarker + 14;
            if ((nReserved == 0) && (nMethod <= 1) && ((qint64)nStoredSize == nNodeEnd - nContent)) {
                bCompressedRecord = true;
                if (nMethod == 0) {
                    if (nStoredSize == nOriginalSize) {
                        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
                        baOut = QByteArray((const char *)p + nContent, (int)nStoredSize);
                        bOk = true;
                    }
                } else if ((nStoredSize > 0) && (p[nContent] == 0x78)) {
                    bOk = baInflate(p + nContent, nStoredSize, nOriginalSize, &baOut, pPdStruct);
                }
            }
        }
        if (!bCompressedRecord && ((qint64)nOriginalSize == nNodeEnd - nDataSlot)) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            baOut = QByteArray((const char *)p + nDataSlot, (int)nOriginalSize);
            bOk = true;
        }

        if (bOk && ((quint32)baOut.size() == nOriginalSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            if ((pContext->listEntries.size() >= BA_MAX_FILE_COUNT) ||
                ((qint64)baOut.size() > BA_MAX_TOTAL_OUTPUT - pContext->nTotalOutput)) {
                return false;
            }

            const QString sNameKey = sName.toCaseFolded();
            if (pContext->setNames.contains(sNameKey)) return false;

            FILE_ENTRY e;
            e.sName = sName;
            e.baData = baOut;
            pContext->listEntries.append(e);
            pContext->setNames.insert(sNameKey);
            pContext->nTotalOutput += baOut.size();
            pos = nNodeEnd;
        } else {
            // At this point the node header, offsets, and name have all been
            // authenticated. A bad payload is corruption, not a scan miss.
            return false;
        }
    }

    return XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XBoxedApp::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    auto scanRegion = [this, pContext, pPdStruct](qint64 nOffset, qint64 nSize) -> bool {
        if ((nOffset < 0) || (nSize <= 0) || (nSize > BA_MAX_CONTAINER_SIZE) || (nOffset > getSize()) || (nSize > getSize() - nOffset) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }

        QByteArray baRegion = read_array_process(nOffset, nSize, pPdStruct);
        return (baRegion.size() == nSize) && XBinary::isPdStructNotCanceled(pPdStruct) && _scanRecords(baRegion, pContext, pPdStruct);
    };

    if ((info.nBxpckOffset >= 0) && (info.nBxpckSize > 0)) {
        if (!scanRegion(info.nBxpckOffset, info.nBxpckSize)) {
            delete pContext;
            return false;
        }
    }
    if ((info.nMainOffset >= 0) && (info.nMainSize > 0)) {
        if (!scanRegion(info.nMainOffset, info.nMainSize)) {
            delete pContext;
            return false;
        }
    }
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XBoxedApp::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return result;

    const FILE_ENTRY &e = pContext->listEntries.at(nIndex);
    result.nStreamSize = e.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = e.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)e.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;
    return result;
}

bool XBoxedApp::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return false;

    const QByteArray &baData = pContext->listEntries.at(nIndex).baData;
    qint64 nWritten = 0;
    pState->nCurrentOffset = 0;
    while (nWritten < baData.size()) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        qint64 nChunk = qMin<qint64>(1ll << 20, baData.size() - nWritten);
        qint64 nResult = pDevice->write(baData.constData() + nWritten, nChunk);
        if ((nResult <= 0) || (nResult > nChunk)) return false;
        nWritten += nResult;
        pState->nCurrentOffset = nWritten;
    }

    return XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XBoxedApp::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XBoxedApp::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState) return false;
    if (pState->pContext) {
        delete (UNPACK_CONTEXT *)pState->pContext;
        pState->pContext = nullptr;
    }
    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    return true;
}
