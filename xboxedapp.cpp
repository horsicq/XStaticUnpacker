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
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
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

static const qint64 BA_MAX_CONTAINER_SIZE = 512ll << 20;
static const qint64 BA_MAX_FILE_SIZE = 256ll << 20;
static const qint64 BA_MAX_TOTAL_OUTPUT = 512ll << 20;
static const qint32 BA_MAX_FILE_COUNT = 65536;

XBoxedApp::INTERNAL_INFO XBoxedApp::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nBxpckOffset = -1;
    result.nMainOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    qint32 nBxpckSections = 0;
    qint32 nMainSections = 0;
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".bxpck") {
            nBxpckSections++;
            result.nBxpckOffset = (qint64)listSections.at(i).PointerToRawData;
            result.nBxpckSize = (qint64)listSections.at(i).SizeOfRawData;
        } else if (baName == ".main") {
            nMainSections++;
            result.nMainOffset = (qint64)listSections.at(i).PointerToRawData;
            result.nMainSize = (qint64)listSections.at(i).SizeOfRawData;
        }
    }

    const qint64 nSize = getSize();
    if ((nBxpckSections != 1) || (nMainSections != 1) || (result.nBxpckOffset < 0) || (result.nBxpckSize <= 0) ||
        (result.nBxpckOffset > nSize) || (result.nBxpckSize > nSize - result.nBxpckOffset) ||
        (result.nMainOffset < 0) || (result.nMainSize <= 0) ||
        (result.nMainOffset > nSize) || (result.nMainSize > nSize - result.nMainOffset) ||
        (result.nBxpckSize > BA_MAX_CONTAINER_SIZE) || (result.nMainSize > BA_MAX_CONTAINER_SIZE) ||
        (result.nBxpckSize > BA_MAX_CONTAINER_SIZE - result.nMainSize)) {
        return result;
    }

    const qint64 nBxpckEnd = result.nBxpckOffset + result.nBxpckSize;
    const qint64 nMainEnd = result.nMainOffset + result.nMainSize;
    if ((result.nBxpckOffset < nMainEnd) && (result.nMainOffset < nBxpckEnd)) return result;

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

    QString sStem = sName.section('.', 0, 0).toUpper();
    sStem.replace(QChar(0x00B9), QLatin1Char('1'));
    sStem.replace(QChar(0x00B2), QLatin1Char('2'));
    sStem.replace(QChar(0x00B3), QLatin1Char('3'));
    static const QSet<QString> setReserved = {
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),  QStringLiteral("NUL"),  QStringLiteral("COM1"),
        QStringLiteral("COM2"), QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"), QStringLiteral("COM6"),
        QStringLiteral("COM7"), QStringLiteral("COM8"), QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"), QStringLiteral("LPT6"), QStringLiteral("LPT7"),
        QStringLiteral("LPT8"), QStringLiteral("LPT9"), QStringLiteral("CONIN$"), QStringLiteral("CONOUT$"), QStringLiteral("CLOCK$")};
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

struct BA_NODE_METADATA {
    qint64 nEnd;
    qint64 nDataSlot;
    quint32 nOriginalSize;
    QString sName;
};

static QString baNameKey(const QString &sName)
{
    return sName.toCaseFolded().normalized(QString::NormalizationForm_C);
}

static bool baReadNodeMetadata(const QByteArray &baRegion, qint64 nPosition, BA_NODE_METADATA *pResult)
{
    if (!pResult || (nPosition < 0) || ((baRegion.size() - nPosition) < 0x56)) return false;

    const quint8 *p = (const quint8 *)baRegion.constData();
    const quint32 nNodeSize = baRd32(p + nPosition);
    if ((baRd16(p + nPosition + 4) != 5) || (baRd32(p + nPosition + 6) != 0xFFFFFFFFU) || (nNodeSize < 0x56) ||
        ((qint64)nNodeSize > baRegion.size() - nPosition)) {
        return false;
    }

    const quint32 nOriginalSize = baRd32(p + nPosition + 0x2A);
    quint32 anOffsets[5];
    bool bOffsetsValid = (nOriginalSize <= (quint32)BA_MAX_FILE_SIZE);
    for (qint32 i = 0; i < 5; i++) {
        anOffsets[i] = baRd32(p + nPosition + 0x3E + i * 4);
        if ((anOffsets[i] < 0x50) || ((i < 4) && (anOffsets[i] >= nNodeSize)) ||
            ((i == 4) && (anOffsets[i] > nNodeSize)) || ((i > 0) && (anOffsets[i] < anOffsets[i - 1]))) {
            bOffsetsValid = false;
        }
    }
    if (!bOffsetsValid) return false;

    const QString sName = baReadName(p, nPosition + anOffsets[3], nPosition + anOffsets[4]);
    if (sName.isEmpty()) return false;

    pResult->nEnd = nPosition + nNodeSize;
    pResult->nDataSlot = nPosition + anOffsets[4];
    pResult->nOriginalSize = nOriginalSize;
    pResult->sName = sName;
    return true;
}

static bool baCollectDeclaredNames(const QByteArray &baRegion, QSet<QString> *pSetNames, qint32 *pnRecords,
                                   XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSetNames || !pnRecords || (baRegion.size() > BA_MAX_CONTAINER_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    for (qint64 nPosition = 0; (nPosition + 0x56) <= baRegion.size();) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        BA_NODE_METADATA node = {};
        if (!baReadNodeMetadata(baRegion, nPosition, &node)) {
            nPosition++;
            continue;
        }
        if (++(*pnRecords) > BA_MAX_FILE_COUNT) return false;
        pSetNames->insert(baNameKey(node.sName));
        nPosition = node.nEnd;
    }

    return true;
}

static QString baUniqueOutputName(const QString &sPreferred, qint32 nRecordIndex, const QSet<QString> &setDeclaredNames,
                                  QSet<QString> *pSetAssignedNames)
{
    if (!pSetAssignedNames || sPreferred.isEmpty() || (nRecordIndex < 0)) return QString();

    const QString sPreferredKey = baNameKey(sPreferred);
    if (!pSetAssignedNames->contains(sPreferredKey)) {
        pSetAssignedNames->insert(sPreferredKey);
        return sPreferred;
    }

    const QString sBase = QString("file_%1").arg(nRecordIndex, 4, 10, QChar('0'));
    for (qint32 i = 0; i <= BA_MAX_FILE_COUNT; i++) {
        const QString sCandidate = (i == 0) ? sBase : QString("%1_%2").arg(sBase).arg(i);
        const QString sCandidateKey = baNameKey(sCandidate);
        if (!setDeclaredNames.contains(sCandidateKey) && !pSetAssignedNames->contains(sCandidateKey)) {
            pSetAssignedNames->insert(sCandidateKey);
            return sCandidate;
        }
    }

    return QString();
}

// Scan a VFS region for file nodes. Each node has a small offset table; the
// final two offsets point to the UTF-16 file name and its data slot. Compressed
// nodes put a 32-byte identity hash, a padding WORD, and the familiar
// [WORD 0x0010][DWORD method][DWORD 0][DWORD size] record in that slot. STORE
// nodes put the raw bytes directly at the slot.
bool XBoxedApp::_scanRecords(const QByteArray &baRegion, const QSet<QString> &setDeclaredNames, UNPACK_CONTEXT *pContext,
                             PDSTRUCT *pPdStruct)
{
    if (!pContext || (baRegion.size() > BA_MAX_CONTAINER_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    const quint8 *p = (const quint8 *)baRegion.constData();
    const qint64 n = baRegion.size();

    for (qint64 pos = 0; pos + 0x56 <= n;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        BA_NODE_METADATA node = {};
        if (!baReadNodeMetadata(baRegion, pos, &node)) {
            pos++;
            continue;
        }

        if ((pContext->listEntries.size() >= BA_MAX_FILE_COUNT) ||
            ((qint64)node.nOriginalSize > BA_MAX_TOTAL_OUTPUT - pContext->nTotalOutput)) {
            return false;
        }
        const QString sName = baUniqueOutputName(node.sName, pContext->listEntries.size(), setDeclaredNames, &pContext->setNames);
        if (sName.isEmpty()) return false;

        const qint64 nNodeEnd = node.nEnd;
        const qint64 nDataSlot = node.nDataSlot;
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
                    if (nStoredSize == node.nOriginalSize) {
                        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
                        baOut = QByteArray((const char *)p + nContent, (int)nStoredSize);
                        bOk = true;
                    }
                } else if ((nStoredSize > 0) && (p[nContent] == 0x78)) {
                    bOk = baInflate(p + nContent, nStoredSize, node.nOriginalSize, &baOut, pPdStruct);
                }
            }
        }
        if (!bCompressedRecord && ((qint64)node.nOriginalSize == nNodeEnd - nDataSlot)) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            baOut = QByteArray((const char *)p + nDataSlot, (int)node.nOriginalSize);
            bOk = true;
        }

        if (bOk && ((quint32)baOut.size() == node.nOriginalSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            FILE_ENTRY e;
            e.sName = sName;
            e.baData = baOut;
            pContext->listEntries.append(e);
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
    if (pState->pContext && !finishUnpack(pState, pPdStruct)) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;
    pState->mapArchiveProperties.clear();

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    auto readRegion = [this, pPdStruct](qint64 nOffset, qint64 nSize, QByteArray *pRegion) -> bool {
        if (!pRegion || (nOffset < 0) || (nSize <= 0) || (nSize > BA_MAX_CONTAINER_SIZE) || (nOffset > getSize()) ||
            (nSize > getSize() - nOffset) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }
        *pRegion = read_array_process(nOffset, nSize, pPdStruct);
        return (pRegion->size() == nSize) && XBinary::isPdStructNotCanceled(pPdStruct);
    };
    QSet<QString> setDeclaredNames;
    qint32 nDeclaredRecords = 0;
    auto collectRegion = [&readRegion, &setDeclaredNames, &nDeclaredRecords, pPdStruct](qint64 nOffset, qint64 nSize) -> bool {
        QByteArray baRegion;
        return readRegion(nOffset, nSize, &baRegion) &&
               baCollectDeclaredNames(baRegion, &setDeclaredNames, &nDeclaredRecords, pPdStruct);
    };
    auto scanRegion = [this, &readRegion, &setDeclaredNames, pContext, pPdStruct](qint64 nOffset, qint64 nSize) -> bool {
        if ((nOffset < 0) || (nSize <= 0) || (nSize > BA_MAX_CONTAINER_SIZE) || (nOffset > getSize()) || (nSize > getSize() - nOffset) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }

        QByteArray baRegion;
        return readRegion(nOffset, nSize, &baRegion) && _scanRecords(baRegion, setDeclaredNames, pContext, pPdStruct);
    };

    if ((info.nBxpckOffset >= 0) && (info.nBxpckSize > 0)) {
        if (!collectRegion(info.nBxpckOffset, info.nBxpckSize)) {
            delete pContext;
            return false;
        }
    }
    if ((info.nMainOffset >= 0) && (info.nMainSize > 0)) {
        if (!collectRegion(info.nMainOffset, info.nMainSize)) {
            delete pContext;
            return false;
        }
    }
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
    if (!XBinary::isPdStructNotCanceled(pPdStruct) || (nDeclaredRecords <= 0) ||
        (pContext->listEntries.size() != nDeclaredRecords)) {
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XBoxedApp::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;
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
    if (!pDevice->isSequential() && (!pDevice->seek(0) || ((pDevice->size() != 0) && !XBinary::resize(pDevice, 0)))) return false;
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
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();
    return true;
}
