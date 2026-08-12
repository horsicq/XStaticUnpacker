/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xenigmavb.h"

#include <QSet>

#include <cstring>
#include <limits>
#include <memory>
#include <new>

#include "xpe.h"

namespace {

const qint64 EVB_MAX_CONTAINER_SIZE = 512ll << 20;
const qint64 EVB_MAX_FILE_SIZE = 256ll << 20;
const qint64 EVB_MAX_TOTAL_OUTPUT = 512ll << 20;
const qint32 EVB_MAX_NODE_COUNT = 100000;
const qint32 EVB_MAX_TREE_DEPTH = 1024;
const qint32 EVB_MAX_NAME_CHARS = 255;

bool evbIsRangeValid(qint64 nOffset, qint64 nSize, qint64 nTotalSize)
{
    return (nOffset >= 0) && (nSize >= 0) && (nTotalSize >= 0) && (nOffset <= nTotalSize) && (nSize <= nTotalSize - nOffset);
}

}  // namespace

XEnigmaVB::XEnigmaVB(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XEnigmaVB::~XEnigmaVB()
{
}

bool XEnigmaVB::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XEnigmaVB::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XEnigmaVB x(pDevice);
    return x.isValid(pPdStruct);
}

XEnigmaVB::INTERNAL_INFO XEnigmaVB::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XEnigmaVB::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *XEnigmaVB::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XEnigmaVB::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XEnigmaVB::getFileType()
{
    return FT_ARCHIVE;
}

XEnigmaVB::INTERNAL_INFO XEnigmaVB::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nMagicOffset = -1;
    result.nBaseOffset = -1;
    result.nBaseSize = -1;
    result.nTreeSize = -1;

    if (!getDevice() || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;
    const qint64 nFileSize = getSize();
    if (nFileSize <= 0) return result;
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    bool bEnigma1 = false, bEnigma2 = false;
    qint64 nE1Raw = -1, nE1Size = 0;
    qint64 nE2Raw = -1, nE2Size = 0;
    for (int i = 0; i < listSections.size(); i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return result;

        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".enigma1") {
            if (bEnigma1) return result;  // Ambiguous package boundary.
            bEnigma1 = true;
            nE1Raw = (qint64)listSections.at(i).PointerToRawData;
            nE1Size = (qint64)listSections.at(i).SizeOfRawData;
        } else if (baName == ".enigma2") {
            if (bEnigma2) return result;
            bEnigma2 = true;
            nE2Raw = (qint64)listSections.at(i).PointerToRawData;
            nE2Size = (qint64)listSections.at(i).SizeOfRawData;
            if ((nE2Size <= 0) || !evbIsRangeValid(nE2Raw, nE2Size, nFileSize)) return result;
        }
    }

    if (!bEnigma1 || !bEnigma2 || (nE1Size < 0x53) || !evbIsRangeValid(nE1Raw, nE1Size, nFileSize) ||
        (nE2Raw < nE1Raw + nE1Size)) {
        return result;
    }
    const qint64 nContainerSize = nE2Raw + nE2Size - nE1Raw;
    if ((nContainerSize < nE1Size) || (nContainerSize > EVB_MAX_CONTAINER_SIZE)) return result;

    // "EVB\0" package header inside .enigma1.
    qint64 nMagic = find_array(nE1Raw, nE1Size, "\x45\x56\x42\x00", 4, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) || (nMagic < nE1Raw) || (nMagic > nE1Raw + nE1Size - 0x53)) return result;

    QByteArray baHeader = read_array_process(nMagic, 0x53, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) || (baHeader.size() != 0x53) || (baHeader.left(4) != QByteArray("EVB\0", 4))) return result;

    const quint8 *pHeader = reinterpret_cast<const quint8 *>(baHeader.constData());
    quint32 nTopCount =
        (quint32)(pHeader[0x4C] | ((quint32)pHeader[0x4D] << 8) | ((quint32)pHeader[0x4E] << 16) | ((quint32)pHeader[0x4F] << 24));
    if (nTopCount > (quint32)EVB_MAX_NODE_COUNT) return result;

    result.bIsValid = true;
    result.nMagicOffset = nMagic;
    result.nBaseOffset = nE1Raw;
    result.nBaseSize = nContainerSize;
    result.nTreeSize = nE1Size;

    // Package-format version: little-endian dword at EVB magic + 0x14.
    quint32 nFmt =
        (quint32)(pHeader[0x14] | ((quint32)pHeader[0x15] << 8) | ((quint32)pHeader[0x16] << 16) | ((quint32)pHeader[0x17] << 24));
    if (nFmt && (nFmt < 0x1000)) result.sVersion = QString("package v%1").arg(nFmt);

    return result;
}

// ---------------------------------------------------------------------------
// extraction (EVB virtual-filesystem tree; STORED files carved verbatim)
// ---------------------------------------------------------------------------

static inline quint16 evbRd16(const quint8 *p)
{
    return (quint16)(p[0] | ((quint16)p[1] << 8));
}
static inline quint32 evbRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}
static inline quint64 evbRd64(const quint8 *p)
{
    quint64 v = 0;
    for (int i = 0; i < 8; i++) v |= ((quint64)p[i]) << (8 * i);
    return v;
}

static bool evbIsSafeBaseName(const QString &sName)
{
    if (sName.isEmpty() || (sName.size() > EVB_MAX_NAME_CHARS) || (sName == ".") || (sName == "..") || sName.endsWith(' ') ||
        sName.endsWith('.')) {
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
        QStringLiteral("LPT8"), QStringLiteral("LPT9"), QStringLiteral("COM\u00B9"), QStringLiteral("COM\u00B2"),
        QStringLiteral("COM\u00B3"), QStringLiteral("LPT\u00B9"), QStringLiteral("LPT\u00B2"), QStringLiteral("LPT\u00B3"),
        QStringLiteral("CONIN$"), QStringLiteral("CONOUT$"), QStringLiteral("CLOCK$")};
    return !setReserved.contains(sStem);
}

static QString evbUniqueOutputName(const QString &sParsedName, qint32 nRecordIndex, QSet<QString> *pSetNames)
{
    if (!pSetNames || (nRecordIndex < 0)) return QString();

    QString sResult = evbIsSafeBaseName(sParsedName) ? sParsedName : QString("file_%1").arg(nRecordIndex, 4, 10, QChar('0'));
    QString sKey = sResult.toCaseFolded().normalized(QString::NormalizationForm_C);
    if (!pSetNames->contains(sKey)) {
        pSetNames->insert(sKey);
        return sResult;
    }

    const QString sFallback = QString("file_%1").arg(nRecordIndex, 4, 10, QChar('0'));
    for (qint32 i = 1; i <= EVB_MAX_NODE_COUNT; i++) {
        sResult = (i == 1) ? sFallback : QString("%1_%2").arg(sFallback).arg(i);
        sKey = sResult.toCaseFolded().normalized(QString::NormalizationForm_C);
        if (!pSetNames->contains(sKey)) {
            pSetNames->insert(sKey);
            return sResult;
        }
    }

    return QString();
}

static bool evbCopyStored(const quint8 *pSrc, qint64 nSize, QByteArray *pOut, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pOut || (!pSrc && (nSize != 0)) || (nSize < 0) || (nSize > EVB_MAX_FILE_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    pOut->clear();
    pOut->reserve((int)nSize);
    qint64 nPosition = 0;
    while (nPosition < nSize) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        const qint64 nChunk = qMin<qint64>(1ll << 20, nSize - nPosition);
        pOut->append(reinterpret_cast<const char *>(pSrc + nPosition), (int)nChunk);
        nPosition += nChunk;
    }

    return ((qint64)pOut->size() == nSize) && XBinary::isPdStructNotCanceled(pPdStruct);
}

// aPLib depacker (Joergen Ibsen's public-domain aP_depack algorithm). EVB stores
// each compressed file as [qword header_len=12][dword stream_len][aPLib stream].
// A decode is accepted only after its end marker, exact input consumption, and
// exact declared output size have all been observed.
static bool evbAplibDepack(const quint8 *pSrc, qint64 nSrcLen, qint64 nExpectedOutput, QByteArray *pOut, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || !pOut || (nSrcLen <= 0) || (nExpectedOutput <= 0) || (nExpectedOutput > EVB_MAX_FILE_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    pOut->clear();
    pOut->reserve((int)nExpectedOutput);

    qint64 nPos = 0;
    quint8 nTag = 0;
    qint32 nBitCount = 0;

    auto getBit = [&]() -> qint32 {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return -1;
        if (nBitCount == 0) {
            if (nPos >= nSrcLen) return -1;
            nTag = pSrc[nPos++];
            nBitCount = 8;
        }
        const qint32 nBit = (nTag >> 7) & 1;
        nTag = (quint8)(nTag << 1);
        nBitCount--;
        return nBit;
    };

    auto getGamma = [&](quint64 *pnValue) -> bool {
        if (!pnValue) return false;
        quint64 nValue = 1;
        for (;;) {
            const qint32 nBit = getBit();
            if (nBit < 0) return false;
            if (nValue > ((quint64)EVB_MAX_FILE_SIZE - (quint64)nBit) / 2) return false;
            nValue = nValue * 2 + (quint64)nBit;
            const qint32 nContinue = getBit();
            if (nContinue < 0) return false;
            if (!nContinue) break;
        }
        *pnValue = nValue;
        return true;
    };

    auto appendByte = [&](quint8 nByte) -> bool {
        if ((qint64)pOut->size() >= nExpectedOutput) return false;
        pOut->append((char)nByte);
        return true;
    };

    auto copyMatch = [&](quint64 nOffset, quint64 nLength) -> bool {
        if ((nOffset == 0) || (nOffset > (quint64)pOut->size()) || (nLength > (quint64)(nExpectedOutput - pOut->size()))) {
            return false;
        }
        for (quint64 i = 0; i < nLength; i++) {
            if (((i & 0x3FFFU) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            pOut->append(pOut->at(pOut->size() - (int)nOffset));
        }
        return true;
    };

    if (!appendByte(pSrc[nPos++])) return false;

    quint64 nR0 = 0;
    qint32 nLwm = 0;
    bool bDone = false;

    while (!bDone && XBinary::isPdStructNotCanceled(pPdStruct)) {
        const qint32 b0 = getBit();
        if (b0 < 0) return false;
        if (b0) {
            const qint32 b1 = getBit();
            if (b1 < 0) return false;
            if (b1) {
                const qint32 b2 = getBit();
                if (b2 < 0) return false;
                if (b2) {
                    quint64 nOffset = 0;
                    for (qint32 i = 0; i < 4; i++) {
                        const qint32 nBit = getBit();
                        if (nBit < 0) return false;
                        nOffset = nOffset * 2 + (quint64)nBit;
                    }
                    if (nOffset) {
                        if (!copyMatch(nOffset, 1)) return false;
                    } else if (!appendByte(0)) {
                        return false;
                    }
                    nLwm = 0;
                } else {
                    if (nPos >= nSrcLen) return false;
                    const quint8 nByte = pSrc[nPos++];
                    const quint64 nLength = 2 + (nByte & 1);
                    const quint64 nOffset = nByte >> 1;
                    if (nOffset == 0) {
                        bDone = true;
                    } else if (!copyMatch(nOffset, nLength)) {
                        return false;
                    }
                    nR0 = nOffset;
                    nLwm = 1;
                }
            } else {
                quint64 nOffsetCode = 0;
                if (!getGamma(&nOffsetCode)) return false;

                if ((nLwm == 0) && (nOffsetCode == 2)) {
                    quint64 nLength = 0;
                    if (!getGamma(&nLength) || !copyMatch(nR0, nLength)) return false;
                } else {
                    const quint64 nDelta = (nLwm == 0) ? 3 : 2;
                    if ((nOffsetCode < nDelta) || (nPos >= nSrcLen)) return false;
                    const quint64 nOffsetHigh = nOffsetCode - nDelta;
                    if (nOffsetHigh > (quint64)EVB_MAX_FILE_SIZE / 256) return false;
                    const quint64 nOffset = nOffsetHigh * 256 + pSrc[nPos++];

                    quint64 nLength = 0;
                    if (!getGamma(&nLength)) return false;
                    if (nOffset >= 32000) nLength++;
                    if (nOffset >= 1280) nLength++;
                    if (nOffset < 128) nLength += 2;
                    if (!copyMatch(nOffset, nLength)) return false;
                    nR0 = nOffset;
                }
                nLwm = 1;
            }
        } else {
            if (nPos >= nSrcLen || !appendByte(pSrc[nPos++])) return false;
            nLwm = 0;
        }
    }

    return bDone && (nPos == nSrcLen) && ((qint64)pOut->size() == nExpectedOutput) &&
           XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XEnigmaVB::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    if (pState->pContext && !finishUnpack(pState, nullptr)) return false;
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapArchiveProperties.clear();

    try {
        pState->mapUnpackProperties = mapProperties;

        const INTERNAL_INFO info = _detect(pPdStruct);
        if (!info.bIsValid || (info.nMagicOffset < 0) || (info.nBaseOffset < 0) || (info.nTreeSize < 0x53) ||
            (info.nBaseSize < info.nTreeSize) ||
            (info.nBaseSize > EVB_MAX_CONTAINER_SIZE) || (info.nBaseSize > (std::numeric_limits<int>::max)()) ||
            !evbIsRangeValid(info.nBaseOffset, info.nBaseSize, getSize()) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }

        std::unique_ptr<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
        const QByteArray baBuf = read_array_process(info.nBaseOffset, info.nBaseSize, pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct) || ((qint64)baBuf.size() != info.nBaseSize)) return false;

        const quint8 *p = reinterpret_cast<const quint8 *>(baBuf.constData());
        const qint64 nTreeLimit = info.nTreeSize;
        const qint64 nMagicIdx = info.nMagicOffset - info.nBaseOffset;
        if ((nMagicIdx < 0) || (nMagicIdx > nTreeLimit - 0x53) || (memcmp(p + nMagicIdx, "EVB\0", 4) != 0)) return false;

        const quint32 nTopCount = evbRd32(p + nMagicIdx + 0x4C);
        if (nTopCount > (quint32)EVB_MAX_NODE_COUNT) return false;

        // Pre-order walk of the node tree, collecting every declared file.
        struct TmpRec {
            QString sName;
            quint64 nOrig;
            quint64 nStored;
        };
        QList<TmpRec> listTmp;
        QList<quint32> stackRemaining;
        if (nTopCount) stackRemaining.append(nTopCount);

        qint64 nCursor = nMagicIdx + 0x53;
        qint32 nScheduledNodes = (qint32)nTopCount;
        qint32 nParsedNodes = 0;
        QSet<quint32> setNodeIds;

        while (!stackRemaining.isEmpty()) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            if (stackRemaining.last() == 0) {
                stackRemaining.removeLast();
                continue;
            }
            stackRemaining.last()--;

            if ((nParsedNodes >= nScheduledNodes) || (nParsedNodes >= EVB_MAX_NODE_COUNT) || (nCursor < 0) ||
                (nTreeLimit - nCursor < 12)) {
                return false;
            }
            nParsedNodes++;

            const quint32 nNodeId = evbRd32(p + nCursor);
            const quint32 nType = evbRd32(p + nCursor + 4);
            const quint32 nChildren = evbRd32(p + nCursor + 8);
            if (setNodeIds.contains(nNodeId)) return false;
            setNodeIds.insert(nNodeId);
            nCursor += 12;

            // UTF-16LE NUL-terminated node name.
            QString sName;
            sName.reserve(64);
            bool bTerminated = false;
            while (nTreeLimit - nCursor >= 2) {
                if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
                const quint16 nCharacter = evbRd16(p + nCursor);
                nCursor += 2;
                if (nCharacter == 0) {
                    bTerminated = true;
                    break;
                }
                if (sName.size() >= EVB_MAX_NAME_CHARS) return false;
                sName.append(QChar(nCharacter));
            }
            if (!bTerminated) return false;

            if (nType == 1) {  // directory
                if ((nCursor < 0) || (nTreeLimit - nCursor < 30)) return false;
                nCursor += 30;  // word + 3x FILETIME(8) + dword

                if (nChildren > (quint32)(EVB_MAX_NODE_COUNT - nScheduledNodes)) return false;
                nScheduledNodes += (qint32)nChildren;
                if (nChildren) {
                    if (stackRemaining.size() >= EVB_MAX_TREE_DEPTH) return false;
                    stackRemaining.append(nChildren);
                }
            } else if (nType == 2) {  // file
                if ((nChildren != 0) || (nCursor < 0) || (nTreeLimit - nCursor < 58) || (listTmp.size() >= EVB_MAX_NODE_COUNT)) {
                    return false;
                }

                nCursor += 3;  // word + byte
                const quint64 nOrig = evbRd64(p + nCursor);
                nCursor += 8;
                nCursor += 39;  // 3x FILETIME(24) + attr(4) + reserved(11)
                const quint64 nStored = evbRd64(p + nCursor);
                nCursor += 8;

                TmpRec record;
                record.sName = sName;
                record.nOrig = nOrig;
                record.nStored = nStored;
                listTmp.append(record);
            } else {
                return false;
            }
        }

        if (nParsedNodes != nScheduledNodes) return false;

        // The file data stream follows the whole tree; blobs are concatenated
        // in record order. Decode atomically: one bad record invalidates the
        // entire context rather than exposing a partial archive.
        qint64 nRunning = nCursor;
        qint64 nTotalOutput = 0;
        QSet<QString> setNames;

        for (qint32 i = 0; i < listTmp.size(); i++) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

            const TmpRec &record = listTmp.at(i);
            if ((record.nOrig > (quint64)EVB_MAX_FILE_SIZE) || (nRunning < 0) || (nRunning > nTreeLimit) ||
                (record.nStored > (quint64)(nTreeLimit - nRunning)) ||
                (record.nOrig > (quint64)(EVB_MAX_TOTAL_OUTPUT - nTotalOutput))) {
                return false;
            }

            FILE_ENTRY entry;
            entry.sName = evbUniqueOutputName(record.sName, i, &setNames);
            if (entry.sName.isEmpty()) return false;

            const quint8 *pBlob = p + nRunning;
            bool bDecoded = false;
            if (record.nStored == record.nOrig) {
                bDecoded = evbCopyStored(pBlob, (qint64)record.nOrig, &entry.baData, pPdStruct);
            } else {
                // [qword header_len=12][dword aplib_stream_len][aPLib stream]
                if (record.nStored < 12) return false;
                const quint64 nHeaderSize = evbRd64(pBlob);
                const quint32 nAplibSize = evbRd32(pBlob + 8);
                if ((nHeaderSize != 12) || (record.nStored != nHeaderSize + (quint64)nAplibSize)) return false;
                bDecoded = evbAplibDepack(pBlob + nHeaderSize, nAplibSize, (qint64)record.nOrig, &entry.baData, pPdStruct);
            }

            if (!bDecoded || ((quint64)entry.baData.size() != record.nOrig) ||
                ((qint64)entry.baData.size() > EVB_MAX_TOTAL_OUTPUT - nTotalOutput)) {
                return false;
            }

            nTotalOutput += entry.baData.size();
            pContext->listEntries.append(entry);
            nRunning += (qint64)record.nStored;
        }

        // The VFS and every declared blob live wholly inside .enigma1.  EVB
        // terminates a non-empty blob stream with 0x16 and zero-fills the rest
        // of the physical section; an empty VFS has zero padding directly.
        // Authenticating that tail prevents a shortened/extended stored-size
        // field from silently re-partitioning adjacent blobs or consuming the
        // .enigma2 loader as file content.
        if (!listTmp.isEmpty()) {
            if ((nRunning >= nTreeLimit) || (p[nRunning] != 0x16)) return false;
            nRunning++;
        }
        while (nRunning < nTreeLimit) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            const qint64 nChunkEnd = qMin<qint64>(nTreeLimit, nRunning + (1ll << 20));
            for (; nRunning < nChunkEnd; nRunning++) {
                if (p[nRunning] != 0) return false;
            }
        }

        if (!XBinary::isPdStructNotCanceled(pPdStruct) || (pContext->listEntries.size() != listTmp.size())) return false;

        pState->nNumberOfRecords = pContext->listEntries.size();
        pState->pContext = pContext.release();
        return true;
    } catch (const std::bad_alloc &) {
        return false;
    }
}

XBinary::ARCHIVERECORD XEnigmaVB::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XEnigmaVB::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return false;

    const QByteArray &baData = pContext->listEntries.at(nIndex).baData;
    const bool bSeekableOutput = !pDevice->isSequential();
    auto failOutput = [&]() -> bool {
        if (bSeekableOutput) {
            XBinary::resize(pDevice, 0);
            pDevice->seek(0);
            pState->nCurrentOffset = 0;
        }
        return false;
    };
    if (bSeekableOutput && (!pDevice->seek(0) || ((pDevice->size() != 0) && !XBinary::resize(pDevice, 0)))) return false;
    qint64 nWritten = 0;
    pState->nCurrentOffset = 0;
    while (nWritten < baData.size()) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return failOutput();
        const qint64 nChunk = qMin<qint64>(1ll << 20, baData.size() - nWritten);
        const qint64 nResult = pDevice->write(baData.constData() + nWritten, nChunk);
        if ((nResult <= 0) || (nResult > nChunk)) return failOutput();
        nWritten += nResult;
        pState->nCurrentOffset = nWritten;
    }

    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return failOutput();
    return true;
}

bool XEnigmaVB::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XEnigmaVB::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
