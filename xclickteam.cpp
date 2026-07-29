/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xclickteam.h"

#include <cstring>
#include <zlib.h>

#include <QBuffer>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QQueue>
#include <QSet>

#include "../XArchive/Algos/xbzip2decoder.h"
#include "xpe.h"

XClickteam::XClickteam(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XClickteam::~XClickteam()
{
}

bool XClickteam::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XClickteam::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XClickteam x(pDevice);
    return x.isValid(pPdStruct);
}

XClickteam::INTERNAL_INFO XClickteam::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XClickteam::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *XClickteam::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XClickteam::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XClickteam::getFileType()
{
    return FT_ARCHIVE;
}

static inline quint32 ctRd32(const quint8 *p);

XClickteam::INTERNAL_INFO XClickteam::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nContainerOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    const qint64 nSize = getSize();
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nSize)) return result;

    // Authenticode data is appended after the installer container. It is not
    // part of Clickteam's chunk table.
    qint64 nContainerEnd = nSize;
    XBinary::OFFSETSIZE osSignature = pe.getSignOffsetSize();
    if ((osSignature.nOffset > nOverlayOffset) && (osSignature.nSize > 0) &&
        (osSignature.nOffset <= nSize) && (osSignature.nSize == nSize - osSignature.nOffset)) {
        nContainerEnd = osSignature.nOffset;
    }
    const qint64 nContainerSize = nContainerEnd - nOverlayOffset;
    if (nContainerSize < 18) return result;

    // "wwgT)" tag at the overlay start (Install Creator 2 payload container).
    QByteArray baHead = read_array_process(nOverlayOffset, qMin<qint64>(19, nContainerSize), pPdStruct);
    if ((baHead.size() < 18) || (baHead.left(5) != QByteArray("\x77\x77\x67\x54\x29", 5))) return result;

    // Authenticate at least the first record boundary (or the exact
    // eight-byte declaration used by separate-data builds). This prevents an
    // arbitrary PE overlay beginning with the five-byte tag from detecting.
    const quint8 *p = reinterpret_cast<const quint8 *>(baHead.constData());
    if (nContainerSize == 18) {
        if ((ctRd32(p + 10) == 0) || (ctRd32(p + 14) != 0)) return result;
    } else {
        if (baHead.size() < 19) return result;
        quint32 nCompressedSize = ctRd32(p + 10);
        quint32 nUncompressedSize = ctRd32(p + 14);
        quint8 nMethod = p[18];
        if ((nCompressedSize <= 1) || ((qint64)nCompressedSize > nContainerSize - 18) ||
            (nUncompressedSize == 0) || ((nMethod != 1) && (nMethod != 2))) {
            return result;
        }
    }

    result.bIsValid = true;
    result.sVersion = pe.getFileVersion().trimmed();
    result.nContainerOffset = nOverlayOffset;

    return result;
}

// ---------------------------------------------------------------------------
// extraction (zlib chunks; installed files live in the last "compound" chunk)
// ---------------------------------------------------------------------------

static const qint64 CT_MAX_CONTAINER_SIZE = 512ll << 20;
static const qint64 CT_MAX_FILE_SIZE = 256ll << 20;
static const qint64 CT_MAX_TOTAL_OUTPUT = 512ll << 20;
static const qint32 CT_MAX_FILE_COUNT = 65536;

static inline quint32 ctRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static bool ctIsSafeBaseName(const QString &sName)
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

// zlib (78 xx) inflate; reports the number of input bytes consumed.
static bool ctInflate(const quint8 *pSrc, qint64 nSrcLen, qint64 nMaxOutput, QByteArray *pOut, qint64 *pnConsumed,
                      XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || !pOut || (nSrcLen <= 0) || (nSrcLen > 0x7FFFFFFF) || (nMaxOutput < 0) || (nMaxOutput > CT_MAX_FILE_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    z_stream s;
    memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, 15) != Z_OK) return false;  // 15 = expect a zlib header

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
        if ((nProduced < 0) || (nProduced > nMaxOutput - pOut->size())) break;
        if (nProduced) pOut->append(aBuf, (int)nProduced);
        if (rc == Z_STREAM_END) {
            bOk = true;
            break;
        }
        if (rc != Z_OK) break;                                    // Z_DATA_ERROR / Z_BUF_ERROR ...
        if ((s.avail_in == 0) && (s.avail_out == sizeof(aBuf))) break;  // no progress
    }

    if (pnConsumed) *pnConsumed = (qint64)s.total_in;
    inflateEnd(&s);
    return bOk && XBinary::isPdStructNotCanceled(pPdStruct);
}

class CTBoundedSink : public QIODevice {
public:
    explicit CTBoundedSink(qint64 nLimit) : m_nLimit(nLimit), m_nWritten(0)
    {
        open(QIODevice::WriteOnly);
    }

    qint64 writtenSize() const { return m_nWritten; }
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *, qint64 nSize) override
    {
        if ((nSize < 0) || (nSize > m_nLimit - m_nWritten)) return -1;
        m_nWritten += nSize;
        return nSize;
    }

private:
    qint64 m_nLimit;
    qint64 m_nWritten;
};

static bool ctValidateBzip(const quint8 *pSrc, qint64 nSrcLen, qint64 nExpectedOutput, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || (nSrcLen < 14) || (nSrcLen > CT_MAX_CONTAINER_SIZE) ||
        (nExpectedOutput < 0) || (nExpectedOutput > CT_MAX_FILE_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    QByteArray baInput(reinterpret_cast<const char *>(pSrc), (int)nSrcLen);
    QBuffer input(&baInput);
    if (!input.open(QIODevice::ReadOnly)) return false;
    CTBoundedSink output(nExpectedOutput);

    XBinary::DATAPROCESS_STATE state = {};
    state.pDeviceInput = &input;
    state.pDeviceOutput = &output;
    state.nInputOffset = 0;
    state.nInputLimit = nSrcLen;
    state.nProcessedOffset = 0;
    state.nProcessedLimit = -1;

    bool bResult = XBZIP2Decoder::decompress(&state, pPdStruct) &&
                   (state.nCountInput == nSrcLen) && (state.nCountOutput == nExpectedOutput) &&
                   (output.writtenSize() == nExpectedOutput) && XBinary::isPdStructNotCanceled(pPdStruct);
    input.close();
    output.close();
    return bResult;
}

static bool ctAppendFile(XClickteam::UNPACK_CONTEXT *pContext, const QByteArray &baData)
{
    if (!pContext || (baData.size() > CT_MAX_FILE_SIZE) || (pContext->listEntries.size() >= CT_MAX_FILE_COUNT) ||
        ((qint64)baData.size() > CT_MAX_TOTAL_OUTPUT - pContext->nTotalOutput)) {
        return false;
    }

    XClickteam::FILE_ENTRY e;
    e.sName = QString("file_%1").arg(pContext->listEntries.size(), 4, 10, QChar('0'));
    e.baData = baData;
    pContext->listEntries.append(e);
    pContext->nTotalOutput += baData.size();
    return true;
}

static bool ctApplyTocNames(XClickteam::UNPACK_CONTEXT *pContext, const QByteArray &baToc, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pContext) return false;

    QHash<quint32, QQueue<QString>> mapNames;
    qint32 nNameCount = 0;
    const quint8 *p = (const quint8 *)baToc.constData();
    const qint64 n = baToc.size();

    // A packaged-file descriptor keeps its uncompressed size 40 bytes before
    // the final NUL-terminated file name. This excludes the preceding
    // uninstaller/product strings, which do not use that layout.
    for (qint64 i = 40; i < n;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        qint64 j = i;
        while ((j < n) && (p[j] >= 0x20) && (p[j] < 0x7F) && (j - i < 260)) j++;
        if ((j > i) && (j < n) && (p[j] == 0)) {
            QByteArray baName((const char *)p + i, (int)(j - i));
            quint32 nSize = ctRd32(p + i - 40);
            const QString sName = QString::fromLatin1(baName);
            if (ctIsSafeBaseName(sName) && (nSize <= (256U << 20))) {
                if (nNameCount >= CT_MAX_FILE_COUNT) return false;
                mapNames[nSize].enqueue(sName);
                nNameCount++;
            }
            i = j + 1;
        } else {
            i++;
        }
    }

    // Reserve every generic fallback before applying metadata. Otherwise a
    // real TOC name such as "file_0001" could collide with another entry's
    // fallback name.
    QSet<QString> setUsedNames;
    for (int i = 0; i < pContext->listEntries.size(); i++) {
        setUsedNames.insert(pContext->listEntries.at(i).sName.toCaseFolded());
    }
    for (int i = 0; i < pContext->listEntries.size(); i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        const QString sOldNameKey = pContext->listEntries.at(i).sName.toCaseFolded();
        setUsedNames.remove(sOldNameKey);
        QHash<quint32, QQueue<QString>>::iterator it = mapNames.find((quint32)pContext->listEntries[i].baData.size());
        if ((it != mapNames.end()) && !it.value().isEmpty()) {
            const QString sName = it.value().dequeue();
            const QString sNameKey = sName.toCaseFolded();
            if (!setUsedNames.contains(sNameKey)) {
                pContext->listEntries[i].sName = sName;
            }
        }
        setUsedNames.insert(pContext->listEntries.at(i).sName.toCaseFolded());
    }

    return true;
}

static bool ctReadSeparateVolume(QIODevice *pDevice, qint64 nDeclaredRegionSize, XClickteam::UNPACK_CONTEXT *pContext,
                                 XBinary::PDSTRUCT *pPdStruct)
{
    if (!pContext || (nDeclaredRegionSize <= 0) || (nDeclaredRegionSize > CT_MAX_CONTAINER_SIZE - 4) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    QFile *pInputFile = qobject_cast<QFile *>(pDevice);
    if (!pInputFile) return false;

    QFileInfo inputInfo(pInputFile->fileName());
    if (inputInfo.fileName().isEmpty()) return false;

    QString sVolumeName = inputInfo.absolutePath() + QDir::separator() + inputInfo.completeBaseName() + ".D01";
    QFileInfo volumeInfo(sVolumeName);
    if (!volumeInfo.exists() || !volumeInfo.isFile() || volumeInfo.isSymLink()) return false;

    QString sCanonicalDirectory = QFileInfo(inputInfo.absolutePath()).canonicalFilePath();
    QString sCanonicalVolume = volumeInfo.canonicalFilePath();
    if (sCanonicalDirectory.isEmpty() || sCanonicalVolume.isEmpty()) return false;
#if defined(Q_OS_WIN) || defined(Q_OS_MAC)
    const Qt::CaseSensitivity pathCaseSensitivity = Qt::CaseInsensitive;
#else
    const Qt::CaseSensitivity pathCaseSensitivity = Qt::CaseSensitive;
#endif
    if (QFileInfo(sCanonicalVolume).absolutePath().compare(sCanonicalDirectory, pathCaseSensitivity) != 0) return false;

    qint64 nVolumeSize = volumeInfo.size();
    if ((nVolumeSize != nDeclaredRegionSize + 4) || (nVolumeSize < 5) || (nVolumeSize > CT_MAX_CONTAINER_SIZE)) return false;

    QFile volumeFile(sVolumeName);
    if (!volumeFile.open(QIODevice::ReadOnly) || (volumeFile.size() != nVolumeSize)) return false;
    QByteArray baVolume = volumeFile.read(nVolumeSize);
    bool bExactRead = (baVolume.size() == nVolumeSize) && volumeFile.atEnd() && (volumeFile.size() == nVolumeSize);
    volumeFile.close();
    if (!bExactRead || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    const quint8 *p = (const quint8 *)baVolume.constData();
    qint64 nRegionSize = ctRd32(p);
    if ((nRegionSize != nDeclaredRegionSize) || (nRegionSize != baVolume.size() - 4)) return false;

    qint64 q = 4;
    const qint64 nEnd = 4 + nRegionSize;
    bool bFirst = true;  // uninstall string table
    qint32 nStreams = 0;
    while (q < nEnd) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        quint8 nMethod = p[q];
        if (nMethod != 1) return false;
        QByteArray baFile;
        qint64 nConsumed = 0;
        if (!ctInflate(p + q + 1, nEnd - (q + 1), CT_MAX_FILE_SIZE, &baFile, &nConsumed, pPdStruct) || (nConsumed <= 0) ||
            (nConsumed > nEnd - (q + 1))) {
            return false;
        }
        if (!bFirst && !ctAppendFile(pContext, baFile)) return false;
        bFirst = false;
        nStreams++;
        q += 1 + nConsumed;
    }

    return (q == nEnd) && (nStreams >= 2) && !pContext->listEntries.isEmpty() && XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XClickteam::_buildEntries(UNPACK_CONTEXT *pContext, qint64 nContainerOffset, PDSTRUCT *pPdStruct)
{
    if (!pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    qint64 nContainerEnd = getSize();
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return false;
    XBinary::OFFSETSIZE osSignature = pe.getSignOffsetSize();
    if ((osSignature.nOffset > nContainerOffset) && (osSignature.nSize > 0) &&
        (osSignature.nOffset <= getSize()) && (osSignature.nSize == getSize() - osSignature.nOffset)) {
        nContainerEnd = osSignature.nOffset;
    }
    qint64 nTail = nContainerEnd - nContainerOffset;
    if ((nTail < 10) || (nTail > CT_MAX_CONTAINER_SIZE)) return false;
    QByteArray baOv = read_array_process(nContainerOffset, nTail, pPdStruct);
    if ((baOv.size() != nTail) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    const quint8 *p = (const quint8 *)baOv.constData();
    const qint64 n = baOv.size();
    if (n < 10) return false;

    // records begin after the 5-byte "wwgT)" tag + 5-byte sub-header.
    QByteArray baToc;
    bool bCompoundFound = false;
    qint64 nDeclaredSeparateRegionSize = -1;
    qint64 nValidatedResourceOutput = 0;
    qint64 pos = 10;
    while (pos < n) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        if (pos + 9 > n) {
            // Separate-data builds end with {u32 D01 region size, u32 0}.
            // The exact declaration is authenticated again against the
            // sibling file's own length prefix before any stream is decoded.
            if ((n - pos != 8) || (ctRd32(p + pos + 4) != 0)) return false;
            nDeclaredSeparateRegionSize = ctRd32(p + pos);
            if ((nDeclaredSeparateRegionSize <= 0) || (nDeclaredSeparateRegionSize > CT_MAX_CONTAINER_SIZE - 4)) return false;
            pos = n;
            break;
        }

        quint32 nCompSize = ctRd32(p + pos);
        quint32 nUncompressedSize = ctRd32(p + pos + 4);
        quint8 nMethod = p[pos + 8];
        if ((nMethod != 1) && (nMethod != 2)) return false;

        qint64 nStreamStart = pos + 9;
        qint64 nRegionEnd = pos + 8 + (qint64)nCompSize;
        if ((nRegionEnd <= nStreamStart) || (nRegionEnd > n) || (nUncompressedSize == 0) || (nUncompressedSize > CT_MAX_FILE_SIZE)) return false;

        if (nMethod == 1) {
            QByteArray baOut;
            qint64 nConsumed = 0;
            qint64 nRegionInputSize = nRegionEnd - nStreamStart;
            if (!ctInflate(p + nStreamStart, nRegionInputSize, nUncompressedSize, &baOut, &nConsumed, pPdStruct) ||
                (nConsumed <= 0) || (nConsumed > nRegionInputSize)) {
                return false;
            }

            bool bHasTocMarker = baOut.contains(QByteArray("Uninstal.exe\0", 13));
            qint64 nLeftover = nRegionInputSize - nConsumed;
            if (nLeftover == 4) {
                // Ordinary top-level records end in a four-byte trailer.
                if ((quint32)baOut.size() != nUncompressedSize) return false;
                if (bHasTocMarker) baToc = baOut;
            } else if (nLeftover > 4) {
                // The final compound region replaces the normal trailer with a
                // sequence of bare [method][zlib stream] installed files.
                if (baToc.isEmpty() || bCompoundFound || (nRegionEnd != n) || (nUncompressedSize != nCompSize)) return false;

                UNPACK_CONTEXT compoundContext;
                qint64 q = nStreamStart + nConsumed;
                while (q < nRegionEnd) {
                    if (!XBinary::isPdStructNotCanceled(pPdStruct) || (p[q] != 1)) return false;

                    QByteArray baFile;
                    qint64 nFileConsumed = 0;
                    qint64 nAvailable = nRegionEnd - (q + 1);
                    if (!ctInflate(p + q + 1, nAvailable, CT_MAX_FILE_SIZE, &baFile, &nFileConsumed, pPdStruct) ||
                        (nFileConsumed <= 0) || (nFileConsumed > nAvailable) || !ctAppendFile(&compoundContext, baFile)) {
                        return false;
                    }
                    q += 1 + nFileConsumed;
                }

                if ((q != nRegionEnd) || compoundContext.listEntries.isEmpty()) return false;
                if ((qint64)compoundContext.nTotalOutput > CT_MAX_TOTAL_OUTPUT - pContext->nTotalOutput ||
                    (pContext->listEntries.size() > CT_MAX_FILE_COUNT - compoundContext.listEntries.size())) {
                    return false;
                }

                pContext->listEntries.append(compoundContext.listEntries);
                pContext->nTotalOutput += compoundContext.nTotalOutput;
                bCompoundFound = true;
            } else {
                return false;
            }
        } else {
            // Method 2 resources are not exposed as installed files, but they
            // are still authenticated. Accepting an unchecked BZip2 body made
            // corruption in a skipped UI chunk invisible to the extractor.
            qint64 nCompressedPayload = nRegionEnd - nStreamStart - 4;
            if ((nCompressedPayload < 14) || ((qint64)nUncompressedSize > CT_MAX_TOTAL_OUTPUT - nValidatedResourceOutput) ||
                !ctValidateBzip(p + nStreamStart, nCompressedPayload, nUncompressedSize, pPdStruct)) {
                return false;
            }
            nValidatedResourceOutput += nUncompressedSize;
        }

        pos = nRegionEnd;
    }

    if (pos != n) return false;
    if (pContext->listEntries.isEmpty()) {
        if (!ctReadSeparateVolume(getDevice(), nDeclaredSeparateRegionSize, pContext, pPdStruct)) return false;
    } else if (nDeclaredSeparateRegionSize != -1) {
        return false;
    }
    if (!baToc.isEmpty() && !ctApplyTocNames(pContext, baToc, pPdStruct)) return false;

    return !pContext->listEntries.isEmpty() && XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XClickteam::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || (info.nContainerOffset < 0)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    if (!_buildEntries(pContext, info.nContainerOffset, pPdStruct)) {
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XClickteam::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XClickteam::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
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

bool XClickteam::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XClickteam::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
