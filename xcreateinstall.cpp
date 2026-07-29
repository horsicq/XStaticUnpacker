/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xcreateinstall.h"

#include <climits>

#include <QBuffer>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QVector>

#include "Algos/xppmdmodel.h"
#include "xpe.h"

static const qint64 CI_MAX_ARCHIVE_SIZE = Q_INT64_C(256) * 1024 * 1024;
static const qint64 CI_MAX_VOLUME_SIZE = Q_INT64_C(256) * 1024 * 1024;
static const qint64 CI_IO_CHUNK_SIZE = Q_INT64_C(1024) * 1024;
static const qint32 CI_MAX_VOLUME_COUNT = 1024;
static const qint32 CI_MAX_FILE_COUNT = 100000;
static const qint32 CI_MAX_DIRECTORY_ENTRIES = 100000;
static const qint32 CI_MAX_VOLUME_PATTERN_LENGTH = 255;
static const qint32 CI_MAX_VOLUME_WIDTH = 10;
static const qint32 CI_MAX_ENTRY_NAME_BYTES = 32768;

XCreateInstall::XCreateInstall(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XCreateInstall::~XCreateInstall()
{
}

bool XCreateInstall::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XCreateInstall::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XCreateInstall x(pDevice);
    return x.isValid(pPdStruct);
}

XCreateInstall::INTERNAL_INFO XCreateInstall::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XCreateInstall::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *XCreateInstall::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XCreateInstall::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XCreateInstall::getFileType()
{
    return FT_ARCHIVE;
}

static inline quint32 ciRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}
static inline quint16 ciRd16(const quint8 *p)
{
    return (quint16)(p[0] | ((quint16)p[1] << 8));
}
static inline quint64 ciRd64(const quint8 *p)
{
    quint64 v = 0;
    for (int i = 0; i < 8; i++) v |= ((quint64)p[i]) << (8 * i);
    return v;
}

static QString ciDeviceFileName(QIODevice *pDevice)
{
    if (QFile *pFile = qobject_cast<QFile *>(pDevice)) {
        return pFile->fileName();
    }
    return QString();
}

static Qt::CaseSensitivity ciFileSystemCaseSensitivity()
{
#ifdef Q_OS_WIN
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

static bool ciIsSafeBaseName(const QString &sName)
{
    if (sName.isEmpty() || (sName.size() > CI_MAX_VOLUME_PATTERN_LENGTH) || (sName == ".") || (sName == "..") ||
        sName.contains('/') || sName.contains('\\') || sName.contains(':') || sName.contains(QChar('\0'))) {
        return false;
    }
    return QFileInfo(sName).fileName() == sName;
}

static bool ciNormalizeOutputName(const QString &sInput, QString *pResult)
{
    if (!pResult || sInput.isEmpty() || (sInput.size() > CI_MAX_ENTRY_NAME_BYTES)) return false;

    QString sName = QDir::fromNativeSeparators(sInput).normalized(QString::NormalizationForm_C);
    if (sName.isEmpty() || QDir::isAbsolutePath(sName) || sName.startsWith('/')) return false;

    QStringList listParts = sName.split('/', Qt::KeepEmptyParts);
    if (listParts.isEmpty()) return false;

    for (const QString &sPart : listParts) {
        if (sPart.isEmpty() || (sPart == ".") || (sPart == "..") || sPart.endsWith('.') || sPart.endsWith(' ')) return false;

        for (int i = 0; i < sPart.size(); i++) {
            ushort nCharacter = sPart.at(i).unicode();
            if ((nCharacter >= 0xD800) && (nCharacter <= 0xDBFF)) {
                if ((i + 1 >= sPart.size()) || (sPart.at(i + 1).unicode() < 0xDC00) || (sPart.at(i + 1).unicode() > 0xDFFF)) {
                    return false;
                }
                i++;
                continue;
            }
            if ((nCharacter >= 0xDC00) && (nCharacter <= 0xDFFF)) return false;
            if ((nCharacter < 0x20) || (sPart.at(i) == '<') || (sPart.at(i) == '>') || (sPart.at(i) == ':') ||
                (sPart.at(i) == '"') || (sPart.at(i) == '|') || (sPart.at(i) == '?') || (sPart.at(i) == '*') ||
                (sPart.at(i) == QChar('\0')) || (sPart.at(i) == QChar::ReplacementCharacter) || !sPart.at(i).isPrint()) {
                return false;
            }
        }

        QString sDeviceName = sPart.section('.', 0, 0).toUpper();
        bool bReservedDigit = (sDeviceName.size() == 4) &&
                              (((sDeviceName.at(3) >= QChar('1')) && (sDeviceName.at(3) <= QChar('9'))) ||
                               (sDeviceName.at(3) == QChar(0x00b9)) || (sDeviceName.at(3) == QChar(0x00b2)) ||
                               (sDeviceName.at(3) == QChar(0x00b3)));
        bool bNumberedDevice = (sDeviceName.startsWith("COM") || sDeviceName.startsWith("LPT")) && bReservedDigit;
        if ((sDeviceName == "CON") || (sDeviceName == "PRN") || (sDeviceName == "AUX") || (sDeviceName == "NUL") ||
            (sDeviceName == "CLOCK$") || (sDeviceName == "CONIN$") || (sDeviceName == "CONOUT$") || bNumberedDevice) {
            return false;
        }
    }

    sName = listParts.join('/');
    if (sName.size() > CI_MAX_ENTRY_NAME_BYTES) return false;
    *pResult = sName;
    return true;
}

namespace {
static bool ciFormatVolumeName(const QString &sPattern, int nVolume, QString *pResult);
}

static bool ciIsDirectRegularFile(const QFileInfo &fileInfo, const QString &sCanonicalDirectory)
{
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable() || fileInfo.isSymLink()) return false;

    QString sCanonicalFile = fileInfo.canonicalFilePath();
    if (sCanonicalFile.isEmpty()) return false;

    QFileInfo canonicalInfo(sCanonicalFile);
    return canonicalInfo.absolutePath().compare(sCanonicalDirectory, ciFileSystemCaseSensitivity()) == 0;
}

static bool ciReadFileExact(const QString &sFileName, qint64 nExpectedSize, QByteArray *pResult, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pResult || (nExpectedSize < 0) || (nExpectedSize > CI_MAX_VOLUME_SIZE) || (nExpectedSize > INT_MAX) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    QFile file(sFileName);
    if (!file.open(QIODevice::ReadOnly) || (file.size() != nExpectedSize)) return false;

    QByteArray baResult;
    baResult.reserve((int)nExpectedSize);
    while ((qint64)baResult.size() < nExpectedSize) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        qint64 nToRead = qMin(CI_IO_CHUNK_SIZE, nExpectedSize - (qint64)baResult.size());
        QByteArray baChunk = file.read(nToRead);
        if (baChunk.size() != nToRead) return false;
        baResult.append(baChunk);
    }

    if ((file.size() != nExpectedSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    *pResult = baResult;
    return true;
}

static bool ciIsMainGeaFile(const QString &sFileName, QByteArray *pHeader = nullptr, XBinary::PDSTRUCT *pPdStruct = nullptr)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    QFileInfo fileInfo(sFileName);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable() || fileInfo.isSymLink() || (fileInfo.size() < 73) ||
        (fileInfo.size() > CI_MAX_VOLUME_SIZE)) {
        return false;
    }

    QFile file(sFileName);
    if (!file.open(QIODevice::ReadOnly) || (file.size() != fileInfo.size())) return false;

    QByteArray baHeader = file.read(73);
    if (baHeader.size() != 73) return false;
    const quint8 *p = (const quint8 *)baHeader.constData();

    if ((p[0] != 'G') || (p[1] != 'E') || (p[2] != 'A') || (p[3] != 0) || (ciRd16(p + 4) != 0)) return false;
    quint32 nHeaderSize = ciRd32(p + 26);
    quint64 nGeaSize = ciRd64(p + 42);
    quint16 nVolumeCount = ciRd16(p + 24);
    if ((p[10] == 0) || (nVolumeCount == 0) || (nVolumeCount > CI_MAX_VOLUME_COUNT) || (nHeaderSize < 73) ||
        (nHeaderSize > (quint32)file.size()) || (nGeaSize != (quint64)file.size())) {
        return false;
    }

    qint64 nPrefixSize = qMin((qint64)nHeaderSize, Q_INT64_C(73) + CI_MAX_VOLUME_PATTERN_LENGTH + 1);
    if (!file.seek(0)) return false;
    QByteArray baPrefix = file.read(nPrefixSize);
    if (baPrefix.size() != nPrefixSize) return false;

    qint64 nPatternEnd = baPrefix.indexOf('\0', 73);
    if ((nPatternEnd < 73) || (nPatternEnd >= nHeaderSize) || (nPatternEnd - 73 > CI_MAX_VOLUME_PATTERN_LENGTH)) return false;
    QString sPattern = QString::fromLatin1(baPrefix.constData() + 73, (int)(nPatternEnd - 73));
    QString sExpectedName;
    if (sPattern.isEmpty() || !ciFormatVolumeName(sPattern, 1, &sExpectedName) ||
        (fileInfo.fileName().compare(sExpectedName, ciFileSystemCaseSensitivity()) != 0)) {
        return false;
    }

    if (pHeader) *pHeader = baHeader;
    return true;
}

static QString ciFindExternalGeaFile(QIODevice *pDevice, QByteArray *pHeader = nullptr, XBinary::PDSTRUCT *pPdStruct = nullptr)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return QString();

    QString sInputName = ciDeviceFileName(pDevice);
    if (sInputName.isEmpty()) return QString();

    QFileInfo inputInfo(sInputName);
    QDir dir(inputInfo.absolutePath());
    QString sCanonicalDirectory = QFileInfo(dir.absolutePath()).canonicalFilePath();
    if (sCanonicalDirectory.isEmpty()) return QString();

    // A detached installer must resolve to one and only one valid volume-zero
    // GEA in its own directory.  Do not let an arbitrary enumeration order or
    // a symlink decide which archive is opened.
    QFileInfoList listFiles = dir.entryInfoList(QDir::Files | QDir::System | QDir::Hidden | QDir::NoDotAndDotDot, QDir::Name);
    if (listFiles.size() > CI_MAX_DIRECTORY_ENTRIES) return QString();

    QString sResult;
    QByteArray baResultHeader;
    for (const QFileInfo &fi : listFiles) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return QString();
        if (fi.absoluteFilePath().compare(inputInfo.absoluteFilePath(), ciFileSystemCaseSensitivity()) == 0) continue;
        if (!ciIsDirectRegularFile(fi, sCanonicalDirectory)) continue;

        QByteArray baCandidateHeader;
        if (!ciIsMainGeaFile(fi.absoluteFilePath(), &baCandidateHeader, pPdStruct)) continue;
        if (!sResult.isEmpty()) return QString();

        sResult = fi.canonicalFilePath();
        baResultHeader = baCandidateHeader;
    }

    if (pHeader && !sResult.isEmpty()) *pHeader = baResultHeader;
    return sResult;
}

XCreateInstall::INTERNAL_INFO XCreateInstall::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nGeaOffset = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);

    bool bGentee = false;
    for (int i = 0; i < listSections.size(); i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName == ".gentee") {
            bGentee = true;
            break;
        }
    }
    if (!bGentee) return result;

    // Corroborate with the Gentee runtime strings (unique to the engine).
    const qint64 nSize = getSize();
    bool bMarker = (find_ansiString(0, nSize, "lzge_decode", pPdStruct) != -1) || (find_ansiString(0, nSize, "genteert.dll", pPdStruct) != -1) ||
                   (find_ansiString(0, nSize, "gentee_init", pPdStruct) != -1);
    if (!bMarker) return result;

    result.bIsValid = true;

    // Locate the payload GEA container: its absolute self-size field equals the
    // installer size (an earlier GEA lives in the SETUP_TEMP resource).  Scan in
    // bounded overlapping windows instead of copying an attacker-sized PE.
    XBinary::OFFSETSIZE osSignature = pe.getSignOffsetSize();
    const bool bSignatureAtEnd = (osSignature.nOffset > 0) && (osSignature.nSize > 0) &&
                                 (osSignature.nOffset <= nSize) && (osSignature.nSize == nSize - osSignature.nOffset);

    qint64 nSearchEnd = bSignatureAtEnd ? osSignature.nOffset : nSize;
    while ((nSearchEnd > 0) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        qint64 nSearchStart = qMax(Q_INT64_C(0), nSearchEnd - CI_IO_CHUNK_SIZE);
        qint64 nOwnedSize = nSearchEnd - nSearchStart;
        qint64 nReadEnd = qMin(nSize, nSearchEnd + Q_INT64_C(72));
        QByteArray baWindow = read_array_process(nSearchStart, nReadEnd - nSearchStart, pPdStruct);
        if (baWindow.size() != nReadEnd - nSearchStart) break;

        const quint8 *pWindow = (const quint8 *)baWindow.constData();
        for (qint64 nLocal = nOwnedSize - 1; nLocal >= 0; nLocal--) {
            if (nLocal + 73 > baWindow.size()) continue;
            if ((pWindow[nLocal] != 'G') || (pWindow[nLocal + 1] != 'E') || (pWindow[nLocal + 2] != 'A') ||
                (pWindow[nLocal + 3] != 0) || (ciRd16(pWindow + nLocal + 4) != 0)) {
                continue;
            }

            quint32 nHeaderSize = ciRd32(pWindow + nLocal + 26);
            quint16 nVolumeCount = ciRd16(pWindow + nLocal + 24);
            quint64 nGeaEnd = ciRd64(pWindow + nLocal + 42);
            qint64 nCandidateOffset = nSearchStart + nLocal;
            bool bEndValid = (nGeaEnd == (quint64)nSize) ||
                             (bSignatureAtEnd && (nGeaEnd == (quint64)osSignature.nOffset));
            if ((pWindow[nLocal + 10] != 0) && (nVolumeCount > 0) && (nVolumeCount <= CI_MAX_VOLUME_COUNT) &&
                (nHeaderSize >= 73) && bEndValid && (nGeaEnd >= (quint64)nCandidateOffset) &&
                ((quint64)nHeaderSize <= nGeaEnd - (quint64)nCandidateOffset)) {
                result.nGeaOffset = nCandidateOffset;
                break;
            }
        }
        if (result.nGeaOffset >= 0) break;
        nSearchEnd = nSearchStart;
    }

    if (result.nGeaOffset >= 0) {
        QByteArray baVer = read_array_process(result.nGeaOffset + 0x0A, 2, pPdStruct);
        if (baVer.size() == 2) {
            quint16 nVer = (quint16)((quint8)baVer.at(0) | ((quint16)(quint8)baVer.at(1) << 8));
            if (nVer && (nVer < 0x100)) result.sVersion = QString("GEA v%1").arg(nVer);
        }
    } else {
        QByteArray baHeader;
        result.sGeaFileName = ciFindExternalGeaFile(getDevice(), &baHeader, pPdStruct);
        if (baHeader.size() >= 12) {
            quint16 nVer = ciRd16((const quint8 *)baHeader.constData() + 10);
            if (nVer && (nVer < 0x100)) result.sVersion = QString("GEA v%1").arg(nVer);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Gentee "lzge" decoder: LZ77 + adaptive canonical-Huffman (reversed from the
// stub's lzge_decode; block-based, per-block Huffman table with RLE-coded code
// lengths, LRU rep-distances, distance table derived from the uncompressed size).
// ---------------------------------------------------------------------------

namespace {

static const int kLzgeLenNbits[19] = {0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 12};
static const int kLzgeLenBase[19] = {2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 28, 36, 52, 68, 100, 132, 196, 260};
static const int kLzgeDistExtra[29] = {1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14};

static int lzgeNbits(quint32 x)
{
    int a = 1;
    while ((a < 32) && (x >= (1u << a))) a++;
    return a;
}

struct LzgeNode {
    int cl;
    int l;
    int r;
    int idx;
};

struct LzgeBits {
    const quint8 *b;
    qint64 len;
    qint64 p;
    int k;
    bool failed;
    LzgeBits(const quint8 *buf, qint64 l) : b(buf), len(l), p(0), k(7), failed(false) {}
    int bit()
    {
        if (failed || !b || (p >= len)) {
            failed = true;
            return 0;
        }
        int v = (b[p] >> k) & 1;
        if (k == 0) {
            p++;
            k = 7;
        } else {
            k--;
        }
        return v;
    }
    quint32 n(int c)
    {
        if ((c < 0) || (c > 32)) {
            failed = true;
            return 0;
        }
        quint32 r = 0;
        for (int i = 0; i < c; i++) {
            int nBit = bit();
            if (failed) return 0;
            r |= ((quint32)nBit) << i;
        }
        return r;
    }
    bool good() const { return !failed; }
    bool eof() const { return p >= len; }
    bool hasCanonicalPadding() const
    {
        if (failed || !b || (p < 0) || (p > len)) return false;
        if (p == len) return k == 7;
        if ((p != len - 1) || (k >= 7)) return false;
        const quint8 nPaddingMask = (quint8)((1u << (k + 1)) - 1u);
        return (b[p] & nPaddingMask) == 0;
    }
};

struct LzgeModel {
    int N;
    QVector<LzgeNode> nodes;
    int root;
    QVector<int> prevlen;
    int base14;
    bool simple;
    explicit LzgeModel(int n) : N(n), root(-1), base14(0), simple(false)
    {
        resetNodes();
        prevlen.fill(0, n);
    }
    void resetNodes()
    {
        nodes.resize(N);
        for (int i = 0; i < N; i++) {
            nodes[i].cl = 0;
            nodes[i].l = -1;
            nodes[i].r = -1;
            nodes[i].idx = i;
        }
        root = -1;
    }
};

static bool lzgeBuildTree(LzgeModel &m)
{
    int nxt = m.N;
    int root = -1;
    for (int guard = 0; guard < 64; guard++) {
        QHash<int, int> A;
        int i = 0;
        while (i < nxt) {
            int cl = m.nodes[i].cl;
            if (cl == 0) {
                i++;
                continue;
            }
            if (!A.contains(cl)) {
                A[cl] = i;
            } else {
                int pend = A[cl];
                LzgeNode nw;
                nw.cl = cl - 1;
                nw.l = pend;
                nw.r = i;
                nw.idx = nxt;
                m.nodes.append(nw);
                if (m.nodes.size() > m.N * 2) return false;
                A.remove(cl);
                root = nxt;
                nxt++;
            }
            m.nodes[i].cl = 0;
            i++;
        }
        if (root < 0) return false;
        if (m.nodes[root].cl == 0) {
            for (int nNode = 0; nNode < m.nodes.size(); nNode++) {
                if (m.nodes[nNode].cl != 0) return false;
            }
            m.root = root;
            return true;
        }
    }
    return false;
}

static int lzgeHuff(LzgeBits &bits, LzgeModel &m)
{
    int nd = m.root;
    if ((nd < 0) || (nd >= m.nodes.size()) || !bits.good()) return -1;
    int guard = 0;
    while (m.nodes[nd].l >= 0) {
        int nBit = bits.bit();
        if (!bits.good()) return -1;
        nd = nBit ? m.nodes[nd].r : m.nodes[nd].l;
        if ((nd < 0) || (nd >= m.nodes.size())) return -1;
        if (++guard > m.nodes.size()) return -1;
    }
    return m.nodes[nd].idx;
}

static bool lzgeLoadModel(LzgeBits &bits, LzgeModel &m)
{
    int N = m.N;
    int nb = (N < 0x20) ? 2 : 3;
    int L = (int)bits.n(nb) + 1;
    m.base14 = (int)bits.n(L);
    bits.n(L);  // 2nd read discarded
    if (!bits.good()) return false;
    QVector<int> raw(N, 0);
    if (m.simple) {
        for (int i = 0; i < N; i++) {
            raw[i] = (int)bits.n(L);
            if (!bits.good()) return false;
        }
    } else {
        LzgeModel sub(0x14);
        sub.simple = true;
        if (!lzgeLoadModel(bits, sub)) return false;
        int i = 0;
        while (i < N) {
            if (bits.eof()) return false;
            int sym = lzgeHuff(bits, sub);
            if (sym < 0) return false;
            if (sym <= 0xf) {
                raw[i] = sym;
                i++;
            } else {
                int s = sym - 0x10;
                int run;
                if (s == 0) run = (int)bits.n(2) + 4;
                else if (s == 1) run = (int)bits.n(4) + 8;
                else if (s == 2) run = (int)bits.n(6) + 0x18;
                else run = (int)bits.n(L);
                if (!bits.good()) return false;
                if (sym == 0x13) {
                    raw[i] = run;
                    i++;
                } else {
                    if ((run <= 0) || (run > N - i)) return false;
                    for (int r = 0; r < run; r++) raw[i++] = 0;
                }
            }
        }
    }
    for (int i = 0; i < N; i++) {
        int prev = m.prevlen[i];
        m.prevlen[i] = 0;
        int ln = raw[i];
        if (ln <= 0xf) {
            ln = (ln + prev) & 0xf;
            m.prevlen[i] = ln;
        }
        if (ln != 0) ln = m.base14 + ln - 1;
        if ((ln < 0) || (ln > 63)) return false;
        m.nodes[i].cl = ln;
    }
    return bits.good() && lzgeBuildTree(m) && (m.root >= 0);
}

static QByteArray lzgeDecode(const quint8 *pSrc, qint64 nSrcLen, qint64 nDstLen, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || (nDstLen <= 0) || (nDstLen > INT_MAX) || (nSrcLen <= 0) || (nSrcLen > INT_MAX) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return QByteArray();
    }

    int nPosBits = qMin(21, lzgeNbits((quint32)nDstLen));
    quint32 nMask = (nPosBits >= 32) ? 0xffffffffu : ((1u << nPosBits) - 1);
    QVector<int> DN, DB;
    DN << 0 << 0 << 0;
    DB << 0 << 0 << 0;
    {
        quint32 base = 2;
        int i = 0;
        for (;;) {
            if (i >= 29) break;
            int ex = kLzgeDistExtra[i];
            DB.append((int)base);
            DN.append(ex);
            base += (1u << ex);
            i++;
            if (base - 1 >= nMask) break;
        }
    }
    int nps = DB.size();

    LzgeBits bits(pSrc, nSrcLen);
    QByteArray out;
    out.reserve((int)qMin(nDstLen + 16, (qint64)(64 << 20)));
    int N = 0x101 + 18 * nps;
    quint32 rep[3] = {3, 4, 5};
    LzgeModel m(N);
    const int nBlockSize = 10000;

    while (((qint64)out.size() < nDstLen) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        m.resetNodes();
        if (!lzgeLoadModel(bits, m)) return QByteArray();
        for (int b = 0; b < nBlockSize; b++) {
            if ((qint64)out.size() >= nDstLen) break;
            if ((b & 0x3ff) == 0 && !XBinary::isPdStructNotCanceled(pPdStruct)) return QByteArray();
            if (bits.eof()) return QByteArray();
            int sym = lzgeHuff(bits, m);
            if (sym < 0) return QByteArray();
            if (sym < 0x100) {
                out.append((char)sym);
                continue;
            }
            int code = sym - 0x100;
            int ls, ds;
            if (code == 18 * nps) {
                ls = 18;
                ds = 0;
            } else {
                ls = code % 18;
                ds = code / 18;
            }
            if ((ls < 0) || (ls > 18)) return QByteArray();
            int length = kLzgeLenBase[ls] + (int)bits.n(kLzgeLenNbits[ls]);
            if (!bits.good()) return QByteArray();
            quint32 dist;
            if (ls == 18) {
                dist = bits.n(nPosBits);
            } else {
                if ((ds < 0) || (ds >= DB.size())) return QByteArray();
                quint32 val = (quint32)DB[ds] + bits.n(DN[ds]);
                if (ds == 0) {
                    dist = rep[0];
                } else if (ds == 1) {
                    dist = rep[1];
                    rep[1] = rep[0];
                    rep[0] = dist;
                } else if (ds == 2) {
                    dist = rep[2];
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = dist;
                } else {
                    dist = val;
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = dist;
                }
            }
            if (!bits.good()) return QByteArray();
            qint64 st = (qint64)out.size() - (qint64)dist;
            if ((st < 0) || (dist == 0) || ((qint64)length > nDstLen - (qint64)out.size())) return QByteArray();
            for (int k = 0; k < length; k++) out.append(out.at((int)(st + k)));
        }
    }

    if (((qint64)out.size() != nDstLen) || !bits.good() || !bits.hasCanonicalPadding() ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return QByteArray();
    }
    return out;
}

struct CiGeaHeader {
    quint32 nUnique;
    quint32 nFlags;
    quint16 nVolumeCount;
    quint32 nHeaderSize;
    quint64 nSummarySize;
    quint32 nInfoSize;
    quint64 nGeaSize;
    quint64 nVolumeSize;
    quint64 nLastVolumeSize;
    quint32 nMovedSize;
    quint8 nMemoryMb;
    quint32 nBlockSize;
    quint32 nSolidSize;
    QString sVolumePattern;
    qint64 nInfoOffset;
};

struct CiGeaFile {
    quint16 nFlags;
    quint64 nSize;
    quint64 nCompressedSize;
    quint32 nPassword;
    QString sName;
};

static bool ciParseGeaHeader(const QByteArray &baArchive, CiGeaHeader *pHeader)
{
    if (!pHeader || (baArchive.size() < 73)) return false;
    const quint8 *p = (const quint8 *)baArchive.constData();
    if ((p[0] != 'G') || (p[1] != 'E') || (p[2] != 'A') || (p[3] != 0) || (ciRd16(p + 4) != 0)) return false;

    CiGeaHeader h = {};
    h.nUnique = ciRd32(p + 6);
    h.nFlags = ciRd32(p + 20);
    h.nVolumeCount = ciRd16(p + 24);
    h.nHeaderSize = ciRd32(p + 26);
    h.nSummarySize = ciRd64(p + 30);
    h.nInfoSize = ciRd32(p + 38);
    h.nGeaSize = ciRd64(p + 42);
    h.nVolumeSize = ciRd64(p + 50);
    h.nLastVolumeSize = ciRd64(p + 58);
    h.nMovedSize = ciRd32(p + 66);
    h.nMemoryMb = p[70];
    h.nBlockSize = (quint32)p[71] * 0x40000u;
    h.nSolidSize = (quint32)p[72] * 0x40000u;

    if ((p[10] == 0) || (h.nVolumeCount == 0) || (h.nVolumeCount > CI_MAX_VOLUME_COUNT) || (h.nHeaderSize < 73) ||
        (h.nHeaderSize > (quint32)baArchive.size()) || (h.nHeaderSize > (quint32)CI_MAX_ARCHIVE_SIZE) ||
        (h.nGeaSize < h.nHeaderSize) || (h.nSummarySize > (quint64)CI_MAX_ARCHIVE_SIZE) ||
        (h.nInfoSize > (quint32)CI_MAX_ARCHIVE_SIZE) || (h.nMovedSize > (quint32)CI_MAX_ARCHIVE_SIZE) || (h.nBlockSize == 0)) {
        return false;
    }

    qint64 nPatternEnd = baArchive.indexOf('\0', 73);
    if ((nPatternEnd < 73) || (nPatternEnd >= h.nHeaderSize)) return false;
    if (nPatternEnd - 73 > CI_MAX_VOLUME_PATTERN_LENGTH) return false;
    h.sVolumePattern = QString::fromLatin1(baArchive.constData() + 73, (int)(nPatternEnd - 73));
    h.nInfoOffset = nPatternEnd + 1;

    if (h.nVolumeCount > 1) {
        if (h.sVolumePattern.isEmpty() || (h.nVolumeSize < 10) || (h.nVolumeSize > (quint64)CI_MAX_VOLUME_SIZE) ||
            (h.nLastVolumeSize < 10) || (h.nLastVolumeSize > (quint64)CI_MAX_VOLUME_SIZE)) {
            return false;
        }
    }

    // Skip the optional password CRC table.
    if (h.nFlags & 0x0001u) {
        if (h.nInfoOffset + 2 > h.nHeaderSize) return false;
        quint16 nPasswords = ciRd16(p + h.nInfoOffset);
        h.nInfoOffset += 2 + (qint64)nPasswords * 4;
        if (h.nInfoOffset > h.nHeaderSize) return false;
    }

    *pHeader = h;
    return true;
}

static bool ciFormatVolumeName(const QString &sPattern, int nVolume, QString *pResult)
{
    if (!pResult || (nVolume <= 0) || !ciIsSafeBaseName(sPattern)) return false;

    int nPercent = sPattern.indexOf('%');
    if ((nPercent < 0) || (sPattern.indexOf('%', nPercent + 1) >= 0)) return false;

    int i = nPercent + 1;
    bool bZeroPad = false;
    if ((i < sPattern.size()) && (sPattern.at(i) == '0')) {
        bZeroPad = true;
        i++;
    }

    int nWidth = 0;
    int nWidthDigits = 0;
    while ((i < sPattern.size()) && (sPattern.at(i) >= QChar('0')) && (sPattern.at(i) <= QChar('9'))) {
        if (++nWidthDigits > 2) return false;
        nWidth = nWidth * 10 + sPattern.at(i).digitValue();
        if (nWidth > CI_MAX_VOLUME_WIDTH) return false;
        i++;
    }
    if ((i >= sPattern.size()) || ((sPattern.at(i) != 'i') && (sPattern.at(i) != 'd'))) return false;

    QString sNumber = QString::number(nVolume);
    if (nWidth > sNumber.size()) sNumber = sNumber.rightJustified(nWidth, bZeroPad ? '0' : ' ');

    QString sResult = sPattern;
    sResult.replace(nPercent, i - nPercent + 1, sNumber);
    if (!ciIsSafeBaseName(sResult)) return false;

    *pResult = sResult;
    return true;
}

static bool ciBuildLogicalData(const QByteArray &baPrimary, const QString &sPrimaryFileName, qint64 nGeaFileOffset, const CiGeaHeader &h,
                               QByteArray *pData, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pData || (nGeaFileOffset < 0) || (h.nGeaSize < (quint64)nGeaFileOffset) ||
        (baPrimary.size() > CI_MAX_ARCHIVE_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    quint64 nPrimaryArchiveSize = h.nGeaSize - (quint64)nGeaFileOffset;
    quint64 nFirstDataOffset = (quint64)h.nHeaderSize + h.nMovedSize;
    if ((nFirstDataOffset > nPrimaryArchiveSize) || (nPrimaryArchiveSize != (quint64)baPrimary.size()) ||
        (h.nSummarySize > (quint64)CI_MAX_ARCHIVE_SIZE)) {
        return false;
    }

    quint64 nFirstDataSize = nPrimaryArchiveSize - nFirstDataOffset;
    if ((nFirstDataOffset > INT_MAX) || (nFirstDataSize > INT_MAX) || (nFirstDataSize > h.nSummarySize)) return false;

    QByteArray baData;
    baData.reserve((int)h.nSummarySize);
    baData.append(baPrimary.constData() + (int)nFirstDataOffset, (int)nFirstDataSize);

    QString sFormattedName;
    if (!h.sVolumePattern.isEmpty() && !ciFormatVolumeName(h.sVolumePattern, 1, &sFormattedName)) return false;

    QFileInfo primaryInfo(sPrimaryFileName);
    QDir primaryDir(primaryInfo.absolutePath());
    QString sCanonicalDirectory;
    QString sPrimaryCanonical;
    QHash<QString, QFileInfo> mapDirectoryFiles;
    QSet<QString> setDuplicateNames;
    const Qt::CaseSensitivity cs = ciFileSystemCaseSensitivity();

    if (nGeaFileOffset == 0) {
        QString sExternalDirectory = QFileInfo(primaryDir.absolutePath()).canonicalFilePath();
        if (sFormattedName.isEmpty() || sExternalDirectory.isEmpty() ||
            (primaryInfo.fileName().compare(sFormattedName, cs) != 0) || !ciIsDirectRegularFile(primaryInfo, sExternalDirectory)) {
            return false;
        }
    }

    if (h.nVolumeCount > 1) {
        if (h.sVolumePattern.isEmpty() || sPrimaryFileName.isEmpty()) return false;

        sCanonicalDirectory = QFileInfo(primaryDir.absolutePath()).canonicalFilePath();
        sPrimaryCanonical = primaryInfo.canonicalFilePath();
        if (sCanonicalDirectory.isEmpty() || sPrimaryCanonical.isEmpty()) return false;

        QFileInfoList listDirectoryEntries =
            primaryDir.entryInfoList(QDir::AllEntries | QDir::System | QDir::Hidden | QDir::NoDotAndDotDot, QDir::Name);
        if (listDirectoryEntries.size() > CI_MAX_DIRECTORY_ENTRIES) return false;

        for (const QFileInfo &fileInfo : listDirectoryEntries) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            QString sKey = (cs == Qt::CaseInsensitive) ? fileInfo.fileName().toCaseFolded() : fileInfo.fileName();
            if (mapDirectoryFiles.contains(sKey)) {
                setDuplicateNames.insert(sKey);
            } else {
                mapDirectoryFiles.insert(sKey, fileInfo);
            }
        }
    }

    quint64 nAggregatePhysicalSize = (quint64)baPrimary.size();
    for (int i = 1; i < h.nVolumeCount; i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        QString sVolumeName;
        if (!ciFormatVolumeName(h.sVolumePattern, i + 1, &sVolumeName)) return false;
        QString sKey = (cs == Qt::CaseInsensitive) ? sVolumeName.toCaseFolded() : sVolumeName;
        if (setDuplicateNames.contains(sKey) || !mapDirectoryFiles.contains(sKey)) return false;

        QFileInfo volumeInfo = mapDirectoryFiles.value(sKey);
        if ((volumeInfo.fileName().compare(sVolumeName, cs) != 0) || !ciIsDirectRegularFile(volumeInfo, sCanonicalDirectory) ||
            (volumeInfo.canonicalFilePath().compare(sPrimaryCanonical, cs) == 0)) {
            return false;
        }

        quint64 nExpectedSize = (i == h.nVolumeCount - 1) ? h.nLastVolumeSize : h.nVolumeSize;
        if ((nExpectedSize < 10) || (nExpectedSize > (quint64)CI_MAX_VOLUME_SIZE) ||
            (nExpectedSize > (quint64)volumeInfo.size()) || (nExpectedSize != (quint64)volumeInfo.size()) ||
            (nAggregatePhysicalSize > (quint64)CI_MAX_ARCHIVE_SIZE - nExpectedSize)) {
            return false;
        }
        nAggregatePhysicalSize += nExpectedSize;

        quint64 nVolumeDataSize = nExpectedSize - 10;
        if ((nVolumeDataSize > (quint64)CI_MAX_ARCHIVE_SIZE - (quint64)baData.size()) ||
            ((quint64)baData.size() + nVolumeDataSize > h.nSummarySize)) {
            return false;
        }

        QFile file(volumeInfo.canonicalFilePath());
        if (!file.open(QIODevice::ReadOnly) || ((quint64)file.size() != nExpectedSize)) return false;

        QByteArray baVolumeHeader = file.read(10);
        if (baVolumeHeader.size() != 10) return false;
        const quint8 *p = (const quint8 *)baVolumeHeader.constData();
        if ((p[0] != 'G') || (p[1] != 'E') || (p[2] != 'A') || (p[3] != 0) || (ciRd16(p + 4) != i) ||
            (ciRd32(p + 6) != h.nUnique)) {
            return false;
        }

        quint64 nReadVolumeData = 0;
        while (nReadVolumeData < nVolumeDataSize) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
            qint64 nToRead = (qint64)qMin((quint64)CI_IO_CHUNK_SIZE, nVolumeDataSize - nReadVolumeData);
            QByteArray baChunk = file.read(nToRead);
            if (baChunk.size() != nToRead) return false;
            baData.append(baChunk);
            nReadVolumeData += (quint64)nToRead;
        }
        if (((quint64)file.size() != nExpectedSize) || !file.atEnd()) return false;
    }

    // When a volume boundary would split a block, GEA moves the tail next to
    // the main header and appends it to the logical data stream.
    if (h.nMovedSize) {
        if (((quint64)h.nHeaderSize + h.nMovedSize > (quint64)baPrimary.size()) ||
            ((quint64)h.nMovedSize > (quint64)CI_MAX_ARCHIVE_SIZE - (quint64)baData.size()) ||
            ((quint64)baData.size() + h.nMovedSize > h.nSummarySize)) {
            return false;
        }
        baData.append(baPrimary.constData() + h.nHeaderSize, (int)h.nMovedSize);
    }

    if (((quint64)baData.size() != h.nSummarySize) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    *pData = baData;
    return true;
}

class CiPpmdDecoder {
public:
    CiPpmdDecoder() : m_bAllocated(false), m_bInitialized(false) {}

    bool allocate(quint8 nMemoryMb)
    {
        quint32 nMb = nMemoryMb ? nMemoryMb : 8;
        if (nMb > 256) return false;
        m_bAllocated = m_model.allocate(nMb << 20);
        return m_bAllocated;
    }

    QByteArray decode(const quint8 *pSrc, qint64 nSrcSize, qint64 nDstSize, int nOrder, XBinary::PDSTRUCT *pPdStruct)
    {
        if (!m_bAllocated || !pSrc || (nSrcSize <= 0) || (nSrcSize > INT_MAX) || (nDstSize < 0) || (nDstSize > INT_MAX) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return QByteArray();
        }

        if (nOrder > 1) {
            if (nOrder > 16) return QByteArray();
            m_model.initGentee((quint8)nOrder);
            m_bInitialized = true;
        } else if (!m_bInitialized) {
            return QByteArray();
        } else {
            if (!m_model.lightweightResetGentee()) return QByteArray();
        }

        QByteArray baInput((const char *)pSrc, (int)nSrcSize);
        QBuffer input(&baInput);
        if (!input.open(QIODevice::ReadOnly)) return QByteArray();
        m_model.setInputStream(&input, nSrcSize);

        QByteArray baResult;
        baResult.resize((int)nDstSize);
        for (int i = 0; i < baResult.size(); i++) {
            if (((i & 0x3fff) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return QByteArray();
            qint32 nSymbol = m_model.decodeSymbol();
            if ((nSymbol < 0) || (nSymbol > 255)) return QByteArray();
            baResult[i] = (char)nSymbol;
        }
        qint64 nBytesRead = m_model.inputBytesRead();
        // PPMd-I's carryless range encoder flushes four bytes.  A fixed-size
        // decode can legitimately leave any part of that flush unread, but no
        // additional framed data may remain.
        if (m_model.hasInputError() || (nBytesRead < 0) || (nBytesRead > nSrcSize) || (nSrcSize - nBytesRead > 4) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return QByteArray();
        }
        return baResult;
    }

private:
    XPPMdModel m_model;
    bool m_bAllocated;
    bool m_bInitialized;
};

}  // namespace

bool XCreateInstall::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(getInternalInfo(pPdStruct));
    if (!pInfo || !pInfo->bIsValid) return false;
    const INTERNAL_INFO &info = *pInfo;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    QByteArray baArchive;
    QString sPrimaryFileName;
    qint64 nGeaFileOffset = 0;

    if (info.nGeaOffset >= 0) {
        QByteArray baHeader = read_array_process(info.nGeaOffset, 73, pPdStruct);
        if ((baHeader.size() != 73) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }
        quint64 nDeclaredEnd = ciRd64(reinterpret_cast<const quint8 *>(baHeader.constData()) + 42);
        if ((nDeclaredEnd < (quint64)info.nGeaOffset) || (nDeclaredEnd > (quint64)getSize())) {
            delete pContext;
            return false;
        }
        qint64 nArchiveSize = (qint64)(nDeclaredEnd - (quint64)info.nGeaOffset);
        if ((nArchiveSize < 73) || (nArchiveSize > CI_MAX_ARCHIVE_SIZE) || (nArchiveSize > INT_MAX)) {
            delete pContext;
            return false;
        }
        baArchive = read_array_process(info.nGeaOffset, nArchiveSize, pPdStruct);
        if ((baArchive.size() != nArchiveSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }
        sPrimaryFileName = ciDeviceFileName(getDevice());
        nGeaFileOffset = info.nGeaOffset;
    } else {
        QString sResolvedFileName = ciFindExternalGeaFile(getDevice(), nullptr, pPdStruct);
        if (sResolvedFileName.isEmpty()) {
            delete pContext;
            return false;
        }

        if (!info.sGeaFileName.isEmpty() &&
            (QFileInfo(info.sGeaFileName).canonicalFilePath().compare(sResolvedFileName, ciFileSystemCaseSensitivity()) != 0)) {
            delete pContext;
            return false;
        }

        sPrimaryFileName = sResolvedFileName;
        qint64 nArchiveSize = QFileInfo(sPrimaryFileName).size();
        if ((nArchiveSize < 73) || !ciReadFileExact(sPrimaryFileName, nArchiveSize, &baArchive, pPdStruct)) {
            delete pContext;
            return false;
        }
    }

    CiGeaHeader header = {};
    if (!ciParseGeaHeader(baArchive, &header)) {
        delete pContext;
        return false;
    }

    // The file table is a standalone metadata region. It is not interleaved
    // with file data; that distinction matters as soon as an archive has more
    // than one member.
    QByteArray baInfo;
    qint64 nPackedInfoSize = (qint64)header.nHeaderSize - header.nInfoOffset;
    if ((header.nInfoOffset < 0) || (nPackedInfoSize < 0) || (nPackedInfoSize > CI_MAX_ARCHIVE_SIZE) ||
        (header.nInfoSize > (quint32)CI_MAX_ARCHIVE_SIZE)) {
        delete pContext;
        return false;
    }
    if (header.nFlags & 0x0002u) {
        if ((nPackedInfoSize == 0) || (header.nInfoSize == 0)) {
            delete pContext;
            return false;
        }
        baInfo = lzgeDecode((const quint8 *)baArchive.constData() + header.nInfoOffset, nPackedInfoSize, header.nInfoSize, pPdStruct);
        if ((quint32)baInfo.size() != header.nInfoSize) {
            delete pContext;
            return false;
        }
    } else {
        if (header.nInfoOffset + header.nInfoSize > header.nHeaderSize) {
            delete pContext;
            return false;
        }
        baInfo = baArchive.mid((int)header.nInfoOffset, (int)header.nInfoSize);
    }

    QList<CiGeaFile> listFiles;
    const quint8 *pInfoData = (const quint8 *)baInfo.constData();
    qint64 nInfoPos = 0;
    quint32 nCurrentPassword = 0;
    QString sCurrentFolder;
    int nInfoGuard = 0;
    quint64 nAggregateDecodedSize = 0;
    quint64 nAggregateCompressedSize = 0;
    QSet<QString> setOutputNames;
    while (nInfoPos < baInfo.size()) {
        if ((nInfoPos + 30 > baInfo.size()) || (++nInfoGuard > CI_MAX_FILE_COUNT) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }

        CiGeaFile file = {};
        file.nFlags = ciRd16(pInfoData + nInfoPos);
        file.nSize = ciRd64(pInfoData + nInfoPos + 10);
        file.nCompressedSize = ciRd64(pInfoData + nInfoPos + 18);
        nInfoPos += 30;

        if ((file.nSize > (quint64)CI_MAX_ARCHIVE_SIZE) ||
            (file.nSize > (quint64)CI_MAX_ARCHIVE_SIZE - nAggregateDecodedSize) ||
            (file.nCompressedSize > header.nSummarySize) ||
            (file.nCompressedSize > header.nSummarySize - nAggregateCompressedSize)) {
            delete pContext;
            return false;
        }
        nAggregateDecodedSize += file.nSize;
        nAggregateCompressedSize += file.nCompressedSize;
        if (file.nFlags & 0x0001u) nInfoPos += 4;  // attributes
        if (file.nFlags & 0x0020u) nInfoPos += 8;  // file version
        if (file.nFlags & 0x0040u) nInfoPos += 4;  // group id
        if (file.nFlags & 0x0080u) {
            if (nInfoPos + 4 > baInfo.size()) {
                delete pContext;
                return false;
            }
            nCurrentPassword = ciRd32(pInfoData + nInfoPos);
            nInfoPos += 4;
        }
        file.nPassword = nCurrentPassword;
        if (nInfoPos > baInfo.size()) {
            delete pContext;
            return false;
        }

        qint64 nNameEnd = baInfo.indexOf('\0', (int)nInfoPos);
        if ((nNameEnd < nInfoPos) || (nNameEnd - nInfoPos > CI_MAX_ENTRY_NAME_BYTES)) {
            delete pContext;
            return false;
        }
        QByteArray baRawName(baInfo.constData() + nInfoPos, (int)(nNameEnd - nInfoPos));
        if (header.nFlags & 0x0004u) {
            file.sName = QString::fromUtf8(baRawName);
            if (file.sName.toUtf8() != baRawName) {
                delete pContext;
                return false;
            }
        } else {
            file.sName = QString::fromLatin1(baRawName);
        }
        nInfoPos = nNameEnd + 1;

        if (file.nFlags & 0x0010u) {
            qint64 nFolderEnd = baInfo.indexOf('\0', (int)nInfoPos);
            if ((nFolderEnd < nInfoPos) || (nFolderEnd - nInfoPos > CI_MAX_ENTRY_NAME_BYTES)) {
                delete pContext;
                return false;
            }
            QByteArray baRawFolder(baInfo.constData() + nInfoPos, (int)(nFolderEnd - nInfoPos));
            if (header.nFlags & 0x0004u) {
                sCurrentFolder = QString::fromUtf8(baRawFolder);
                if (sCurrentFolder.toUtf8() != baRawFolder) {
                    delete pContext;
                    return false;
                }
            } else {
                sCurrentFolder = QString::fromLatin1(baRawFolder);
            }
            nInfoPos = nFolderEnd + 1;
        }
        if (!sCurrentFolder.isEmpty()) {
            file.sName = QDir::fromNativeSeparators(sCurrentFolder) + "/" + file.sName;
        }

        QString sOutputName;
        QString sCandidateName = file.sName.isEmpty() ? QString("file_%1").arg(nInfoGuard - 1, 4, 10, QChar('0')) : file.sName;
        if (!ciNormalizeOutputName(sCandidateName, &sOutputName)) {
            delete pContext;
            return false;
        }
        QString sOutputKey = sOutputName.toCaseFolded();
        if (setOutputNames.contains(sOutputKey)) {
            delete pContext;
            return false;
        }
        setOutputNames.insert(sOutputKey);
        file.sName = sOutputName;
        listFiles.append(file);
    }

    if (nAggregateCompressedSize != header.nSummarySize) {
        delete pContext;
        return false;
    }

    QByteArray baLogicalData;
    if (listFiles.isEmpty() || !ciBuildLogicalData(baArchive, sPrimaryFileName, nGeaFileOffset, header, &baLogicalData, pPdStruct)) {
        delete pContext;
        return false;
    }

    qint64 nDataPos = 0;
    QByteArray baLzgeHistory;
    CiPpmdDecoder ppmd;
    bool bPpmdAllocated = false;
    bool bArchiveOk = true;

    for (int nFileIndex = 0; nFileIndex < listFiles.size(); nFileIndex++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            bArchiveOk = false;
            break;
        }

        const CiGeaFile &file = listFiles.at(nFileIndex);
        if ((nDataPos < 0) || (nDataPos > baLogicalData.size()) ||
            (file.nCompressedSize > (quint64)(baLogicalData.size() - nDataPos)) || file.nPassword) {
            bArchiveOk = false;
            break;
        }

        qint64 nFileDataEnd = nDataPos + (qint64)file.nCompressedSize;
        QByteArray baFileData;
        baFileData.reserve((int)file.nSize);

        while ((quint64)baFileData.size() < file.nSize) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct) || (nDataPos + 9 > nFileDataEnd)) {
                bArchiveOk = false;
                break;
            }

            const quint8 *pDescriptor = (const quint8 *)baLogicalData.constData() + nDataPos;
            int nPackedOrder = pDescriptor[0] & 0x7f;
            int nMethod = nPackedOrder >> 4;
            int nOrder = (nPackedOrder & 0x0f) + 1;
            quint64 nStreamSize = ciRd64(pDescriptor + 1);
            nDataPos += 9;

            if ((nStreamSize == 0) || (nStreamSize > (quint64)(nFileDataEnd - nDataPos)) || (nStreamSize > INT_MAX)) {
                bArchiveOk = false;
                break;
            }

            qint64 nRemaining = (qint64)file.nSize - baFileData.size();
            qint64 nOutputSize = qMin((qint64)header.nBlockSize, nRemaining);
            const quint8 *pStream = (const quint8 *)baLogicalData.constData() + nDataPos;
            QByteArray baBlock;

            if (nMethod == 0) {
                if ((qint64)nStreamSize != nOutputSize) {
                    bArchiveOk = false;
                    break;
                }
                baBlock = QByteArray((const char *)pStream, (int)nStreamSize);
                baLzgeHistory.clear();
            } else if (nMethod == 1) {
                if (nOrder > 1) baLzgeHistory.clear();
                qint64 nSolidOffset = baLzgeHistory.size();
                if ((nSolidOffset < 0) || (nOutputSize > CI_MAX_ARCHIVE_SIZE - nSolidOffset)) {
                    bArchiveOk = false;
                    break;
                }
                QByteArray baDecoded = lzgeDecode(pStream, (qint64)nStreamSize, nSolidOffset + nOutputSize, pPdStruct);
                if (baDecoded.size() != nSolidOffset + nOutputSize) {
                    bArchiveOk = false;
                    break;
                }
                baBlock = baDecoded.mid((int)nSolidOffset, (int)nOutputSize);
                if (header.nSolidSize) {
                    baLzgeHistory = baDecoded.right((int)qMin((quint32)baDecoded.size(), header.nSolidSize));
                } else {
                    baLzgeHistory.clear();
                }
            } else if (nMethod == 2) {
                if (!bPpmdAllocated) {
                    bPpmdAllocated = ppmd.allocate(header.nMemoryMb);
                    if (!bPpmdAllocated) {
                        bArchiveOk = false;
                        break;
                    }
                }
                baBlock = ppmd.decode(pStream, (qint64)nStreamSize, nOutputSize, nOrder, pPdStruct);
                if (baBlock.size() != nOutputSize) {
                    bArchiveOk = false;
                    break;
                }
                baLzgeHistory.clear();
            } else {
                bArchiveOk = false;
                break;
            }

            baFileData.append(baBlock);
            nDataPos += (qint64)nStreamSize;
        }

        if (!bArchiveOk || ((quint64)baFileData.size() != file.nSize) || (nDataPos != nFileDataEnd)) {
            bArchiveOk = false;
            break;
        }

        FILE_ENTRY entry;
        entry.sName = file.sName;
        entry.baData = baFileData;
        pContext->listEntries.append(entry);
    }

    if (nDataPos != baLogicalData.size()) bArchiveOk = false;
    if (!bArchiveOk) pContext->listEntries.clear();

    if (pContext->listEntries.isEmpty()) {
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XCreateInstall::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XCreateInstall::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
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

        qint64 nToWrite = qMin(CI_IO_CHUNK_SIZE, (qint64)baData.size() - nWritten);
        qint64 nCurrent = pDevice->write(baData.constData() + nWritten, nToWrite);
        if ((nCurrent <= 0) || (nCurrent > nToWrite)) return false;
        nWritten += nCurrent;
        pState->nCurrentOffset = nWritten;
    }

    return XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XCreateInstall::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XCreateInstall::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
