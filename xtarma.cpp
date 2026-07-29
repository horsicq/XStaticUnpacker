/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xtarma.h"

#include <cstdlib>
#include <cstring>
#include <zlib.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMap>
#include <QRegularExpression>
#include <QSet>

#include "xpe.h"
#include "LzmaDec.h"  // vendored public-domain LZMA-SDK decoder

namespace {
const qint64 TARMA_MAX_CONTAINER_SIZE = Q_INT64_C(256) * 1024 * 1024;
const qint64 TARMA_MAX_INNER_SIZE = Q_INT64_C(256) * 1024 * 1024;
const quint64 TARMA_MAX_TOTAL_SOURCE_SIZE = Q_UINT64_C(512) * 1024 * 1024;
const quint64 TARMA_MAX_TOTAL_PAYLOAD_SIZE = Q_UINT64_C(256) * 1024 * 1024;
const int TARMA_MAX_VOLUME_COUNT = 1024;
const int TARMA_MAX_BLOCK_COUNT = 8192;
const int TARMA_MAX_FILE_COUNT = 4096;
}

XTarma::XTarma(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XTarma::~XTarma()
{
}

bool XTarma::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XTarma::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XTarma x(pDevice);
    return x.isValid(pPdStruct);
}

XTarma::INTERNAL_INFO XTarma::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XTarma::handleInternalInfo(PDSTRUCT *pPdStruct)
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

void *XTarma::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XTarma::setInternalInfo(void *pInternalInfo)
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
    result.nContainerOffset = -1;

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
                result.nContainerOffset = nArchRaw;
                result.bExtractable = (p[3] == 0x32) || (p[3] == 0x33);
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
                result.bExtractable = true;
                result.nContainerOffset = nOverlayOffset;
                return result;
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// extraction (tiz2z: zlib, tiz3z: LZMA1 -> "tzf3" block sequence)
// ---------------------------------------------------------------------------

static void *tarmaAlloc(ISzAllocPtr, size_t nSize)
{
    return malloc(nSize);
}
static void tarmaFree(ISzAllocPtr, void *p)
{
    free(p);
}

// Raw LZMA1 decode to the end-of-stream marker (output size not known in advance).
static bool tarmaLzmaToEnd(const quint8 *pProps, const quint8 *pSrc, qint64 nSrcSize, QByteArray *pOut, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pProps || !pSrc || !pOut || (nSrcSize <= 0) || (nSrcSize > TARMA_MAX_CONTAINER_SIZE)) return false;

    static const ISzAlloc g_alloc = {tarmaAlloc, tarmaFree};

    CLzmaDec dec;
    LzmaDec_Construct(&dec);
    if (LzmaDec_Allocate(&dec, (const Byte *)pProps, 5, &g_alloc) != SZ_OK) return false;
    LzmaDec_Init(&dec);

    pOut->clear();
    const int nChunk = 1 << 16;
    QByteArray baChunk(nChunk, (char)0);

    qint64 nSrcPos = 0;
    bool bOk = false;
    for (;;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) break;

        SizeT nDestLen = nChunk;
        SizeT nSrcRemain = (SizeT)(nSrcSize - nSrcPos);
        ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
        SRes res = LzmaDec_DecodeToBuf(&dec, (Byte *)baChunk.data(), &nDestLen, (const Byte *)pSrc + nSrcPos, &nSrcRemain, LZMA_FINISH_ANY, &status);
        if (res != SZ_OK) break;

        if ((qint64)nDestLen > TARMA_MAX_INNER_SIZE - pOut->size()) break;
        pOut->append(baChunk.constData(), (int)nDestLen);
        nSrcPos += (qint64)nSrcRemain;

        if (status == LZMA_STATUS_FINISHED_WITH_MARK) {
            bOk = true;
            break;
        }
        if ((nDestLen == 0) && (nSrcRemain == 0)) break;  // no progress -> give up
    }

    LzmaDec_Free(&dec, &g_alloc);
    if (!bOk) return false;

    // .tsuarch is raw-section padded with zeroes. Authenticate all bytes after
    // the LZMA end marker so a valid decoded prefix cannot hide appended
    // corruption inside the declared container.
    for (qint64 i = nSrcPos; i < nSrcSize; i++) {
        if (((i & 0xFFFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        if (pSrc[i] != 0) return false;
    }
    return XBinary::isPdStructNotCanceled(pPdStruct);
}

static inline quint32 tarmaRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint64 tarmaRd64(const quint8 *p)
{
    return (quint64)tarmaRd32(p) | ((quint64)tarmaRd32(p + 4) << 32);
}

static bool tarmaInflate(const quint8 *pSrc, qint64 nSrcSize, QByteArray *pOut, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || !pOut || (nSrcSize <= 0) || (nSrcSize > TARMA_MAX_CONTAINER_SIZE)) return false;
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 15) != Z_OK) return false;

    stream.next_in = (Bytef *)pSrc;
    stream.avail_in = (uInt)qMin(nSrcSize, (qint64)0x7FFFFFFF);
    pOut->clear();

    char aBuffer[65536];
    bool bOk = false;
    for (;;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) break;

        stream.next_out = (Bytef *)aBuffer;
        stream.avail_out = sizeof(aBuffer);
        int nResult = inflate(&stream, Z_NO_FLUSH);
        qint64 nProduced = sizeof(aBuffer) - stream.avail_out;
        if (nProduced > TARMA_MAX_INNER_SIZE - pOut->size()) break;
        pOut->append(aBuffer, (int)nProduced);
        if (nResult == Z_STREAM_END) {
            bOk = true;
            break;
        }
        if (nResult != Z_OK) break;
        if ((stream.avail_in == 0) && (stream.avail_out == sizeof(aBuffer))) break;
    }

    qint64 nConsumed = (qint64)stream.total_in;
    inflateEnd(&stream);
    if (!bOk || (nConsumed < 0) || (nConsumed > nSrcSize)) return false;

    for (qint64 i = nConsumed; i < nSrcSize; i++) {
        if (((i & 0xFFFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        if (pSrc[i] != 0) return false;
    }
    return XBinary::isPdStructNotCanceled(pPdStruct);
}

static bool tarmaDecodeContainer(const QByteArray &baContainer, QByteArray *pInner, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pInner || (baContainer.size() <= 0) || (baContainer.size() > TARMA_MAX_CONTAINER_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    const quint8 *p = (const quint8 *)baContainer.constData();
    const qint64 n = baContainer.size();

    if ((n >= 10) && (memcmp(p, "tiz1", 4) == 0) && (p[8] == 0x78)) {
        return tarmaInflate(p + 8, n - 8, pInner, pPdStruct);
    }

    if ((n < 0x4D) || (memcmp(p + 0x10, "tiz", 3) != 0) || (p[0x14] != 'z')) return false;
    if (p[0x13] == '2') {
        // "Deflate (fast)" in InstallMate's compressor selector. The eight
        // bytes at +0x40 are framing/checksum data.
        return tarmaInflate(p + 0x48, n - 0x48, pInner, pPdStruct);
    }
    if (p[0x13] == '3') {
        return tarmaLzmaToEnd(p + 0x48, p + 0x4D, n - 0x4D, pInner, pPdStruct);
    }

    return false;
}

struct TARMA_BLOCK {
    QByteArray baData;
    bool bUsed;
};

struct TARMA_NAME {
    QString sName;
    QString sLoosePath;
    quint64 nSize;
};

struct TARMA_FOLDER {
    QByteArray baParentId;
    QString sPhysicalName;
};

static QList<TARMA_BLOCK> tarmaReadBlocks(const QByteArray &baInner, XBinary::PDSTRUCT *pPdStruct)
{
    QList<TARMA_BLOCK> result;
    const quint8 *p = (const quint8 *)baInner.constData();
    const qint64 n = baInner.size();

    // The DWORD at +4 varies by compressor and is not a reliable file type.
    // The framing and bounded payload size are the authoritative block test.
    for (qint64 i = 0; i + 64 <= n;) {
        if (((i & 0xFFFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) {
            result.clear();
            return result;
        }

        if (memcmp(p + i, "tzf3", 4) == 0) {
            quint32 nSize = tarmaRd32(p + i + 16);
            qint64 nData = i + 64;
            if ((qint64)nSize <= n - nData) {
                if (result.size() >= TARMA_MAX_BLOCK_COUNT) {
                    result.clear();
                    return result;
                }
                TARMA_BLOCK block;
                block.baData = QByteArray((const char *)p + nData, (int)nSize);
                block.bUsed = false;
                result.append(block);
                i = nData + nSize;
                continue;
            }
        }
        i++;
    }
    return result;
}

static bool tarmaReadDbString(const quint8 *p, qint64 nSize, qint64 nLengthOffset, QByteArray *pValue)
{
    if ((nLengthOffset < 0) || (nLengthOffset + 4 > nSize)) return false;

    quint32 nLength = tarmaRd32(p + nLengthOffset);
    qint64 nValueOffset = nLengthOffset + 4;
    if ((nLength == 0) || (nLength > 260) || ((qint64)nLength + 4 > nSize - nValueOffset)) return false;

    // tin9 stores display strings in the local 8-bit encoding. Preserve
    // high-bit bytes for fromLocal8Bit(), but reject embedded C0/DEL controls
    // (including NUL) before interpreting the field.
    for (quint32 i = 0; i < nLength; i++) {
        if ((p[nValueOffset + i] < 0x20) || (p[nValueOffset + i] == 0x7F)) return false;
    }
    if (tarmaRd32(p + nValueOffset + nLength) != 0) return false;

    *pValue = QByteArray((const char *)p + nValueOffset, (int)nLength);
    return true;
}

static bool tarmaIsAsciiIdentifier(const QByteArray &baValue)
{
    for (int i = 0; i < baValue.size(); i++) {
        quint8 nByte = (quint8)baValue.at(i);
        if ((nByte < 0x20) || (nByte >= 0x7F)) return false;
    }
    return !baValue.isEmpty();
}

static bool tarmaIsSafePathPart(const QString &sValue)
{
    if (sValue.isEmpty() || (sValue.size() > 255) || (sValue == ".") || (sValue == "..")) return false;
    static const QString g_sInvalidPathChars = "<>:\"/\\|?*";
    for (int i = 0; i < sValue.size(); i++) {
        if (!sValue.at(i).isPrint() || (sValue.at(i) == QChar::ReplacementCharacter) || g_sInvalidPathChars.contains(sValue.at(i))) return false;
    }
    if (sValue.endsWith('.') || sValue.endsWith(' ')) return false;

    static const QSet<QString> setReserved = {
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),  QStringLiteral("NUL"),  QStringLiteral("COM1"),
        QStringLiteral("COM2"), QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"), QStringLiteral("COM6"),
        QStringLiteral("COM7"), QStringLiteral("COM8"), QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"), QStringLiteral("LPT6"), QStringLiteral("LPT7"),
        QStringLiteral("LPT8"), QStringLiteral("LPT9")};
    return !setReserved.contains(sValue.section('.', 0, 0).toUpper());
}

static QString tarmaBuildLoosePath(const QByteArray &baFolderId, const QString &sName, const QHash<QByteArray, TARMA_FOLDER> &mapFolders)
{
    if ((baFolderId.size() != 8) || !tarmaIsSafePathPart(sName)) return QString();

    QStringList listParts;
    QList<QByteArray> listVisited;
    QByteArray baCurrentId = baFolderId;
    const QByteArray baNullId(8, 0);

    while (baCurrentId != baNullId) {
        if ((listVisited.size() >= 64) || listVisited.contains(baCurrentId) || !mapFolders.contains(baCurrentId)) return QString();
        listVisited.append(baCurrentId);

        const TARMA_FOLDER &folder = mapFolders.value(baCurrentId);
        if (!tarmaIsSafePathPart(folder.sPhysicalName)) return QString();
        listParts.prepend(folder.sPhysicalName);
        baCurrentId = folder.baParentId;
    }

    if (listParts.isEmpty()) return QString();
    listParts.append(sName);
    return listParts.join('/');
}

static bool tarmaPathHasLink(const QString &sBasePath, const QString &sRelativePath)
{
    QString sCurrent = sBasePath;
    const QStringList listParts = QDir::fromNativeSeparators(sRelativePath).split('/', Qt::SkipEmptyParts);
    for (int i = 0; i < listParts.size(); i++) {
        sCurrent = QDir(sCurrent).absoluteFilePath(listParts.at(i));
        QFileInfo info(sCurrent);
        if (info.isSymLink()) return true;
    }
    return false;
}

static bool tarmaReadFileBounded(QFile *pFile, qint64 nExpectedSize, QByteArray *pData, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pFile || !pData || !pFile->isOpen() || (nExpectedSize < 0) || (nExpectedSize > TARMA_MAX_CONTAINER_SIZE) ||
        (pFile->size() != nExpectedSize)) {
        return false;
    }

    pData->clear();
    pData->reserve((int)nExpectedSize);
    const qint64 nChunkSize = 1024 * 1024;
    while (pData->size() < nExpectedSize) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            pData->clear();
            return false;
        }
        qint64 nToRead = qMin(nChunkSize, nExpectedSize - pData->size());
        QByteArray baChunk = pFile->read(nToRead);
        if (baChunk.size() != nToRead) {
            pData->clear();
            return false;
        }
        pData->append(baChunk);
    }

    return pFile->atEnd() && XBinary::isPdStructNotCanceled(pPdStruct);
}

static QList<TARMA_NAME> tarmaReadNames(const QList<TARMA_BLOCK> &listBlocks, XBinary::PDSTRUCT *pPdStruct)
{
    QList<TARMA_NAME> result;
    if (listBlocks.isEmpty()) return result;

    // The first tzf3 block is the tin9 database. Resolve its file records
    // through the folder-ID tree so plain-file packages can use an exact
    // declared relative path instead of a directory-wide basename search.
    const QByteArray &baMeta = listBlocks.first().baData;
    const quint8 *p = (const quint8 *)baMeta.constData();
    const qint64 n = baMeta.size();

    QHash<QByteArray, TARMA_FOLDER> mapFolders;
    for (qint64 i = 0; i + 64 <= n; i++) {
        if (((i & 0xFFFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) {
            result.clear();
            return result;
        }
        if ((memcmp(p + i, "fldr", 4) != 0) || (tarmaRd32(p + i + 4) != 0)) continue;

        // Standard folders store the identifier length at +44. Folders tied
        // to a component have one additional eight-byte component field and
        // store it at +52.
        const qint64 anNameLengthOffsets[] = {44, 52};
        for (qint32 j = 0; j < 2; j++) {
            qint64 nNameLengthOffset = anNameLengthOffsets[j];
            QByteArray baIdentifier;
            if (!tarmaReadDbString(p, n, i + nNameLengthOffset, &baIdentifier)) continue;
            if (!tarmaIsAsciiIdentifier(baIdentifier)) continue;

            qint64 nPhysicalLengthOffset = i + nNameLengthOffset + 8 + baIdentifier.size();
            QByteArray baPhysicalName;
            if (!tarmaReadDbString(p, n, nPhysicalLengthOffset, &baPhysicalName)) continue;

            TARMA_FOLDER folder;
            folder.baParentId = QByteArray((const char *)p + i + nNameLengthOffset - 8, 8);
            folder.sPhysicalName = QString::fromLocal8Bit(baPhysicalName);
            if (!tarmaIsSafePathPart(folder.sPhysicalName)) continue;
            QByteArray baFolderKey((const char *)p + i + 8, 8);
            if (mapFolders.contains(baFolderKey)) {
                result.clear();
                return result;
            }
            mapFolders.insert(baFolderKey, folder);
            break;
        }
    }

    QSet<QString> setFileNames;
    for (qint64 i = 0; i + 88 <= n; i++) {
        if (((i & 0xFFFF) == 0) && !XBinary::isPdStructNotCanceled(pPdStruct)) {
            result.clear();
            return result;
        }
        if ((memcmp(p + i, "file", 4) != 0) || (tarmaRd32(p + i + 4) != 0)) continue;

        QByteArray baName;
        if (!tarmaReadDbString(p, n, i + 84, &baName)) continue;

        quint64 nFileSize = tarmaRd64(p + i + 60);
        QString sName = QString::fromLocal8Bit(baName);
        if (!tarmaIsSafePathPart(sName) || (nFileSize > (256U << 20))) {
            continue;
        }
        QString sNameKey = sName.toCaseFolded();
        if (setFileNames.contains(sNameKey)) {
            result.clear();
            return result;
        }
        setFileNames.insert(sNameKey);

        TARMA_NAME entry;
        entry.sName = sName;
        entry.sLoosePath = tarmaBuildLoosePath(QByteArray((const char *)p + i + 44, 8), entry.sName, mapFolders);
        entry.nSize = nFileSize;
        result.append(entry);
        if (result.size() > TARMA_MAX_FILE_COUNT) {
            result.clear();
            return result;
        }
    }

    return result;
}

bool XTarma::_buildEntries(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (!pContext) return false;
    pContext->listEntries.clear();

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || !info.bExtractable || (info.nContainerOffset < 0)) return false;

    qint64 nPrimarySize = -1;
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return false;
    if (!info.bIsLegacy) {
        const QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);
        for (int i = 0; i < listSections.size(); i++) {
            QByteArray baName(reinterpret_cast<const char *>(listSections.at(i).Name), 8);
            int nZero = baName.indexOf('\0');
            if (nZero >= 0) baName.truncate(nZero);
            if ((baName == ".tsuarch") && ((qint64)listSections.at(i).PointerToRawData == info.nContainerOffset)) {
                nPrimarySize = (qint64)listSections.at(i).SizeOfRawData;
                break;
            }
        }
    } else {
        qint64 nContainerEnd = getSize();
        XBinary::OFFSETSIZE osSignature = pe.getSignOffsetSize();
        if ((osSignature.nOffset > info.nContainerOffset) && (osSignature.nSize > 0) &&
            (osSignature.nOffset <= getSize()) && (osSignature.nSize == getSize() - osSignature.nOffset)) {
            nContainerEnd = osSignature.nOffset;
        }
        nPrimarySize = nContainerEnd - info.nContainerOffset;
    }
    if ((nPrimarySize <= 0) || (nPrimarySize > TARMA_MAX_CONTAINER_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    if ((info.nContainerOffset > getSize()) || (nPrimarySize > getSize() - info.nContainerOffset)) return false;

    QByteArray baPrimaryContainer = read_array_process(info.nContainerOffset, nPrimarySize, pPdStruct);
    if ((baPrimaryContainer.size() != nPrimarySize) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    QByteArray baPrimaryInner;
    if (!tarmaDecodeContainer(baPrimaryContainer, &baPrimaryInner, pPdStruct)) return false;

    QList<TARMA_BLOCK> listBlocks = tarmaReadBlocks(baPrimaryInner, pPdStruct);
    QList<TARMA_NAME> listNames = tarmaReadNames(listBlocks, pPdStruct);
    if (listBlocks.isEmpty() || listNames.isEmpty() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    if (!listBlocks.isEmpty()) {
        // The first primary tzf3 block is the tin9 metadata database. It is
        // never a payload, even if a declared file happens to have its size.
        listBlocks[0].bUsed = true;
    }

    QFile *pInputFile = qobject_cast<QFile *>(getDevice());
    QString sInputDirectory;
    quint64 nTotalSourceSize = (quint64)nPrimarySize;
    if (pInputFile) {
        QFileInfo inputInfo(pInputFile->fileName());
        sInputDirectory = inputInfo.absolutePath();

        // Loader/archive distributions place one or more matching TIZ volumes
        // next to the executable.
        if (!info.bIsLegacy && (baPrimaryContainer.size() >= 0x40)) {
            QDir inputDir(sInputDirectory);
            const QFileInfoList listCandidates =
                inputDir.entryInfoList(QStringList() << "Disk*.tiz", QDir::Files | QDir::System | QDir::Hidden, QDir::Name | QDir::IgnoreCase);
            static const QRegularExpression reVolume(QStringLiteral("^Disk([0-9]{4})\\.tiz$"), QRegularExpression::CaseInsensitiveOption);
            QMap<int, QFileInfo> mapVolumes;
            QByteArray baGuid = baPrimaryContainer.mid(0x30, 16);
            for (int i = 0; i < listCandidates.size(); i++) {
                if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

                const QFileInfo &candidate = listCandidates.at(i);
                QRegularExpressionMatch match = reVolume.match(candidate.fileName());
                if (!match.hasMatch()) continue;
                bool bNumberOK = false;
                int nVolume = match.captured(1).toInt(&bNumberOK);
                // Files that only resemble a Tarma volume must not poison a
                // valid package in the same directory. Authenticate the
                // package GUID before applying strict volume constraints.
                if (!bNumberOK || (nVolume <= 0) || (nVolume > TARMA_MAX_VOLUME_COUNT) || candidate.isSymLink() ||
                    (candidate.size() < 0x40)) {
                    continue;
                }

                QFile headerFile(candidate.absoluteFilePath());
                if (!headerFile.open(QIODevice::ReadOnly)) continue;
                QByteArray baHeader = headerFile.read(0x40);
                headerFile.close();
                if ((baHeader.size() != 0x40) || (baHeader.mid(0x30, 16) != baGuid)) continue;

                if (mapVolumes.contains(nVolume)) return false;
                mapVolumes.insert(nVolume, candidate);
            }

            int nLastMatchingVolume = 0;
            QMap<int, QFileInfo>::const_iterator it = mapVolumes.constBegin();
            while (it != mapVolumes.constEnd()) {
                if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

                const QFileInfo &volumeInfo = it.value();
                qint64 nVolumeSize = volumeInfo.size();
                if ((nVolumeSize < 0x40) || (nVolumeSize > TARMA_MAX_CONTAINER_SIZE) ||
                    ((quint64)nVolumeSize > TARMA_MAX_TOTAL_SOURCE_SIZE - nTotalSourceSize)) {
                    return false;
                }

                QFile volumeFile(volumeInfo.absoluteFilePath());
                if (!volumeFile.open(QIODevice::ReadOnly)) return false;
                QByteArray baVolume;
                bool bReadOK = tarmaReadFileBounded(&volumeFile, nVolumeSize, &baVolume, pPdStruct);
                volumeFile.close();
                if (!bReadOK) return false;

                // Standard DiskNNNN files belonging to another installer may
                // coexist in the directory. Only the exact package GUID joins
                // this logical archive.
                if (baVolume.mid(0x30, 16) == baGuid) {
                    if (it.key() != nLastMatchingVolume + 1) return false;
                    nLastMatchingVolume = it.key();
                    nTotalSourceSize += (quint64)nVolumeSize;

                    QByteArray baVolumeInner;
                    if (!tarmaDecodeContainer(baVolume, &baVolumeInner, pPdStruct)) return false;
                    QList<TARMA_BLOCK> listVolumeBlocks = tarmaReadBlocks(baVolumeInner, pPdStruct);
                    if (listVolumeBlocks.isEmpty() || (listVolumeBlocks.size() > TARMA_MAX_BLOCK_COUNT - listBlocks.size())) return false;
                    listBlocks.append(listVolumeBlocks);
                }
                ++it;
            }
        }
    }

    quint64 nTotalPayloadSize = 0;
    for (int i = 0; i < listNames.size(); i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        QByteArray baFile;
        bool bResolved = false;
        for (int j = 0; j < listBlocks.size(); j++) {
            if (!listBlocks[j].bUsed && ((quint64)listBlocks[j].baData.size() == listNames.at(i).nSize)) {
                baFile = listBlocks[j].baData;
                listBlocks[j].bUsed = true;
                bResolved = true;
                break;
            }
        }

        // Plain-file-tree distributions materialize the tin9 folder tree next
        // to the installer. Open only the exact metadata-declared path, and
        // reject links that resolve outside the installer directory.
        if (!bResolved && !sInputDirectory.isEmpty() && !listNames.at(i).sLoosePath.isEmpty()) {
            QString sBasePath = QFileInfo(sInputDirectory).canonicalFilePath();
            QFileInfo looseInfo(QDir(sInputDirectory).absoluteFilePath(listNames.at(i).sLoosePath));
            QString sLoosePath = looseInfo.canonicalFilePath();
            if (!sBasePath.isEmpty() && !sLoosePath.isEmpty() && looseInfo.isFile() && !looseInfo.isSymLink() &&
                !tarmaPathHasLink(sInputDirectory, listNames.at(i).sLoosePath) && ((quint64)looseInfo.size() == listNames.at(i).nSize)) {
                QString sRelativePath = QDir(sBasePath).relativeFilePath(sLoosePath);
                if (!QDir::isAbsolutePath(sRelativePath) && (sRelativePath != "..") && !sRelativePath.startsWith("../") &&
                    !sRelativePath.startsWith("..\\")) {
                    QFile looseFile(sLoosePath);
                    if (looseFile.open(QIODevice::ReadOnly)) {
                        bResolved = tarmaReadFileBounded(&looseFile, (qint64)listNames.at(i).nSize, &baFile, pPdStruct);
                        if (!bResolved) baFile.clear();
                        looseFile.close();
                    }
                }
            }
        }

        if (bResolved && ((quint64)baFile.size() == listNames.at(i).nSize)) {
            if ((quint64)baFile.size() > TARMA_MAX_TOTAL_PAYLOAD_SIZE - nTotalPayloadSize) return false;
            nTotalPayloadSize += (quint64)baFile.size();

            FILE_ENTRY entry;
            entry.sName = listNames.at(i).sName;
            entry.baData = baFile;
            pContext->listEntries.append(entry);
        } else {
            // Never expose a successful prefix of a package. Every file in
            // the authoritative tin9 metadata must resolve exactly.
            pContext->listEntries.clear();
            return false;
        }
    }

    return (pContext->listEntries.size() == listNames.size()) && !pContext->listEntries.isEmpty() &&
           XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XTarma::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    if (!_buildEntries(pContext, pPdStruct)) {
        delete pContext;
        return false;
    }

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XTarma::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XTarma::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return false;

    const FILE_ENTRY &e = pContext->listEntries.at(nIndex);
    qint64 nWritten = 0;
    pState->nCurrentOffset = 0;
    while (nWritten < e.baData.size()) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        qint64 nChunk = qMin<qint64>(1 << 20, e.baData.size() - nWritten);
        qint64 nResult = pDevice->write(e.baData.constData() + nWritten, nChunk);
        if ((nResult <= 0) || (nResult > nChunk)) return false;
        nWritten += nResult;
        pState->nCurrentOffset = nWritten;
    }
    return XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XTarma::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XTarma::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
