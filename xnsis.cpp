/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

/* The NSIS parser/extractor below is a focused port of the NSIS archive handler
 * from 7-Zip (CPP/7zip/Archive/Nsis, vendored under XArchive/inbox). It covers
 * the parts required to enumerate and extract the packed files:
 *   - first header + method/solid detection (NsisIn::Open2)
 *   - header decompression (Copy / Deflate / LZMA; solid and non-solid)
 *   - block-header table + install-script instruction walk (NsisIn::ReadEntries)
 *   - NSIS string decoding with variable / shell-folder / lang substitution
 *   - per-file extraction by data-block position (NsisIn::Decode)
 * BZip2 (the NSIS-modified variant) is detected but not decoded here.
 */

#include "xnsis.h"

#include <QByteArray>
#include <QBuffer>

#include <algorithm>
#include <cstring>
#include <zlib.h>

#include "LzmaDec.h"

// ---------------------------------------------------------------------------
// Constants (mirror 7-Zip NsisIn.cpp)
// ---------------------------------------------------------------------------

static const unsigned kNumCommandParams = 6;
static const unsigned kCmdSize = 4 + kNumCommandParams * 4;  // 28

// install-script opcodes we care about
enum {
    EW_CREATEDIR = 11,        // CreateDirectory / SetOutPath
    EW_EXTRACTFILE = 20,      // File
    EW_ASSIGNVAR = 25,        // StrCpy
    EW_WRITEUNINSTALLER = 62  // WriteUninstaller
};

// internal variable indexes
#define kVar_INSTDIR 21
#define kVar_OUTDIR 22
#define kVar_EXEDIR 23
#define kVar_TEMP 25
#define kVar_PLUGINSDIR 26
#define kVar_Spec_OUTDIR 31

// NSIS-2 / Park string escape codes
#define NS_CODE_SKIP 252
#define NS_CODE_VAR 253
#define NS_CODE_SHELL 254
// NS_CODE_LANG 255

// NSIS-3 string escape codes
#define NS_3_CODE_LANG 1
#define NS_3_CODE_SHELL 2
#define NS_3_CODE_VAR 3
#define NS_3_CODE_SKIP 4

// Park (unicode) string escape codes
#define PARK_CODE_SKIP 0xE000
#define PARK_CODE_VAR 0xE001
#define PARK_CODE_SHELL 0xE002
#define PARK_CODE_LANG 0xE003

#define IS_NS_SPEC_CHAR(c) ((c) >= NS_CODE_SKIP)
#define IS_PARK_SPEC_CHAR(c) ((c) >= PARK_CODE_SKIP && (c) <= PARK_CODE_LANG)

#define DECODE_NUMBER_FROM_2_CHARS(c0, c1) (((unsigned)(c0) & 0x7F) | (((unsigned)((c1) & 0x7F)) << 7))
#define CONVERT_NUMBER_NS_3_UNICODE(n) ((n) = (((n) & 0x7F) | ((((n) >> 8) & 0x7F) << 7)))
#define CONVERT_NUMBER_PARK(n) ((n) &= 0x7FFF)

static const quint32 kMask_IsCompressed = (quint32)1 << 31;

static const char *const kVarStrings[] = {"CMDLINE", "INSTDIR", "OUTDIR",     "EXEDIR", "LANGUAGE", "TEMP",
                                          "PLUGINSDIR", "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK", "_OUTDIR"};

static const char *const kShellStrings[] = {
    "DESKTOP", "INTERNET", "SMPROGRAMS", "CONTROLS", "PRINTERS", "DOCUMENTS", "FAVORITES", "SMSTARTUP", "RECENT", "SENDTO", "BITBUCKET", "STARTMENU", nullptr, "MUSIC",
    "VIDEOS", nullptr, "DESKTOP", "DRIVES", "NETWORK", "NETHOOD", "FONTS", "TEMPLATES", "STARTMENU", "SMPROGRAMS", "SMSTARTUP", "DESKTOP", "APPDATA", "PRINTHOOD",
    "LOCALAPPDATA", "ALTSTARTUP", "ALTSTARTUP", "FAVORITES", "INTERNET_CACHE", "COOKIES", "HISTORY", "APPDATA", "WINDIR", "SYSDIR", "PROGRAM_FILES", "PICTURES",
    "PROFILE", "SYSTEMX86", "PROGRAM_FILESX86", "PROGRAM_FILES_COMMON", "PROGRAM_FILES_COMMONX8", "TEMPLATES", "DOCUMENTS", "ADMINTOOLS", "ADMINTOOLS", "CONNECTIONS",
    nullptr, nullptr, nullptr, "MUSIC", "PICTURES", "VIDEOS", "RESOURCES", "RESOURCES_LOCALIZED", "COMMON_OEM_LINKS", "CDBURN_AREA", nullptr, "COMPUTERSNEARME"};

static const unsigned kNumShellStrings = sizeof(kShellStrings) / sizeof(kShellStrings[0]);

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static inline quint16 rd16(const quint8 *p)
{
    return (quint16)(p[0] | ((quint16)p[1] << 8));
}

static inline quint32 rd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static bool nsisIsLZMA(const quint8 *p, quint32 *pDict)
{
    if (pDict) {
        *pDict = rd32(p + 1);
    }
    return (p[0] == 0x5D && p[1] == 0x00 && p[2] == 0x00 && p[5] == 0x00 && (p[6] & 0x80) == 0x00);
}

static bool nsisIsLZMA_flag(const quint8 *p, quint32 *pDict, bool *pThereIsFlag)
{
    if (nsisIsLZMA(p, pDict)) {
        *pThereIsFlag = false;
        return true;
    }
    if (p[0] <= 1 && nsisIsLZMA(p + 1, pDict)) {
        *pThereIsFlag = true;
        return true;
    }
    return false;
}

static bool nsisIsBZip2(const quint8 *p)
{
    return (p[0] == 0x31 && p[1] < 14);
}

static bool nsisIsDrivePath(const QString &s)
{
    if (s.length() < 2) {
        return false;
    }
    QChar c = s.at(0);
    return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'))) && (s.at(1) == ':');
}

static bool nsisIsAbsolutePath(const QString &s)
{
    if (s.startsWith("\\\\")) {
        return true;
    }
    return nsisIsDrivePath(s);
}

static QString nsisReducedName(const QString &sPrefix, bool bHasPrefix, const QString &sName)
{
    QString s;
    if (bHasPrefix) {
        s = sPrefix;
        if (!s.isEmpty() && !s.endsWith('\\')) {
            s += '\\';
        }
    }
    s += sName.isEmpty() ? QString("file") : sName;

    const QString sRemove = "$INSTDIR\\";
    if (s.startsWith(sRemove, Qt::CaseInsensitive)) {
        s = s.mid(sRemove.length());
        if (s.startsWith('\\')) {
            s = s.mid(1);
        }
    }
    // Normalise separators to forward slash so output paths are portable.
    s.replace('\\', '/');
    return s;
}

static void *nsisSzAlloc(ISzAllocPtr, size_t nSize)
{
    return malloc(nSize);
}

static void nsisSzFree(ISzAllocPtr, void *p)
{
    free(p);
}

static ISzAlloc g_nsisAlloc = {nsisSzAlloc, nsisSzFree};

// ---------------------------------------------------------------------------
// XCONVERT table + boilerplate
// ---------------------------------------------------------------------------

XBinary::XCONVERT _TABLE_XNSIS_STRUCTID[] = {
    {XNSIS::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XNSIS::STRUCTID_HEADER, "HEADER", QString("Header")},
    {XNSIS::STRUCTID_FILEENTRY, "FILEENTRY", QString("File Entry")},
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

QString XNSIS::structIDToFtString(quint32 nID)
{
    return XBinary::XCONVERT_idToFtString(nID, _TABLE_XNSIS_STRUCTID, sizeof(_TABLE_XNSIS_STRUCTID) / sizeof(XBinary::XCONVERT));
}

quint32 XNSIS::ftStringToStructID(const QString &sFtString)
{
    return XCONVERT_ftStringToId(sFtString, _TABLE_XNSIS_STRUCTID, sizeof(_TABLE_XNSIS_STRUCTID) / sizeof(XBinary::XCONVERT));
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

    const char *apszSignatures[] = {"NullsoftInst", "Nullsoft.NSIS", ";!@Install@!UTF-8!", ";!@Install@!UTF-16LE", ";!@Install@!"};
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

            qint64 nBytesToRead = (std::min)(nWindowSize, nRemainingSize);

            if (nBytesToRead > 0) {
                QByteArray baWindow = read_array_process(nOffset, nBytesToRead, pPdStruct);

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

    return result;
}

// ---------------------------------------------------------------------------
// first header
// ---------------------------------------------------------------------------

bool XNSIS::_findFirstHeader(qint64 nSignatureOffset, qint64 nTotalSize, UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    // Header layout: [4 flags][0xDEADBEEF][16-byte signature ...] where the signature
    // 'NullsoftInst' begins 4 bytes after the DEADBEEF marker. HeaderSize is at +0x14,
    // ArcSize at +0x18. The DEADBEEF marker sits 4 bytes before the signature.
    qint64 nSearchStart = (std::max)((qint64)0, nSignatureOffset - 32);

    for (qint64 i = nSignatureOffset; (i >= nSearchStart) && isPdStructNotCanceled(pPdStruct); i--) {
        if (read_uint32(i, false) == 0xDEADBEEF) {
            qint64 nHeaderOffset = i - 4;
            if (nHeaderOffset < 0) {
                return false;
            }

            quint32 nFlags = read_uint32(nHeaderOffset, false);
            quint32 nHeaderSize = read_uint32(nHeaderOffset + 0x14, false);
            quint32 nArcSize = read_uint32(nHeaderOffset + 0x18, false);

            if ((nArcSize > 0x1C) && (nHeaderSize > 0) && ((qint64)nArcSize <= (nTotalSize - nHeaderOffset))) {
                pContext->nFirstHeaderOffset = nHeaderOffset;
                pContext->nDataStreamOffset = nHeaderOffset + 0x1C;
                pContext->nFlags = nFlags;
                pContext->nHeaderSize = nHeaderSize;
                pContext->nArchiveSize = nArcSize;
                return true;
            }
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// method / solid detection (NsisIn::Open2)
// ---------------------------------------------------------------------------

bool XNSIS::_detectMethod(UNPACK_CONTEXT *pContext, const quint8 *pSig, qint64 nSigSize)
{
    const qint64 kSigNeeded = 4 + 1 + 5 + 2;
    if (nSigSize < kSigNeeded) {
        return false;
    }

    pContext->bHeaderIsCompressed = true;
    pContext->bIsSolid = true;
    pContext->bFilterFlag = false;
    pContext->nNonSolidStartOffset = 0;

    quint32 nCompressedHeaderSize = rd32(pSig);
    quint32 nDict = 0;

    if (nCompressedHeaderSize == pContext->nHeaderSize) {
        pContext->bHeaderIsCompressed = false;
        pContext->bIsSolid = false;
        pContext->method = NMETHOD_COPY;
    } else if (nsisIsLZMA_flag(pSig, &nDict, &pContext->bFilterFlag)) {
        pContext->method = NMETHOD_LZMA;
    } else if (pSig[3] == 0x80) {
        pContext->bIsSolid = false;
        bool bFlag = false;
        if (nsisIsLZMA_flag(pSig + 4, &nDict, &bFlag)) {
            pContext->method = NMETHOD_LZMA;
            pContext->bFilterFlag = bFlag;
        } else if (nsisIsBZip2(pSig + 4)) {
            pContext->method = NMETHOD_BZIP2;
        } else {
            pContext->method = NMETHOD_DEFLATE;
        }
    } else if (nsisIsBZip2(pSig)) {
        pContext->method = NMETHOD_BZIP2;
    } else {
        pContext->method = NMETHOD_DEFLATE;
    }

    if (!pContext->bIsSolid) {
        pContext->bHeaderIsCompressed = ((nCompressedHeaderSize & kMask_IsCompressed) != 0);
        pContext->nNonSolidStartOffset = nCompressedHeaderSize & ~kMask_IsCompressed;
    }

    switch (pContext->method) {
        case NMETHOD_LZMA: pContext->compressMethod = HANDLE_METHOD_LZMA; break;
        case NMETHOD_BZIP2: pContext->compressMethod = HANDLE_METHOD_BZIP2; break;
        case NMETHOD_DEFLATE: pContext->compressMethod = HANDLE_METHOD_DEFLATE; break;
        default: pContext->compressMethod = HANDLE_METHOD_STORE; break;
    }

    return true;
}

// ---------------------------------------------------------------------------
// low-level decoders
// ---------------------------------------------------------------------------

bool XNSIS::_lzmaDecode(const quint8 *pSrc, qint64 nSrcSize, qint64 nOutHint, bool bOutHintKnown, QByteArray *pResult)
{
    if (nSrcSize < 5) {
        return false;
    }

    CLzmaDec dec;
    LzmaDec_Construct(&dec);

    if (LzmaDec_Allocate(&dec, (const Byte *)pSrc, 5, &g_nsisAlloc) != SZ_OK) {
        return false;
    }
    LzmaDec_Init(&dec);

    const Byte *pIn = (const Byte *)pSrc + 5;
    SizeT nInRemaining = (SizeT)(nSrcSize - 5);

    pResult->clear();
    qint64 nCapacity = bOutHintKnown ? nOutHint : (qint64)(1 << 20);
    if (nCapacity < (1 << 16)) {
        nCapacity = (1 << 16);
    }
    pResult->resize((int)nCapacity);
    qint64 nOutPos = 0;

    bool bOk = false;

    for (;;) {
        if (nOutPos >= pResult->size()) {
            qint64 nNext = (qint64)pResult->size() * 2;
            if (bOutHintKnown && (nNext > nOutHint) && (nOutHint > nOutPos)) {
                nNext = nOutHint;
            }
            pResult->resize((int)nNext);
        }

        SizeT nDestLen = (SizeT)(pResult->size() - nOutPos);
        if (bOutHintKnown) {
            SizeT nRem = (SizeT)(nOutHint - nOutPos);
            if (nRem < nDestLen) {
                nDestLen = nRem;
            }
        }

        SizeT nSrcLen = nInRemaining;
        ELzmaStatus status = LZMA_STATUS_NOT_FINISHED;
        SRes res = LzmaDec_DecodeToBuf(&dec, (Byte *)pResult->data() + nOutPos, &nDestLen, pIn, &nSrcLen, LZMA_FINISH_ANY, &status);

        nOutPos += (qint64)nDestLen;
        pIn += nSrcLen;
        nInRemaining -= nSrcLen;

        if (res != SZ_OK) {
            bOk = false;
            break;
        }

        if (status == LZMA_STATUS_FINISHED_WITH_MARK) {
            bOk = true;
            break;
        }

        if (bOutHintKnown && (nOutPos >= nOutHint)) {
            bOk = true;
            break;
        }

        if ((nDestLen == 0) && (nSrcLen == 0)) {
            // no progress: input consumed (or stuck). Accept what we have.
            bOk = true;
            break;
        }

        if (nInRemaining == 0 && nDestLen == 0) {
            bOk = true;
            break;
        }
    }

    LzmaDec_Free(&dec, &g_nsisAlloc);

    if (bOk) {
        pResult->resize((int)nOutPos);
        return true;
    }

    pResult->clear();
    return false;
}

bool XNSIS::_inflateRaw(const quint8 *pSrc, qint64 nSrcSize, qint64 nOutHint, bool bOutHintKnown, QByteArray *pResult)
{
    if (nSrcSize <= 0) {
        return false;
    }

    z_stream stream = {};
    stream.next_in = (Bytef *)pSrc;
    stream.avail_in = (uInt)nSrcSize;

    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        return false;
    }

    pResult->clear();
    qint64 nCapacity = bOutHintKnown ? nOutHint : (qint64)(1 << 20);
    if (nCapacity < (1 << 16)) {
        nCapacity = (1 << 16);
    }
    pResult->resize((int)nCapacity);
    qint64 nOutPos = 0;

    int nRes = Z_OK;

    for (;;) {
        if (nOutPos >= pResult->size()) {
            pResult->resize((int)((qint64)pResult->size() * 2));
        }

        stream.next_out = (Bytef *)pResult->data() + nOutPos;
        stream.avail_out = (uInt)(pResult->size() - nOutPos);

        nRes = inflate(&stream, Z_NO_FLUSH);
        nOutPos = (qint64)stream.total_out;

        if ((nRes == Z_STREAM_END) || (nRes == Z_BUF_ERROR)) {
            break;
        }
        if (nRes != Z_OK) {
            break;
        }
        if (stream.avail_in == 0 && stream.avail_out != 0) {
            break;
        }
    }

    inflateEnd(&stream);

    bool bOk = (nRes == Z_STREAM_END) || (nRes == Z_BUF_ERROR) || (nRes == Z_OK);
    if (bOutHintKnown) {
        bOk = bOk && (nOutPos >= nOutHint);
        if (nOutPos > nOutHint) {
            nOutPos = nOutHint;
        }
    }

    if (bOk && (nOutPos > 0)) {
        pResult->resize((int)nOutPos);
        return true;
    }

    pResult->clear();
    return false;
}

bool XNSIS::_decodeBlock(NMETHOD method, bool bFilterFlag, const quint8 *pSrc, qint64 nSrcSize, qint64 nOutHint, bool bOutHintKnown, QByteArray *pResult,
                         PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (bFilterFlag) {
        // 7-Zip-modified NSIS (BCJ filter) is not supported here.
        return false;
    }

    switch (method) {
        case NMETHOD_LZMA: return _lzmaDecode(pSrc, nSrcSize, nOutHint, bOutHintKnown, pResult);
        case NMETHOD_DEFLATE: return _inflateRaw(pSrc, nSrcSize, nOutHint, bOutHintKnown, pResult);
        case NMETHOD_COPY: {
            qint64 nSize = bOutHintKnown ? (std::min)(nOutHint, nSrcSize) : nSrcSize;
            *pResult = QByteArray((const char *)pSrc, (int)nSize);
            return true;
        }
        case NMETHOD_BZIP2:
        default: return false;  // NSIS-modified BZip2 not supported
    }
}

// ---------------------------------------------------------------------------
// header / solid stream decoding
// ---------------------------------------------------------------------------

bool XNSIS::_decodeSolidStream(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    if (pContext->bSolidDecoded) {
        return !pContext->baSolid.isEmpty();
    }
    pContext->bSolidDecoded = true;

    QByteArray baCompressed = read_array_process(pContext->nDataStreamOffset, pContext->nDataSize, pPdStruct);
    if (baCompressed.isEmpty()) {
        return false;
    }

    bool bOk = _decodeBlock(pContext->method, pContext->bFilterFlag, (const quint8 *)baCompressed.constData(), baCompressed.size(), 0, false, &pContext->baSolid,
                            pPdStruct);
    return bOk && !pContext->baSolid.isEmpty();
}

bool XNSIS::_decodeHeader(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    const quint32 nHeaderSize = pContext->nHeaderSize;

    if (pContext->bIsSolid) {
        if (!_decodeSolidStream(pContext, pPdStruct)) {
            return false;
        }
        // solid layout: [4-byte HeaderSize][header][files...]
        if ((qint64)(4 + nHeaderSize) > pContext->baSolid.size()) {
            return false;
        }
        quint32 nStored = rd32((const quint8 *)pContext->baSolid.constData());
        if (nStored != nHeaderSize) {
            return false;
        }
        pContext->baHeader = pContext->baSolid.mid(4, nHeaderSize);
        return (quint32)pContext->baHeader.size() == nHeaderSize;
    }

    // non-solid: header is its own block right after the 4-byte size word
    if (!pContext->bHeaderIsCompressed || (pContext->method == NMETHOD_COPY)) {
        pContext->baHeader = read_array_process(pContext->nDataStreamOffset + 4, nHeaderSize, pPdStruct);
        return (quint32)pContext->baHeader.size() == nHeaderSize;
    }

    QByteArray baCompressed = read_array_process(pContext->nDataStreamOffset + 4, pContext->nNonSolidStartOffset, pPdStruct);
    if ((quint32)baCompressed.size() != pContext->nNonSolidStartOffset) {
        return false;
    }

    bool bOk = _decodeBlock(pContext->method, pContext->bFilterFlag, (const quint8 *)baCompressed.constData(), baCompressed.size(), nHeaderSize, true,
                            &pContext->baHeader, pPdStruct);
    return bOk && ((quint32)pContext->baHeader.size() == nHeaderSize);
}

// ---------------------------------------------------------------------------
// string helpers (operate on pContext->baHeader string table)
// ---------------------------------------------------------------------------

void XNSIS::_appendVar(QString *pRes, quint32 nIndex, const UNPACK_CONTEXT *pContext) const
{
    Q_UNUSED(pContext)
    *pRes += '$';
    if (nIndex < 20) {
        if (nIndex >= 10) {
            *pRes += 'R';
            nIndex -= 10;
        }
        *pRes += QString::number(nIndex);
    } else {
        const unsigned nNumInternal = 20 + (sizeof(kVarStrings) / sizeof(kVarStrings[0]));
        if (nIndex < nNumInternal) {
            *pRes += QString::fromLatin1(kVarStrings[nIndex - 20]);
        } else {
            *pRes += '_';
            *pRes += QString::number(nIndex - nNumInternal);
            *pRes += '_';
        }
    }
}

void XNSIS::_appendShellString(QString *pRes, unsigned nIndex1, unsigned nIndex2, const UNPACK_CONTEXT *pContext) const
{
    if ((nIndex1 & 0x80) != 0) {
        unsigned nOffset = (nIndex1 & 0x3F);
        if (nOffset >= pContext->nNumStringChars) {
            *pRes += "$_ERROR_STR_";
            return;
        }

        const quint8 *pStr = (const quint8 *)pContext->baHeader.constData() + pContext->nStringsPos;
        int nId = -1;
        QString sValue;
        if (pContext->bIsUnicode) {
            const quint8 *p = pStr + nOffset * 2;
            QString sReg;
            for (unsigned i = 0; i < 256; i++) {
                quint16 c = rd16(p + i * 2);
                if (c == 0) {
                    break;
                }
                sReg += QChar(c);
            }
            if (sReg == "ProgramFilesDir") {
                nId = 0;
            } else if (sReg == "CommonFilesDir") {
                nId = 1;
            }
            sValue = sReg;
        } else {
            const char *p = (const char *)pStr + nOffset;
            sValue = QString::fromLatin1(p);
            if (sValue == "ProgramFilesDir") {
                nId = 0;
            } else if (sValue == "CommonFilesDir") {
                nId = 1;
            }
        }

        *pRes += (nId >= 0) ? (nId == 0 ? "$PROGRAMFILES" : "$COMMONFILES") : "$_ERROR_UNSUPPORTED_VALUE_REGISTRY_";
        if ((nIndex1 & 0x40) != 0) {
            *pRes += "64";
        }
        if (nId < 0) {
            *pRes += '(';
            *pRes += sValue;
            *pRes += ')';
        }
        return;
    }

    *pRes += '$';
    if (nIndex1 < kNumShellStrings && kShellStrings[nIndex1]) {
        *pRes += QString::fromLatin1(kShellStrings[nIndex1]);
        return;
    }
    if (nIndex2 < kNumShellStrings && kShellStrings[nIndex2]) {
        *pRes += QString::fromLatin1(kShellStrings[nIndex2]);
        return;
    }
    *pRes += QString("$_ERROR_UNSUPPORTED_SHELL_[%1,%2]").arg(nIndex1).arg(nIndex2);
}

QString XNSIS::_readStringRaw(const UNPACK_CONTEXT *pContext, quint32 nStrPos) const
{
    QString sResult;

    if ((qint32)nStrPos < 0) {
        return QString("$(LSTR_%1)").arg((quint32) - ((qint32)nStrPos + 1));
    }
    if (nStrPos >= pContext->nNumStringChars) {
        return QString("$_ERROR_STR_");
    }

    const quint8 *pData = (const quint8 *)pContext->baHeader.constData();
    const qint64 nHeaderSize = pContext->baHeader.size();
    const bool bIsPark = (pContext->nNsisType >= NSISTYPE_PARK1);
    const bool bIsNsis3 = (pContext->nNsisType == NSISTYPE_NSIS3);

    if (pContext->bIsUnicode) {
        qint64 nPos = pContext->nStringsPos + (qint64)nStrPos * 2;

        if (bIsPark) {
            for (;;) {
                if (nPos + 2 > nHeaderSize) break;
                unsigned c = rd16(pData + nPos);
                nPos += 2;
                if (c == 0) break;
                if (c < 0x80) {
                    sResult += QChar((ushort)c);
                    continue;
                }
                if (IS_PARK_SPEC_CHAR(c)) {
                    if (nPos + 2 > nHeaderSize) break;
                    unsigned n = rd16(pData + nPos);
                    nPos += 2;
                    if (n == 0) break;
                    if (c != PARK_CODE_SKIP) {
                        if (c == PARK_CODE_SHELL) {
                            _appendShellString(&sResult, n & 0xFF, n >> 8, pContext);
                        } else {
                            CONVERT_NUMBER_PARK(n);
                            if (c == PARK_CODE_VAR) {
                                _appendVar(&sResult, n, pContext);
                            } else {
                                sResult += QString("$(LSTR_%1)").arg(n);
                            }
                        }
                        continue;
                    }
                    c = n;
                }
                sResult += QChar((ushort)c);
            }
        } else {
            // NSIS-3 unicode
            for (;;) {
                if (nPos + 2 > nHeaderSize) break;
                unsigned c = rd16(pData + nPos);
                nPos += 2;
                if (c > NS_3_CODE_SKIP) {
                    sResult += QChar((ushort)c);
                    continue;
                }
                if (c == 0) break;
                if (nPos + 2 > nHeaderSize) break;
                unsigned n = rd16(pData + nPos);
                nPos += 2;
                if (n == 0) break;
                if (c == NS_3_CODE_SKIP) {
                    sResult += QChar((ushort)n);
                    continue;
                }
                if (c == NS_3_CODE_SHELL) {
                    _appendShellString(&sResult, n & 0xFF, n >> 8, pContext);
                } else {
                    CONVERT_NUMBER_NS_3_UNICODE(n);
                    if (c == NS_3_CODE_VAR) {
                        _appendVar(&sResult, n, pContext);
                    } else {
                        sResult += QString("$(LSTR_%1)").arg(n);
                    }
                }
            }
        }
        return sResult;
    }

    // ANSI
    qint64 nPos = pContext->nStringsPos + nStrPos;
    QByteArray baResult;

    if (!bIsNsis3) {
        for (;;) {
            if (nPos >= nHeaderSize) break;
            quint8 c = pData[nPos++];
            if (c == 0) break;
            if (IS_NS_SPEC_CHAR(c)) {
                if (nPos >= nHeaderSize) break;
                quint8 c0 = pData[nPos++];
                if (c0 == 0) break;
                if (c != NS_CODE_SKIP) {
                    if (nPos >= nHeaderSize) break;
                    quint8 c1 = pData[nPos++];
                    if (c1 == 0) break;
                    QString sTok;
                    if (c == NS_CODE_SHELL) {
                        _appendShellString(&sTok, c0, c1, pContext);
                    } else {
                        unsigned n = DECODE_NUMBER_FROM_2_CHARS(c0, c1);
                        if (c == NS_CODE_VAR) {
                            _appendVar(&sTok, n, pContext);
                        } else {
                            sTok = QString("$(LSTR_%1)").arg(n);
                        }
                    }
                    baResult += sTok.toLatin1();
                    continue;
                }
                c = c0;
            }
            baResult += (char)c;
        }
    } else {
        // NSIS-3 ANSI
        for (;;) {
            if (nPos >= nHeaderSize) break;
            quint8 c = pData[nPos++];
            if (c <= NS_3_CODE_SKIP) {
                if (c == 0) break;
                if (nPos >= nHeaderSize) break;
                quint8 c0 = pData[nPos++];
                if (c0 == 0) break;
                if (c != NS_3_CODE_SKIP) {
                    if (nPos >= nHeaderSize) break;
                    quint8 c1 = pData[nPos++];
                    if (c1 == 0) break;
                    QString sTok;
                    if (c == NS_3_CODE_SHELL) {
                        _appendShellString(&sTok, c0, c1, pContext);
                    } else {
                        unsigned n = DECODE_NUMBER_FROM_2_CHARS(c0, c1);
                        if (c == NS_3_CODE_VAR) {
                            _appendVar(&sTok, n, pContext);
                        } else {
                            sTok = QString("$(LSTR_%1)").arg(n);
                        }
                    }
                    baResult += sTok.toLatin1();
                    continue;
                }
                c = c0;
            }
            baResult += (char)c;
        }
    }

    return QString::fromLocal8Bit(baResult.constData(), baResult.size());
}

qint32 XNSIS::_getVarIndex(const UNPACK_CONTEXT *pContext, quint32 nStrPos) const
{
    if (nStrPos >= pContext->nNumStringChars) {
        return -1;
    }
    const quint8 *pStr = (const quint8 *)pContext->baHeader.constData() + pContext->nStringsPos;
    const bool bIsPark = (pContext->nNsisType >= NSISTYPE_PARK1);

    if (pContext->bIsUnicode) {
        if (pContext->nNumStringChars - nStrPos < 3 * 2) {
            return -1;
        }
        const quint8 *p = pStr + (qint64)nStrPos * 2;
        unsigned code = rd16(p);
        if (bIsPark) {
            if (code != PARK_CODE_VAR) return -1;
            quint32 n = rd16(p + 2);
            if (n == 0) return -1;
            CONVERT_NUMBER_PARK(n);
            return (qint32)n;
        }
        if (code != NS_3_CODE_VAR) return -1;
        quint32 n = rd16(p + 2);
        if (n == 0) return -1;
        CONVERT_NUMBER_NS_3_UNICODE(n);
        return (qint32)n;
    }

    if (pContext->nNumStringChars - nStrPos < 4) {
        return -1;
    }
    const quint8 *p = pStr + nStrPos;
    unsigned c = p[0];
    if (pContext->nNsisType == NSISTYPE_NSIS3) {
        if (c != NS_3_CODE_VAR) return -1;
    } else if (c != NS_CODE_VAR) {
        return -1;
    }
    unsigned c0 = p[1];
    if (c0 == 0) return -1;
    unsigned c1 = p[2];
    if (c1 == 0) return -1;
    return (qint32)DECODE_NUMBER_FROM_2_CHARS(c0, c1);
}

qint32 XNSIS::_getVarIndex(const UNPACK_CONTEXT *pContext, quint32 nStrPos, quint32 *pResOffset) const
{
    *pResOffset = 0;
    qint32 nVar = _getVarIndex(pContext, nStrPos);
    if (nVar < 0) {
        return nVar;
    }
    if (pContext->bIsUnicode) {
        if (pContext->nNumStringChars - nStrPos < 2 * 2) return -1;
        *pResOffset = 2;
    } else {
        if (pContext->nNumStringChars - nStrPos < 3) return -1;
        *pResOffset = 3;
    }
    return nVar;
}

bool XNSIS::_isAbsolutePathVar(const UNPACK_CONTEXT *pContext, quint32 nStrPos) const
{
    qint32 nVar = _getVarIndex(pContext, nStrPos);
    switch (nVar) {
        case kVar_INSTDIR:
        case kVar_EXEDIR:
        case kVar_TEMP:
        case kVar_PLUGINSDIR: return true;
    }
    return false;
}

bool XNSIS::_isGoodString(const UNPACK_CONTEXT *pContext, quint32 nStrPos) const
{
    if (nStrPos >= pContext->nNumStringChars) {
        return false;
    }
    if (nStrPos == 0) {
        return true;
    }
    const quint8 *p = (const quint8 *)pContext->baHeader.constData() + pContext->nStringsPos;
    unsigned c;
    if (pContext->bIsUnicode) {
        c = rd16(p + (qint64)nStrPos * 2 - 2);
    } else {
        c = p[nStrPos - 1];
    }
    return (c == 0 || c == '\\');
}

quint32 XNSIS::_getCmd(const UNPACK_CONTEXT *pContext, quint32 nCmd) const
{
    Q_UNUSED(pContext)
    // Park/log command-id translation only affects opcodes >= EW_REGISTERDLL (44).
    // The opcodes we use for extraction are all below that, so identity is correct.
    return nCmd;
}

bool XNSIS::_uninstallerPatch(const QByteArray &baPatch, QByteArray *pDest)
{
    // The uninstaller data is a sequence of [len:u32][offset:u32][len bytes] edits
    // applied onto a copy of the installer's PE stub, terminated by a zero length.
    const quint8 *p = (const quint8 *)baPatch.constData();
    qint64 nSize = baPatch.size();
    quint8 *pDst = (quint8 *)pDest->data();
    const qint64 nDestSize = pDest->size();

    for (;;) {
        if (nSize < 4) {
            return false;
        }
        quint32 nLen = rd32(p);
        if (nLen == 0) {
            return (nSize == 4);
        }
        if (nSize < 8) {
            return false;
        }
        quint32 nOffs = rd32(p + 4);
        p += 8;
        nSize -= 8;
        if (((qint64)nLen > nSize) || ((qint64)nOffs > nDestSize) || ((qint64)nLen > nDestSize - (qint64)nOffs)) {
            return false;
        }
        memcpy(pDst + nOffs, p, nLen);
        p += nLen;
        nSize -= nLen;
    }
}

// ---------------------------------------------------------------------------
// header parse + instruction walk
// ---------------------------------------------------------------------------

void XNSIS::_detectNsisType(UNPACK_CONTEXT *pContext, quint32 nEntriesOffset, quint32 nEntriesNum)
{
    Q_UNUSED(nEntriesOffset)
    Q_UNUSED(nEntriesNum)

    pContext->nNsisType = NSISTYPE_NSIS2;

    const quint8 *pStr = (const quint8 *)pContext->baHeader.constData() + pContext->nStringsPos;
    const quint32 nNum = pContext->nNumStringChars;

    bool bStrongNsis = false;

    if (nNum > 2) {
        if (pContext->bIsUnicode) {
            quint32 num = nNum - 2;
            for (quint32 i = 0; i < num; i++) {
                if (rd16(pStr + (qint64)i * 2) == 0) {
                    unsigned c2 = rd16(pStr + 2 + (qint64)i * 2);
                    if (c2 == NS_3_CODE_VAR) {
                        if ((rd16(pStr + 4 + (qint64)i * 2) & 0x8080) == 0x8080) {
                            bStrongNsis = true;
                            break;
                        }
                    }
                }
            }
            pContext->nNsisType = bStrongNsis ? NSISTYPE_NSIS3 : NSISTYPE_PARK1;
        } else {
            quint32 num = nNum - 2;
            for (quint32 i = 0; i < num; i++) {
                if (pStr[i] == 0) {
                    quint8 c2 = pStr[i + 1];
                    if (c2 == NS_3_CODE_VAR) {
                        if ((pStr[i + 2] & 0x80) != 0) {
                            bStrongNsis = true;
                            break;
                        }
                    }
                }
            }
            pContext->nNsisType = bStrongNsis ? NSISTYPE_NSIS3 : NSISTYPE_NSIS2;
        }
    }
}

bool XNSIS::_parseHeader(UNPACK_CONTEXT *pContext)
{
    const quint8 *p = (const quint8 *)pContext->baHeader.constData();
    const qint64 nSize = pContext->baHeader.size();

    // detect 32/64-bit block-header layout
    bool bIs64 = false;
    if (nSize >= (qint64)(4 + 12 * 8)) {
        bIs64 = true;
        for (int k = 0; k < 8; k++) {
            if (rd32(p + 4 + 12 * k + 4) != 0) {
                bIs64 = false;
                break;
            }
        }
    }
    pContext->bIs64Bit = bIs64;

    const unsigned nBhoSize = bIs64 ? 12 : 8;
    if (nSize < (qint64)(4 + nBhoSize * 8)) {
        return false;
    }

    auto parseBH = [&](int k, quint32 *pOffset, quint32 *pNum) {
        const quint8 *pb = p + 4 + nBhoSize * k;
        *pOffset = rd32(pb);
        *pNum = rd32(pb + nBhoSize - 4);
    };

    quint32 nEntriesOffset, nEntriesNum;
    quint32 nStringsOffset, nStringsNum;
    quint32 nLangOffset, nLangNum;
    parseBH(2, &nEntriesOffset, &nEntriesNum);
    parseBH(3, &nStringsOffset, &nStringsNum);
    parseBH(4, &nLangOffset, &nLangNum);
    Q_UNUSED(nStringsNum)
    Q_UNUSED(nLangNum)

    pContext->nStringsPos = nStringsOffset;

    if (((qint64)nStringsOffset > nSize) || ((qint64)nLangOffset > nSize) || ((qint64)nEntriesOffset > nSize)) {
        return false;
    }
    if (nLangOffset < nStringsOffset) {
        return false;
    }

    quint32 nStringTableSize = nLangOffset - nStringsOffset;
    if (nStringTableSize < 2) {
        return false;
    }
    const quint8 *pStrData = p + nStringsOffset;
    if (pStrData[nStringTableSize - 1] != 0) {
        return false;
    }

    pContext->bIsUnicode = (rd16(pStrData) == 0);
    pContext->nNumStringChars = nStringTableSize;
    if (pContext->bIsUnicode) {
        if ((nStringTableSize & 1) != 0) {
            return false;
        }
        pContext->nNumStringChars >>= 1;
        if (pStrData[nStringTableSize - 2] != 0) {
            return false;
        }
    }

    if (nEntriesNum > (1u << 25)) {
        return false;
    }
    if ((qint64)nEntriesNum * kCmdSize > nSize - (qint64)nEntriesOffset) {
        return false;
    }

    _detectNsisType(pContext, nEntriesOffset, nEntriesNum);

    QStringList prefixes;
    if (!_readEntries(pContext, nEntriesOffset, nEntriesNum, &prefixes)) {
        return false;
    }

    _sortItems(pContext);

    return true;
}

bool XNSIS::_readEntries(UNPACK_CONTEXT *pContext, quint32 nEntriesOffset, quint32 nEntriesNum, QStringList *pPrefixes)
{
    const quint8 *pBase = (const quint8 *)pContext->baHeader.constData();
    const quint8 *p = pBase + nEntriesOffset;

    pPrefixes->clear();
    pPrefixes->append("$INSTDIR");

    QString sSpecOutdir;
    const quint32 nSpecOutdirVar = kVar_Spec_OUTDIR;  // NSIS 2.26+

    pContext->listEntries.clear();

    for (quint32 kkk = 0; kkk < nEntriesNum; kkk++, p += kCmdSize) {
        quint32 nCmd = _getCmd(pContext, rd32(p));
        quint32 params[kNumCommandParams];
        for (unsigned i = 0; i < kNumCommandParams; i++) {
            params[i] = rd32(p + 4 + 4 * i);
        }

        switch (nCmd) {
            case EW_CREATEDIR: {
                bool bIsSetOutPath = (params[1] != 0);
                if (bIsSetOutPath) {
                    quint32 nPar0 = params[0];
                    quint32 nResOffset = 0;
                    qint32 nIdx = _getVarIndex(pContext, nPar0, &nResOffset);
                    if ((nIdx == (qint32)nSpecOutdirVar) || (nIdx == kVar_OUTDIR)) {
                        nPar0 += nResOffset;
                    }
                    QString sRaw = _readStringRaw(pContext, nPar0);
                    if (nIdx == (qint32)nSpecOutdirVar) {
                        sRaw = sSpecOutdir + sRaw;
                    } else if (nIdx == kVar_OUTDIR) {
                        sRaw = pPrefixes->last() + sRaw;
                    }
                    pPrefixes->append(sRaw);
                }
                break;
            }

            case EW_ASSIGNVAR: {
                if (params[0] == nSpecOutdirVar) {
                    sSpecOutdir.clear();
                    quint32 nResOffset = 0;
                    qint32 nIdx = _getVarIndex(pContext, params[1], &nResOffset);
                    // IsVarStr(params[1], kVar_OUTDIR): the string is exactly "$OUTDIR"
                    bool bIsOutdir = false;
                    if (nIdx == kVar_OUTDIR) {
                        // check terminator right after the var
                        quint32 nAfter = params[1] + nResOffset;
                        if (nAfter <= pContext->nNumStringChars) {
                            QString sTail = _readStringRaw(pContext, nAfter);
                            bIsOutdir = sTail.isEmpty();
                        }
                    }
                    if (bIsOutdir && (params[2] == 0) && (params[3] == 0)) {
                        sSpecOutdir = pPrefixes->last();
                    }
                }
                break;
            }

            case EW_EXTRACTFILE: {
                FILE_ENTRY entry = {};
                entry.bSizeDefined = false;
                entry.bIsEmptyFile = false;

                quint32 nPar1 = params[1];
                QString sName = _readStringRaw(pContext, nPar1);
                bool bIsAbs = _isAbsolutePathVar(pContext, nPar1) || nsisIsAbsolutePath(sName);

                QString sPrefix;
                bool bHasPrefix = false;
                if (!bIsAbs) {
                    sPrefix = pPrefixes->last();
                    bHasPrefix = true;
                }
                entry.sFileName = nsisReducedName(sPrefix, bHasPrefix, sName);
                entry.nPos = params[2];
                entry.nMTimeLow = params[3];
                entry.nMTimeHigh = params[4];
                pContext->listEntries.append(entry);
                break;
            }

            case EW_WRITEUNINSTALLER: {
                FILE_ENTRY entry = {};
                entry.bSizeDefined = false;
                entry.bIsEmptyFile = false;

                QString sName = _readStringRaw(pContext, params[0]);
                bool bIsAbs = _isAbsolutePathVar(pContext, params[0]) || nsisIsAbsolutePath(sName);
                QString sPrefix;
                bool bHasPrefix = false;
                if (!bIsAbs) {
                    sPrefix = pPrefixes->last();
                    bHasPrefix = true;
                }
                entry.sFileName = nsisReducedName(sPrefix, bHasPrefix, sName);
                entry.nPos = params[1];
                entry.bIsUninstaller = true;
                pContext->listEntries.append(entry);
                break;
            }

            default: break;
        }
    }

    return true;
}

void XNSIS::_sortItems(UNPACK_CONTEXT *pContext)
{
    QList<FILE_ENTRY> &list = pContext->listEntries;

    std::stable_sort(list.begin(), list.end(), [](const FILE_ENTRY &a, const FILE_ENTRY &b) { return a.nPos < b.nPos; });

    // drop consecutive duplicates (same position + same name)
    for (int i = 0; i + 1 < list.size();) {
        if ((list.at(i).nPos == list.at(i + 1).nPos) && (list.at(i).sFileName == list.at(i + 1).sFileName)) {
            list.removeAt(i + 1);
        } else {
            i++;
        }
    }

    // For solid archives we already have the decoded stream: fill in real sizes so
    // infoCurrent() can report them.
    if (pContext->bIsSolid && !pContext->baSolid.isEmpty()) {
        const quint8 *pSolid = (const quint8 *)pContext->baSolid.constData();
        const qint64 nSolidSize = pContext->baSolid.size();
        for (int i = 0; i < list.size(); i++) {
            qint64 nAbs = 4 + (qint64)pContext->nHeaderSize + list[i].nPos;
            if ((nAbs + 4) <= nSolidSize) {
                list[i].nSize = rd32(pSolid + nAbs);
                list[i].bSizeDefined = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------

bool XNSIS::_open(UNPACK_CONTEXT *pContext, PDSTRUCT *pPdStruct)
{
    // Compressed-data size = ArcSize - firstheader(0x1C) - CRC(4 if present)
    bool bThereIsCrc = ((pContext->nFlags & 8 /*ForceCrc*/) != 0) || ((pContext->nFlags & 4 /*NoCrc*/) == 0);
    qint64 nAvail = getSize() - pContext->nDataStreamOffset;
    qint64 nDataSize = (qint64)pContext->nArchiveSize - 0x1C - (bThereIsCrc ? 4 : 0);
    if (nDataSize > nAvail) {
        nDataSize = nAvail;
    }
    if (nDataSize <= 0) {
        return false;
    }
    pContext->nDataOffset = pContext->nDataStreamOffset;
    pContext->nDataSize = nDataSize;

    QByteArray baSig = read_array_process(pContext->nDataStreamOffset, (std::min)((qint64)64, nDataSize), pPdStruct);
    if (baSig.size() < 12) {
        return false;
    }

    if (!_detectMethod(pContext, (const quint8 *)baSig.constData(), baSig.size())) {
        return false;
    }

    if (!_decodeHeader(pContext, pPdStruct)) {
        return false;
    }

    if (!_parseHeader(pContext)) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

bool XNSIS::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = getInternalInfo(pPdStruct);
    if (!info.bIsValid) {
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->nFirstHeaderOffset = 0;
    pContext->nDataStreamOffset = 0;
    pContext->nFlags = 0;
    pContext->nHeaderSize = 0;
    pContext->nArchiveSize = 0;
    pContext->method = NMETHOD_DEFLATE;
    pContext->compressMethod = HANDLE_METHOD_UNKNOWN;
    pContext->bIsSolid = false;
    pContext->bFilterFlag = false;
    pContext->bHeaderIsCompressed = true;
    pContext->nNonSolidStartOffset = 0;
    pContext->nStringsPos = 0;
    pContext->nNumStringChars = 0;
    pContext->bIsUnicode = false;
    pContext->bIs64Bit = false;
    pContext->nNsisType = NSISTYPE_NSIS2;
    pContext->bIsNsis225 = false;
    pContext->bSolidDecoded = false;
    pContext->nDataOffset = 0;
    pContext->nDataSize = 0;

    if (_findFirstHeader(info.nSignatureOffset, pState->nTotalSize, pContext, pPdStruct)) {
        if (_open(pContext, pPdStruct)) {
            pState->nNumberOfRecords = pContext->listEntries.size();
        }
    }

    pState->pContext = pContext;

    return true;
}

XBinary::ARCHIVERECORD XNSIS::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};

    if (!pState || !pState->pContext) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;

    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) {
        return result;
    }

    const FILE_ENTRY &entry = pContext->listEntries.at(nIndex);

    result.nStreamOffset = pContext->nDataOffset;
    result.nStreamSize = pContext->nDataSize;

    result.mapProperties[FPART_PROP_ORIGINALNAME] = entry.sFileName.isEmpty() ? QString("file_%1").arg(nIndex, 4, 10, QChar('0')) : entry.sFileName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)(entry.bSizeDefined ? entry.nSize : 0);
    result.mapProperties[FPART_PROP_HANDLEMETHOD] = pContext->compressMethod;
    result.mapProperties[FPART_PROP_ISFOLDER] = false;
    result.mapProperties[FPART_PROP_ISSOLID] = pContext->bIsSolid;

    return result;
}

bool XNSIS::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;

    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) {
        return false;
    }

    const FILE_ENTRY &entry = pContext->listEntries.at(nIndex);

    // Obtain the item's raw (uncompressed) data.
    QByteArray baData;
    QByteArray baSolidTail;  // for a patched uninstaller: the block that follows the patch block

    if (pContext->bIsSolid) {
        if (!_decodeSolidStream(pContext, pPdStruct)) {
            return false;
        }
        const qint64 nSolidSize = pContext->baSolid.size();
        const quint8 *pSolid = (const quint8 *)pContext->baSolid.constData();

        qint64 nAbs = 4 + (qint64)pContext->nHeaderSize + entry.nPos;
        if ((nAbs + 4) > nSolidSize) {
            return false;
        }
        quint32 nSize = rd32(pSolid + nAbs);
        if (nSize == 0) {
            return true;  // empty file
        }
        if ((qint64)(nAbs + 4 + nSize) > nSolidSize) {
            return false;
        }
        baData = QByteArray((const char *)pSolid + nAbs + 4, (int)nSize);

        // A patched uninstaller is stored as two consecutive blocks: the patch, then
        // the uninstaller's own stub archive appended after the patched PE stub.
        if (entry.bIsUninstaller) {
            qint64 nAbsB = nAbs + 4 + nSize;
            if ((nAbsB + 4) <= nSolidSize) {
                quint32 nSizeB = rd32(pSolid + nAbsB);
                if ((nSizeB > 0) && ((qint64)(nAbsB + 4 + nSizeB) <= nSolidSize)) {
                    baSolidTail = QByteArray((const char *)pSolid + nAbsB + 4, (int)nSizeB);
                }
            }
        }
    } else {
        // non-solid: [4-byte size|flag][block]
        qint64 nItemPos = pContext->nDataStreamOffset + 4 + pContext->nNonSolidStartOffset + entry.nPos;
        quint32 nSizeField = read_uint32(nItemPos, false);
        bool bIsCompressed = (nSizeField & kMask_IsCompressed) != 0;
        quint32 nSize = nSizeField & ~kMask_IsCompressed;

        if (nSize == 0) {
            return true;  // empty file
        }

        QByteArray baBlock = read_array_process(nItemPos + 4, nSize, pPdStruct);
        if ((quint32)baBlock.size() != nSize) {
            return false;
        }

        if (!bIsCompressed) {
            baData = baBlock;
        } else if (!_decodeBlock(pContext->method, pContext->bFilterFlag, (const quint8 *)baBlock.constData(), baBlock.size(), 0, false, &baData, pPdStruct)) {
            return false;
        }
    }

    // Patched uninstaller: apply the patch stream onto a copy of the installer's PE stub,
    // then append the following block (the uninstaller's own stub archive).
    if (entry.bIsUninstaller && (pContext->nFirstHeaderOffset > 0)) {
        QByteArray baStub = read_array_process(0, pContext->nFirstHeaderOffset, pPdStruct);
        if (baStub.size() == pContext->nFirstHeaderOffset) {
            QByteArray baPatched = baStub;
            if (_uninstallerPatch(baData, &baPatched)) {
                baPatched.append(baSolidTail);
                qint64 nWritten = pDevice->write(baPatched);
                return (nWritten == baPatched.size());
            }
        }
        // not a patch stream (e.g. NSIS 3.08 unpatched uninstaller): fall through to raw output
    }

    qint64 nWritten = pDevice->write(baData);
    return (nWritten == baData.size());
}

bool XNSIS::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) {
        return false;
    }

    pState->nCurrentIndex++;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XNSIS::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        pContext->listEntries.clear();
        pContext->baHeader.clear();
        pContext->baSolid.clear();
        delete pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}
