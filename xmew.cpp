/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xmew.h"
#include "xmaterializedunpackguard.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <climits>
#include <cstdlib>
#include <cstring>

#include "LzmaDec.h"  // public-domain LZMA-SDK decoder (XArchive/3rdparty/lzma/src)

static inline quint32 mewRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 mewAlign(quint32 v, quint32 a)
{
    return (v + a - 1) & ~(a - 1);
}

XMEW::XMEW(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XMEW::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XMEW::~XMEW()
{
    QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (pLifetimeState) pLifetimeState->bOwnerAlive = false;
    m_pUnpackLifetimeState.clear();
    if (pLifetimeState && !pLifetimeState->bOperationInProgress) {
        const QSet<UNPACK_CONTEXT *> setContextsCopy = pLifetimeState->setContexts;
        pLifetimeState->setContexts.clear();
        for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
    }
}

XMEW::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XMEW::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive && !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XMEW::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XMEW> guardedThis(this);
    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XMEW::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XMEW m(pDevice);
    return m.isValid(pPdStruct);
}

XBinary::FT XMEW::getFileType()
{
    return FT_PE32_MEW;
}

XMEW::INTERNAL_INFO XMEW::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    DETECT d = _detect(pPdStruct);
    result.bIsValid = d.bIsValid;
    result.bUsesLzma = (d.nUseLzma != 0);
    result.sVersion = d.bIsValid ? ((d.nVersion == 10) ? QString("10") : QString("11 SE")) : QString();
    return result;
}

// Cache format-specific parsing together with the XBinary memory map.
bool XMEW::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XMEW> guardedThis(this);
    const bool bAlreadyHandled = guardedThis->isInternalInfoHandled();
    if (!guardedThis) return false;

    if (!bAlreadyHandled) {
        const quint64 nTransaction = guardedThis->beginInternalInfoTransaction();
        if (!nTransaction) return false;

        // The transaction supplies the recursion sentinel. Keep every
        // source-derived value local until the same binding is revalidated.
        guardedThis->m_internalInfo = INTERNAL_INFO();
        INTERNAL_INFO info = guardedThis->_getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }

        const XBinary::_MEMORY_MAP memoryMap = guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        info.memoryMap = memoryMap;

        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        guardedThis->m_internalInfo = info;
        if (!guardedThis->commitInternalInfoTransaction(nTransaction, static_cast<XBinary::INTERNAL_INFO *>(&guardedThis->m_internalInfo))) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
    }

    return true;
}

void *XMEW::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XMEW> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XMEW::setInternalInfo(void *pInternalInfo)
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

// ---------------------------------------------------------------------------
// aPLib-style depacker (identical to FSG's unfsg / MEW's unmew)
// ---------------------------------------------------------------------------

static int mewGetBit(const quint8 *pSrc, qint64 nSrcSize, qint64 *ps, quint8 *pmydl)
{
    quint8 olddl = *pmydl;
    *pmydl = (quint8)(*pmydl * 2);
    if (!(olddl & 0x7f)) {
        if ((*ps < 0) || (*ps >= nSrcSize - 1)) return -1;
        olddl = pSrc[*ps];
        *pmydl = (quint8)(olddl * 2 + 1);
        (*ps)++;
    }
    return (olddl >> 7) & 1;
}

qint64 XMEW::_aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed)
{
    if ((nSrcSize <= 0) || (nDstSize <= 0)) return -1;

    qint64 s = 0, d = 0;
    quint8 mydl = 0x80;
    quint32 oldback = 0;
    int lostbit = 1;

    if ((s >= nSrcSize) || (d >= nDstSize)) return -1;
    pDst[d++] = pSrc[s++];

    for (;;) {
        int oob = mewGetBit(pSrc, nSrcSize, &s, &mydl);
        if (oob == -1) return -1;

        if (oob) {
            quint32 backsize = 0, backbytes = 0;
            int b = mewGetBit(pSrc, nSrcSize, &s, &mydl);
            if (b == -1) return -1;
            if (b) {
                int b2 = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                if (b2 == -1) return -1;
                if (b2) {
                    lostbit = 1;
                    backsize++;
                    backbytes = 0x10;
                    while (backbytes < 0x100) {
                        int x = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backbytes = backbytes * 2 + x;
                    }
                    backbytes &= 0xff;
                    if (!backbytes) {
                        if (d >= nDstSize) return -1;
                        pDst[d++] = 0x00;
                        continue;
                    }
                } else {
                    if (s >= nSrcSize) return -1;
                    backbytes = pSrc[s];
                    backsize = backsize * 2 + (backbytes & 1);
                    backbytes = (backbytes & 0xff) >> 1;
                    s++;
                    if (!backbytes) break;
                    backsize += 2;
                    oldback = backbytes;
                    lostbit = 0;
                }
            } else {
                backsize = 1;
                do {
                    int x = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (x == -1) return -1;
                    backsize = backsize * 2 + x;
                    oob = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (oob == -1) return -1;
                } while (oob);
                backsize = backsize - 1 - lostbit;
                if (!backsize) {
                    backsize = 1;
                    do {
                        int x = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (oob == -1) return -1;
                    } while (oob);
                    backbytes = oldback;
                } else {
                    if (s >= nSrcSize) return -1;
                    backbytes = pSrc[s];
                    backbytes += (backsize - 1) << 8;
                    backsize = 1;
                    s++;
                    do {
                        int x = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = mewGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (oob == -1) return -1;
                    } while (oob);
                    if (backbytes >= 0x7d00) backsize++;
                    if (backbytes >= 0x500) backsize++;
                    if (backbytes <= 0x7f) backsize += 2;
                    oldback = backbytes;
                }
                lostbit = 0;
            }

            if ((backbytes == 0) || ((qint64)backbytes > d) || (d + (qint64)backsize > nDstSize)) return -1;
            while (backsize--) {
                pDst[d] = pDst[d - backbytes];
                d++;
            }
        } else {
            if ((d >= nDstSize) || (s >= nSrcSize)) return -1;
            pDst[d++] = pSrc[s++];
            lostbit = 1;
        }
    }

    if (pnSrcConsumed) *pnSrcConsumed = s;
    return d;
}

// ---------------------------------------------------------------------------
// LZMA path
//
// MEW 11 SE's LZMA payload is a *stock* LZMA1 stream (range coder + probability
// model bit-exact against the LZMA SDK) with lc=4, lp=0, pb=2 hardcoded (props
// byte 0x5E) and no container header of its own. The compressed blocks are
// framed by a small MEW-specific structure at f1+4 (see _lzmaDepack); each raw
// stream begins with the normal 5-byte range-coder init (first byte 0x00) and
// has no end marker, so the exact uncompressed size bounds the decode.
//
// The decode itself is delegated to the public-domain LZMA-SDK LzmaDec (already
// vendored in XArchive/3rdparty/lzma); only the framing and the optional x86
// call/jmp de-filter below are reimplemented from format facts. No GPL code is
// reused. Verified byte-exact (except the runtime-resolved IAT, reconstructed
// separately) against MEW11_SE_1.1/1.2 clear32.unp.exe.
// ---------------------------------------------------------------------------

static void *xmewLzmaAlloc(ISzAllocPtr, size_t nSize)
{
    return malloc(nSize);
}
static void xmewLzmaFree(ISzAllocPtr, void *pAddr)
{
    free(pAddr);
}

bool XMEW::_decodeRawLzma(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, quint32 nDstSize, quint32 nDictSize)
{
    if ((nSrcSize <= (qint64)LZMA_REQUIRED_INPUT_MAX) || (nDstSize == 0)) return false;

    static const ISzAlloc g_alloc = {xmewLzmaAlloc, xmewLzmaFree};

    if (nDictSize < 0x1000) nDictSize = 0x1000;

    // 5-byte props: [ (pb*5 + lp)*9 + lc = 0x5E ][ dictSize little-endian ]
    quint8 props[LZMA_PROPS_SIZE];
    props[0] = 0x5E;  // lc=4, lp=0, pb=2
    props[1] = (quint8)(nDictSize & 0xff);
    props[2] = (quint8)((nDictSize >> 8) & 0xff);
    props[3] = (quint8)((nDictSize >> 16) & 0xff);
    props[4] = (quint8)((nDictSize >> 24) & 0xff);

    SizeT nDestLen = (SizeT)nDstSize;
    SizeT nSrcLen = (SizeT)nSrcSize;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

    SRes res = LzmaDecode((Byte *)pDst, &nDestLen, (const Byte *)pSrc, &nSrcLen, (const Byte *)props, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &g_alloc);

    // MEW streams carry no end marker; the container's exact uncompressed size
    // is authoritative, so SZ_OK + the full length produced is the success test
    // (status is informational and may be MAYBE_FINISHED_WITHOUT_MARK).
    (void)status;
    return (res == SZ_OK) && (nDestLen == (SizeT)nDstSize);
}

// "special" mode only: MEW stores absolute call/jmp targets, so convert the
// first nLen decoded bytes' e8/e9 operands back to relative. Mirrors mew.c:
// dword = byteswap(dword) - offset - 1. (Not exercised by the known corpus.)
void XMEW::_bcjFilter(quint8 *pData, quint32 nSize, quint32 nLen)
{
    if (nLen < 5) return;
    if (nLen > nSize) nLen = nSize;
    for (quint32 i = 0; i + 5 < nLen; i++) {
        if ((pData[i] == 0xe8) || (pData[i] == 0xe9)) {
            quint32 v = mewRd32(pData + i + 1);
            quint32 bs = ((v & 0xff) << 24) | (((v >> 8) & 0xff) << 16) | (((v >> 16) & 0xff) << 8) | ((v >> 24) & 0xff);
            quint32 out = bs - i - 1;
            pData[i + 1] = (quint8)(out & 0xff);
            pData[i + 2] = (quint8)((out >> 8) & 0xff);
            pData[i + 3] = (quint8)((out >> 16) & 0xff);
            pData[i + 4] = (quint8)((out >> 24) & 0xff);
            i += 4;
        }
    }
}

static bool mewCont(qint64 nBufSize, qint64 off, qint64 len)
{
    return (off >= 0) && (len >= 0) && ((off + len) <= nBufSize);
}

// Parse the MEW LZMA container (at f1+4, after the aPLib loader loop) and
// decode every block in place into baBuf's destination region.
bool XMEW::_lzmaDepack(QByteArray &baBuf, qint64 nContainerOff, quint32 nUseLzma, quint32 nDsize, quint32 nVma, PDSTRUCT *pPdStruct)
{
    const qint64 nBufSize = baBuf.size();
    quint8 *buf = (quint8 *)baBuf.data();

    // "special" tag.  The decompressor stub prologue is
    //   55 8B EC 83 EC 40 53 AD 89 45 D8 <X> ...
    // where X selects the two container shapes:
    //   0x56 (push esi)         -> exactly one block, then an x86 call/jmp de-filter
    //   0x89 (mov [ebp-1c],esi) -> zero-terminated block list
    // libclamav tests `+8 == 0x50` instead; that byte is 0x89 in both shapes for
    // the MEW 11/11 SE builds seen here, so it is kept only as a fallback for
    // other builds.  Both shapes use the same container layout (no extra dword),
    // and the de-filter covers the whole decoded block.
    if (!mewCont(nBufSize, (qint64)nUseLzma + 8, 4)) return false;
    const bool bSpecial = (buf[nUseLzma + 0x0b] == 0x56) || (buf[nUseLzma + 8] == 0x50);

    qint64 p = nContainerOff;
    // prob-array RVA (used by MEW's in-buffer model; not needed for the SDK decode)
    if (!mewCont(nBufSize, p, 4)) return false;
    p += 4;

    int nBlocks = 0;
    for (;;) {
        if (!isPdStructNotCanceled(pPdStruct)) return false;

        if (!bSpecial) {
            if (!mewCont(nBufSize, p, 4)) return false;
            if (mewRd32(buf + p) == 0) break;  // zero terminator
        }
        if (!mewCont(nBufSize, p, 13)) return false;  // uncompressedSize(4) + destRVA(4) + csize(4) + 1 skipped byte

        quint32 nUnpSize = mewRd32(buf + p);
        p += 4;
        quint32 nDestRva = mewRd32(buf + p);
        p += 4;
        quint32 nCsize = mewRd32(buf + p);
        p += 5;  // 4-byte size + 1 skipped byte ("yes, five")
        qint64 nStreamOff = p;
        p += nCsize;

        if (nUnpSize == 0) return false;
        qint64 nDestOff = (qint64)nDestRva - (qint64)nVma;
        if (!mewCont(nBufSize, nDestOff, nUnpSize)) return false;

        qint64 nAvail = nBufSize - nStreamOff;
        if (!_decodeRawLzma(buf + nStreamOff, nAvail, buf + nDestOff, nUnpSize, nDsize ? nDsize : nUnpSize)) return false;

        if (bSpecial) {
            _bcjFilter(buf + nDestOff, nUnpSize, nUnpSize);
            break;  // special mode processes exactly one block
        }

        if (++nBlocks > 4096) return false;  // safety
    }

    return true;
}

// ---------------------------------------------------------------------------
// PE rebuild (0x1000-aligned; sections read from buffer at .raw)
// ---------------------------------------------------------------------------

QByteArray XMEW::_buildPE(const QByteArray &baBuf, const QList<SECT> &listSections, quint32 nImageBase, quint32 nOEP, qint64 nOutputLimit)
{
    int nSectCount = listSections.size();
    if (nSectCount <= 0) return QByteArray();

    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    quint32 nFirstRva = listSections.at(0).rva;
    quint32 nRawBase = mewAlign(nHeaderBase + 0x28 * nSectCount, 0x200);
    const bool bGhost = (nFirstRva > mewAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = mewAlign(nHeaderBase + 0x28 * (nSectCount + 1), 0x200);
    }

    quint64 nRawTotal = nRawBase;
    quint32 nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += mewAlign(listSections.at(i).rsz, 0x1000);
        nMaxVEnd = qMax(nMaxVEnd, listSections.at(i).rva + qMax(listSections.at(i).vsz, listSections.at(i).rsz));
    }

    if ((nRawTotal > INT_MAX) || ((nOutputLimit >= 0) && (nRawTotal > (quint64)nOutputLimit))) return QByteArray();
    QByteArray baResult((int)nRawTotal, (char)0);
    char *p = baResult.data();

    _write_uint16(p + 0, 0x5A4D);
    _write_uint32(p + 0x3C, 0x40);
    char *pe = p + 0x40;
    _write_uint32(pe + 0, 0x00004550);
    char *fh = pe + 4;
    _write_uint16(fh + 0, 0x014C);
    _write_uint16(fh + 2, (quint16)(nSectCount + (bGhost ? 1 : 0)));
    _write_uint16(fh + 16, 0x00E0);
    _write_uint16(fh + 18, 0x010F);
    char *oh = fh + 20;
    _write_uint16(oh + 0, 0x010B);
    _write_uint32(oh + 16, nOEP);
    _write_uint32(oh + 28, nImageBase);
    _write_uint32(oh + 32, 0x1000);
    _write_uint32(oh + 36, 0x200);
    _write_uint16(oh + 40, 4);
    _write_uint16(oh + 48, 4);
    _write_uint32(oh + 56, mewAlign(nMaxVEnd, 0x1000));
    _write_uint32(oh + 60, nRawBase);
    _write_uint16(oh + 68, 2);
    _write_uint32(oh + 92, 16);

    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;
    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = mewAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, nFirstRva - nGhostVA);
        _write_uint32(sec + 12, nGhostVA);
        _write_uint32(sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    for (int i = 0; i < nSectCount; i++) {
        const SECT &u = listSections.at(i);
        quint32 nRsz = mewAlign(u.rsz, 0x1000);
        char szName[9];
        snprintf(szName, sizeof(szName), ".clam%.2d", i + 1);
        memcpy(sec, szName, qMin<size_t>(8, strlen(szName)));
        _write_uint32(sec + 8, u.vsz ? u.vsz : u.rsz);
        _write_uint32(sec + 12, u.rva);
        _write_uint32(sec + 16, nRsz);
        _write_uint32(sec + 20, nRaw);
        _write_uint32(sec + 36, 0xE00000E0);

        if (((qint64)u.raw + u.rsz) <= baBuf.size()) {
            memcpy(baResult.data() + nRaw, baBuf.constData() + u.raw, u.rsz);
        }
        nRaw += nRsz;
        sec += 0x28;
    }

    return baResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XMEW::DETECT XMEW::_detect(PDSTRUCT *pPdStruct)
{
    DETECT result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n < 2) return result;

    // empty-section pair (dest = i, source = i+1)
    int i = -1;
    for (int k = 0; k + 1 < n; k++) {
        if ((listSections.at(k).SizeOfRawData == 0) && (listSections.at(k).Misc.VirtualSize != 0) && (listSections.at(k + 1).SizeOfRawData != 0) &&
            (listSections.at(k + 1).Misc.VirtualSize != 0)) {
            i = k;
            break;
        }
    }
    if (i < 0) return result;

    const quint32 nVep = pe.getOptionalHeader_AddressOfEntryPoint();
    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();

    qint64 nEpOffset = pe.relAddressToOffset(nVep);
    if (nEpOffset == -1) return result;
    QByteArray baEp = read_array_process(nEpOffset, 16, pPdStruct);
    if (baEp.size() < 16) return result;

    // MEW 11/11 SE enter with a bare `jmp rel32`; MEW 10 prefixes `xor eax,eax`.
    qint32 nPrefix = 0;
    if ((quint8)baEp.at(0) == 0xe9) {
        nPrefix = 0;
    } else if (((quint8)baEp.at(0) == 0x33) && ((quint8)baEp.at(1) == 0xc0) && ((quint8)baEp.at(2) == 0xe9)) {
        nPrefix = 2;
    } else {
        return result;
    }

    quint32 nFileOffset = nVep + nPrefix + mewRd32((const quint8 *)baEp.constData() + nPrefix + 1) + 5;
    if ((nFileOffset != 0x154) && (nFileOffset != 0x155) && (nFileOffset != 0x158)) return result;

    QByteArray baT = read_array_process(nFileOffset, 0xb0, pPdStruct);
    if (baT.size() < 0xb0) return result;
    const quint8 *tbuff = (const quint8 *)baT.constData();

    // Both generations open with `mov esi, imm32`; the following two bytes
    // separate them.  MEW 10 reads its header with `lodsb / xchg eax,ecx`,
    // MEW 11 with `mov ebx,esi`.
    if (tbuff[0] != 0xbe) return result;
    quint32 nVersion = 0;
    if ((tbuff[5] == 0xac) && (tbuff[6] == 0x91)) {
        nVersion = 10;
    } else if ((tbuff[5] == 0x8b) && (tbuff[6] == 0xde)) {
        nVersion = 11;
    } else {
        return result;
    }

    quint32 nOffDiff = mewRd32(tbuff + 1) - nImageBase;
    const XPE_DEF::IMAGE_SECTION_HEADER &srcSec = listSections.at(i + 1);
    const XPE_DEF::IMAGE_SECTION_HEADER &dstSec = listSections.at(i);

    if ((nOffDiff <= srcSec.VirtualAddress) || (nOffDiff >= srcSec.VirtualAddress + srcSec.PointerToRawData - 4)) return result;
    nOffDiff -= srcSec.VirtualAddress;

    quint32 nSsize = srcSec.Misc.VirtualSize;
    quint32 nDsize = dstSec.Misc.VirtualSize;
    if ((nSsize + nDsize < nSsize) || (nOffDiff >= nSsize + nDsize)) return result;
    if ((srcSec.SizeOfRawData < nOffDiff + 12) || (srcSec.SizeOfRawData > nSsize)) return result;

    quint32 nUseLzma = 0;
    if ((nVersion == 11) && (tbuff[0x7b] == 0xe8)) {
        nUseLzma = mewRd32(tbuff + 0x7c) - (listSections.at(0).VirtualAddress - nFileOffset - 0x80);
    }

    result.bIsValid = true;
    result.nVersion = nVersion;
    result.nIndex = i;
    result.nFileOffset = nFileOffset;
    result.nOffDiff = nOffDiff;
    result.nSsize = nSsize;
    result.nDsize = nDsize;
    result.nSrcRaw = srcSec.PointerToRawData;
    result.nSrcRsz = srcSec.SizeOfRawData;
    result.nVadd = listSections.at(0).VirtualAddress;
    result.nImageBase = nImageBase;
    result.nUseLzma = nUseLzma;

    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XMEW::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XMEW::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    struct PROGRESS_ALIVE_PROBE {
        PDSTRUCT *pPdStruct;
        const PDSTRUCTLIFETIME *pProgressLifetime;
        bool operator()() const { return !pPdStruct || XBinary::isPdStructLifetimeAlive(*pProgressLifetime); }
    };
    const PROGRESS_ALIVE_PROBE isProgressAlive = {pPdStruct, &progressLifetime};
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XMEW> guardedThis(this);

    if (pState->pContext || !pState->baUnpackSourceToken.isEmpty()) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pOldContext || !pLifetimeState->setContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState) ||
            (pOldContext->baToken != pState->baUnpackSourceToken))
            return false;
        pLifetimeState->setContexts.remove(pOldContext);
        *pState = UNPACK_STATE();
        delete pOldContext;
    } else {
        *pState = UNPACK_STATE();
    }
    if (!isProgressAlive() || !guardedThis || !isPdStructNotCanceled(pPdStruct)) return false;
    const QSharedPointer<LIFETIME_STATE> pOwnerLifetimeState = pLifetimeState;

    QPointer<QIODevice> guardedSource(getDevice());
    const quint64 nGeneration = getDeviceGeneration();
    const bool bIsImage = isImage();
    const XADDR nModuleAddress = getModuleAddress();
    if (!guardedSource) return false;
    const QString sFileName = getUnpackedFileName(guardedSource.data());
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;
    const qint64 nSourceSize = guardedSource->size();
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) || (nSourceSize < 0))
        return false;
    QScopedPointer<XMaterializedUnpackGuard> pSourceGuard(XMaterializedUnpackGuard::bind(guardedSource.data(), pPdStruct));
    if (!isProgressAlive() || !pSourceGuard || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()))
        return false;

    QScopedPointer<QIODevice> pSnapshot(createFileBuffer(nSourceSize, pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pSnapshot || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()))
        return false;
    const bool bCopied = copyDeviceMemory(guardedSource.data(), 0, pSnapshot.data(), 0, nSourceSize, pPdStruct);
    if (!isProgressAlive() || !bCopied || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;

    XMEW worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._getInternalInfo(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) || !info.bIsValid)
        return false;
    QByteArray baData;
    const bool bUnpacked = worker._unpackToBuffer(baData, nOutputLimit, pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) || !bUnpacked ||
        baData.isEmpty() || !isPdStructNotCanceled(pPdStruct))
        return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
    pContext->baData = baData;
    pContext->sFileName = sFileName;
    pContext->sInfo = QString("MEW %1").arg(info.sVersion);
    pContext->pSourceDevice = guardedSource;
    pContext->pOwnerState = pState;
    pContext->baToken = QUuid::createUuid().toRfc4122();
    pContext->nDeviceGeneration = nGeneration;
    pContext->nSourceSize = nSourceSize;
    pContext->nCurrentOffset = 0;
    pContext->nCurrentIndex = 0;
    if (pContext->baToken.isEmpty()) return false;
    const bool bSourceFinal = pSourceGuard->validateAndFinalize(pPdStruct);
    if (!isProgressAlive() || !bSourceFinal || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
        !isPdStructNotCanceled(pPdStruct))
        return false;
    pContext->pSourceGuard = pSourceGuard.take();

    pState->nCurrentOffset = 0;
    pState->nTotalSize = nSourceSize;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 1;
    pState->mapUnpackProperties = mapProperties;
    pState->pContext = pContext.data();
    pState->baUnpackSourceToken = pContext->baToken;
    pOwnerLifetimeState->setContexts.insert(pContext.take());
    if (!guardedThis || !pOwnerLifetimeState->bOwnerAlive) return false;
    return true;
}

XBinary::ARCHIVERECORD XMEW::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XMEW> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) || (pContext->pSourceDevice.data() != getDevice()) || (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) || (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize))
        return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis || !pLifetimeState->bOwnerAlive ||
        !pLifetimeState->setContexts.contains(pContext) || (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken))
        return result;

    result.nStreamOffset = 0;
    result.nStreamSize = pContext->baData.size();
    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, pContext->sFileName);
    result.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, pContext->nSourceSize);
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, (qint64)pContext->baData.size());
    result.mapProperties.insert(FPART_PROP_HANDLEMETHOD, (qint32)HANDLE_METHOD_FILE);
    result.mapProperties.insert(FPART_PROP_ISFOLDER, false);
    result.mapProperties.insert(FPART_PROP_INFO, pContext->sInfo);

    return guardedThis ? result : ARCHIVERECORD();
}

bool XMEW::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) || (pContext->pSourceDevice.data() != getDevice()) || (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) || (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= 1) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize))
        return false;

    return false;
}

bool XMEW::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    if (!pState->pContext && pState->baUnpackSourceToken.isEmpty()) {
        *pState = UNPACK_STATE();
        return true;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pContext || !pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || (pContext->baToken != pState->baUnpackSourceToken))
        return false;
    pLifetimeState->setContexts.remove(pContext);
    *pState = UNPACK_STATE();
    delete pContext;
    return true;
}

bool XMEW::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XMEW> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !guardedOutput || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) || (pContext->pSourceDevice.data() != getDevice()) || (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) || (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize))
        return false;

    const bool bOpen = guardedOutput->isOpen();
    if (!guardedThis || !guardedOutput || !bOpen) return false;
    const bool bWritable = guardedOutput->isWritable();
    if (!guardedThis || !guardedOutput || !bWritable) return false;
    const bool bSequential = guardedOutput->isSequential();
    if (!guardedThis || !guardedOutput || bSequential) return false;
    const QIODevice::OpenMode openMode = guardedOutput->openMode();
    if (!guardedThis || !guardedOutput || (openMode & (QIODevice::Append | QIODevice::Text)) || !isResizeEnable(guardedOutput.data())) return false;
    QPointer<QIODevice> guardedSource(pContext->pSourceDevice);
    if (guardedSource && devicesAlias(guardedSource.data(), guardedOutput.data())) return false;
    if (!guardedThis || !guardedOutput) return false;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis || !guardedOutput || !pLifetimeState->bOwnerAlive ||
        !pLifetimeState->setContexts.contains(pContext) || (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken))
        return false;

    // This override bypasses the base decode chain's per-entry gate; account
    // the member here. Produced bytes are charged by writeUnpackData.
    if (pState->spOutputBudget) {
        if (!pState->spOutputBudget->beginEntry(pState->nCurrentIndex, pContext->sFileName)) {
            if (pState->spOutputBudget->isEnforcing()) {
                XBinary::setPdStructErrorString(pPdStruct, tr("Unpacked output exceeds the configured limit"));
                return false;
            }
            XBinary::OUTPUT_BUDGET::noteShadowRefusal(pState->spOutputBudget.data());
        }
    }

    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    const bool bResult = writeUnpackData(&writeState, guardedOutput.data(), pContext->baData, pPdStruct);
    const bool bSourceCurrent = bResult && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bAuthenticated = bSourceCurrent && guardedThis && guardedOutput && pLifetimeState->bOwnerAlive && pLifetimeState->setContexts.contains(pContext) &&
                                (pState->pContext == pContext) && (pContext->pOwnerState == pState) && (pState->baUnpackSourceToken == pContext->baToken) &&
                                (pState->nCurrentIndex == pContext->nCurrentIndex) && (pState->nCurrentOffset == pContext->nCurrentOffset) &&
                                (pState->nNumberOfRecords == 1) && (pState->nTotalSize == pContext->nSourceSize);
    if (!bResult || !bAuthenticated) {
        if (bResult && guardedOutput) {
            resize(guardedOutput.data(), 0);
            if (guardedOutput) guardedOutput->seek(0);
        }
        return false;
    }
    pContext->nCurrentOffset = writeState.nCurrentOffset;
    pState->nCurrentOffset = writeState.nCurrentOffset;
    return true;
}

static bool mewContSum(quint64 nSizeSum, qint64 off, qint64 len)
{
    return (off >= 0) && (len >= 0) && ((quint64)(off + len) <= nSizeSum);
}

// MEW 10 uses the same aPLib bitstream as MEW 11 but a different loader shape:
// the header is `db nBlocks | dd helperTable | dd sourceVA | nBlocks*dd destVA |
// dd importFixerVA`, the source stream is continuous across blocks instead of
// carrying a next-RVA after each one, and the original entry point is the dword
// immediately preceding the import fixer rather than a header field.
bool XMEW::_unpackMew10(QByteArray &baBuf, const DETECT &d, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    const quint64 nSizeSum = (quint64)d.nSsize + d.nDsize;
    const quint32 nBase = d.nImageBase;
    const quint32 nVma = nBase + d.nVadd;
    quint8 *buf = (quint8 *)baBuf.data();

    const qint64 nHdr = (qint64)d.nDsize + d.nOffDiff;
    if (!mewContSum(nSizeSum, nHdr, 1)) return false;
    const quint32 nBlocks = buf[nHdr];
    if ((nBlocks == 0) || (nBlocks > 64)) return false;
    if (!mewContSum(nSizeSum, nHdr, 13 + 4 * (qint64)nBlocks)) return false;

    qint64 nLesi = (qint64)mewRd32(buf + nHdr + 5) - nVma;  // continuous source stream

    QList<SECT> listSections;
    for (quint32 k = 0; k < nBlocks; k++) {
        if (!isPdStructNotCanceled(pPdStruct)) return false;
        const quint32 nDestVa = mewRd32(buf + nHdr + 9 + 4 * k);
        const qint64 nLedi = (qint64)nDestVa - nVma;
        if ((nLesi < 0) || ((quint64)nLesi >= nSizeSum)) return false;
        if ((nLedi < 0) || ((quint64)nLedi >= nSizeSum)) return false;

        qint64 nConsumed = 0;
        const qint64 nProduced = _aplibDepack(buf + nLesi, (qint64)nSizeSum - nLesi, buf + nLedi, (qint64)nSizeSum - nLedi, &nConsumed);
        if ((nProduced < 0) || (nConsumed <= 0)) return false;

        // The final block lands in the source section: it is the import fixer,
        // not a section of the original image.
        if (nLedi + nProduced <= (qint64)d.nDsize) {
            if (nDestVa < nBase) return false;
            SECT s;
            s.raw = (quint32)nLedi;
            s.rva = nDestVa - nBase;
            s.rsz = s.vsz = (quint32)nProduced;
            listSections.append(s);
        }
        nLesi += nConsumed;
    }
    if (listSections.isEmpty()) return false;

    const qint64 nFixer = (qint64)mewRd32(buf + nHdr + 9 + 4 * nBlocks) - nVma;
    if (!mewContSum(nSizeSum, nFixer - 4, 4)) return false;
    const quint32 nStoredOep = mewRd32(buf + nFixer - 4);
    if (nStoredOep < nBase) return false;

    QByteArray baPE = _buildPE(baBuf, listSections, nBase, nStoredOep - nBase, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;
    return true;
}

bool XMEW::_unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    DETECT d = _detect(pPdStruct);
    if (!d.bIsValid) return false;

    const quint32 nSsize = d.nSsize;
    const quint32 nDsize = d.nDsize;
    const quint64 nSizeSum = (quint64)nSsize + nDsize;
    if ((nSizeSum > INT_MAX) || ((nOutputLimit >= 0) && ((quint64)nDsize > (quint64)nOutputLimit))) return false;
    const quint32 nVadd = d.nVadd;
    const quint32 nBase = d.nImageBase;
    const quint32 nVma = nBase + nVadd;
    const quint32 nOff = d.nOffDiff;

    QByteArray baBuf((int)nSizeSum, (char)0);
    QByteArray baSrc = read_array_process(d.nSrcRaw, d.nSrcRsz, pPdStruct);
    if ((quint32)baSrc.size() != d.nSrcRsz) return false;
    memcpy(baBuf.data() + nDsize, baSrc.constData(), d.nSrcRsz);

    quint8 *buf = (quint8 *)baBuf.data();

    if (d.nVersion == 10) return _unpackMew10(baBuf, d, baOut, nOutputLimit, pPdStruct);

    if (!mewContSum(nSizeSum, (qint64)nOff, 12)) return false;

    qint64 nSourceOff = (qint64)nDsize + nOff;
    qint64 nLesi = nSourceOff + 12;
    quint32 nEntryPoint = mewRd32(buf + nSourceOff + 4);
    quint32 nNewEdi = mewRd32(buf + nSourceOff + 8);
    qint64 nLedi = (qint64)nNewEdi - nVma;
    // The remaining destination budget spans the whole ssize+dsize buffer, not
    // just dsize: with LZMA the loader's last aPLib block lands in the *source*
    // section (it is the LZMA stub), which is above dsize.  Using dsize made
    // that budget negative and failed every LZMA-packed sample.
    qint64 nLocDs = (qint64)nSizeSum - ((qint64)nNewEdi - nVma);
    qint64 nLocSs = (qint64)nSsize - 12 - nOff;

    QList<SECT> listSections;
    SECT sec0;
    sec0.raw = 0;
    sec0.rva = nVadd;
    sec0.rsz = sec0.vsz = 0;
    listSections.append(sec0);

    int idx = 0;
    for (;;) {
        if (!isPdStructNotCanceled(pPdStruct)) return false;
        if (!mewContSum(nSizeSum, nLesi, nLocSs) || !mewContSum(nSizeSum, nLedi, nLocDs)) return false;

        qint64 nConsumed = 0;
        qint64 nProduced = _aplibDepack(buf + nLesi, nLocSs, buf + nLedi, nLocDs, &nConsumed);
        if (nProduced < 0) return false;

        qint64 f1 = nLesi + nConsumed;
        qint64 f2 = nLedi + nProduced;
        if (!mewContSum(nSizeSum, f1, 4)) return false;

        nLocSs -= (f1 + 4 - nLesi);
        nLesi = f1 + 4;

        quint32 nNextRva = mewRd32(buf + f1);
        nLedi = (qint64)nNextRva - nVma;
        nLocDs = (qint64)nSizeSum - ((qint64)nNextRva - nVma);

        if (!d.nUseLzma) {
            quint32 val = mewAlign((quint32)f2, 0x1000);
            if (idx && (val < listSections.at(idx).raw)) return false;

            if (listSections.size() < idx + 2) {
                SECT s;
                s.raw = val;
                s.rva = val + nVadd;
                s.rsz = s.vsz = 0;
                listSections.append(s);
            } else {
                listSections[idx + 1].raw = val;
                listSections[idx + 1].rva = val + nVadd;
            }
            listSections[idx].rsz = listSections[idx].vsz = (idx ? (val - listSections.at(idx).raw) : val);

            if (listSections.at(idx).raw + listSections.at(idx).rsz > nDsize) return false;
        }

        idx++;
        if (!nNextRva) break;
        if (idx > 4096) return false;
    }

    if (d.nUseLzma) {
        if (!_lzmaDepack(baBuf, nLesi, d.nUseLzma, nDsize, nVma, pPdStruct)) return false;

        QList<SECT> lzmaSections;
        SECT s;
        s.raw = 0;
        s.rva = nVadd;
        s.rsz = s.vsz = nDsize;
        lzmaSections.append(s);

        QByteArray baLzmaPE = _buildPE(baBuf, lzmaSections, nBase, nEntryPoint - nBase, nOutputLimit);
        if (baLzmaPE.isEmpty()) return false;

        baOut = baLzmaPE;
        return true;
    }

    while (listSections.size() > idx) {
        listSections.removeLast();
    }

    QByteArray baPE = _buildPE(baBuf, listSections, nBase, nEntryPoint - nBase, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}
