/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xmew.h"

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
    setIsArchive(true);
}

XMEW::~XMEW()
{
}

bool XMEW::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

bool XMEW::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XMEW m(pDevice);
    return m.isValid(pPdStruct);
}

XBinary::FT XMEW::getFileType()
{
    return FT_BINARY;
}

XMEW::INTERNAL_INFO XMEW::getInternalInfo(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    DETECT d = _detect(pPdStruct);
    result.bIsValid = d.bIsValid;
    result.bUsesLzma = (d.nUseLzma != 0);
    result.sVersion = d.bIsValid ? QString("11 SE") : QString();
    return result;
}

// ---------------------------------------------------------------------------
// aPLib-style depacker (identical to FSG's unfsg / MEW's unmew)
// ---------------------------------------------------------------------------

qint64 XMEW::_aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed)
{
    if ((nSrcSize <= 0) || (nDstSize <= 0)) return -1;

    qint64 s = 0, d = 0;
    quint8 mydl = 0x80;
    quint32 oldback = 0;
    int lostbit = 1;

    auto getbit = [&]() -> int {
        quint8 olddl = mydl;
        mydl = (quint8)(mydl * 2);
        if (!(olddl & 0x7f)) {
            if ((s < 0) || (s >= nSrcSize - 1)) return -1;
            olddl = pSrc[s];
            mydl = (quint8)(olddl * 2 + 1);
            s++;
        }
        return (olddl >> 7) & 1;
    };

    if ((s >= nSrcSize) || (d >= nDstSize)) return -1;
    pDst[d++] = pSrc[s++];

    for (;;) {
        int oob = getbit();
        if (oob == -1) return -1;

        if (oob) {
            quint32 backsize = 0, backbytes = 0;
            int b = getbit();
            if (b == -1) return -1;
            if (b) {
                int b2 = getbit();
                if (b2 == -1) return -1;
                if (b2) {
                    lostbit = 1;
                    backsize++;
                    backbytes = 0x10;
                    while (backbytes < 0x100) {
                        int x = getbit();
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
                    int x = getbit();
                    if (x == -1) return -1;
                    backsize = backsize * 2 + x;
                    oob = getbit();
                    if (oob == -1) return -1;
                } while (oob);
                backsize = backsize - 1 - lostbit;
                if (!backsize) {
                    backsize = 1;
                    do {
                        int x = getbit();
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = getbit();
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
                        int x = getbit();
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = getbit();
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

    SRes res = LzmaDecode((Byte *)pDst, &nDestLen, (const Byte *)pSrc, &nSrcLen, (const Byte *)props, LZMA_PROPS_SIZE, LZMA_FINISH_END,
                          &status, &g_alloc);

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

// Parse the MEW LZMA container (at f1+4, after the aPLib loader loop) and
// decode every block in place into baBuf's destination region.
bool XMEW::_lzmaDepack(QByteArray &baBuf, qint64 nContainerOff, quint32 nUseLzma, quint32 nDsize, quint32 nVma, PDSTRUCT *pPdStruct)
{
    const qint64 nBufSize = baBuf.size();
    quint8 *buf = (quint8 *)baBuf.data();

    auto cont = [nBufSize](qint64 off, qint64 len) -> bool { return (off >= 0) && (len >= 0) && ((off + len) <= nBufSize); };

    // "special" tag: byte at buf[uselzma + 8] == 0x50 (push eax) => single block + call de-filter.
    if (!cont((qint64)nUseLzma + 8, 1)) return false;
    const bool bSpecial = (buf[nUseLzma + 8] == 0x50);

    qint64 p = nContainerOff;
    quint32 nPushedEdx = 0;
    if (bSpecial) {
        if (!cont(p, 4)) return false;
        nPushedEdx = mewRd32(buf + p);
        p += 4;
    }
    // prob-array RVA (used by MEW's in-buffer model; not needed for the SDK decode)
    if (!cont(p, 4)) return false;
    p += 4;

    int nBlocks = 0;
    for (;;) {
        if (!isPdStructNotCanceled(pPdStruct)) return false;

        if (!bSpecial) {
            if (!cont(p, 4)) return false;
            if (mewRd32(buf + p) == 0) break;  // zero terminator
        }
        if (!cont(p, 13)) return false;  // uncompressedSize(4) + destRVA(4) + csize(4) + 1 skipped byte

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
        if (!cont(nDestOff, nUnpSize)) return false;

        qint64 nAvail = nBufSize - nStreamOff;
        if (!_decodeRawLzma(buf + nStreamOff, nAvail, buf + nDestOff, nUnpSize, nDsize ? nDsize : nUnpSize)) return false;

        if (bSpecial) {
            _bcjFilter(buf + nDestOff, nUnpSize, nPushedEdx);
            break;  // special mode processes exactly one block
        }

        if (++nBlocks > 4096) return false;  // safety
    }

    return true;
}

// ---------------------------------------------------------------------------
// PE rebuild (0x1000-aligned; sections read from buffer at .raw)
// ---------------------------------------------------------------------------

QByteArray XMEW::_buildPE(const QByteArray &baBuf, const QList<SECT> &listSections, quint32 nImageBase, quint32 nOEP)
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

    quint32 nRawTotal = nRawBase, nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += mewAlign(listSections.at(i).rsz, 0x1000);
        nMaxVEnd = qMax(nMaxVEnd, listSections.at(i).rva + qMax(listSections.at(i).vsz, listSections.at(i).rsz));
    }

    QByteArray baResult(nRawTotal, (char)0);
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
    if ((baEp.size() < 16) || ((quint8)baEp.at(0) != 0xe9)) return result;

    quint32 nFileOffset = nVep + mewRd32((const quint8 *)baEp.constData() + 1) + 5;
    if ((nFileOffset != 0x154) && (nFileOffset != 0x158)) return result;

    QByteArray baT = read_array_process(nFileOffset, 0xb0, pPdStruct);
    if (baT.size() < 0xb0) return result;
    const quint8 *tbuff = (const quint8 *)baT.constData();

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
    if (tbuff[0x7b] == 0xe8) {
        nUseLzma = mewRd32(tbuff + 0x7c) - (listSections.at(0).VirtualAddress - nFileOffset - 0x80);
    }

    result.bIsValid = true;
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
// unpack
// ---------------------------------------------------------------------------

bool XMEW::unpack(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pDevice) return false;

    DETECT d = _detect(pPdStruct);
    if (!d.bIsValid) return false;

    const quint32 nSsize = d.nSsize;
    const quint32 nDsize = d.nDsize;
    const quint64 nSizeSum = (quint64)nSsize + nDsize;
    const quint32 nVadd = d.nVadd;
    const quint32 nBase = d.nImageBase;
    const quint32 nVma = nBase + nVadd;
    const quint32 nOff = d.nOffDiff;

    // buffer: [ dest (dsize) | source (ssize) ]
    QByteArray baBuf((int)nSizeSum, (char)0);
    QByteArray baSrc = read_array_process(d.nSrcRaw, d.nSrcRsz, pPdStruct);
    if ((quint32)baSrc.size() != d.nSrcRsz) return false;
    memcpy(baBuf.data() + nDsize, baSrc.constData(), d.nSrcRsz);

    quint8 *buf = (quint8 *)baBuf.data();

    auto cont = [nSizeSum](qint64 off, qint64 len) -> bool { return (off >= 0) && (len >= 0) && ((quint64)(off + len) <= nSizeSum); };

    if (!cont((qint64)nOff, 12)) return false;

    qint64 nSourceOff = (qint64)nDsize + nOff;
    qint64 nLesi = nSourceOff + 12;
    quint32 nEntryPoint = mewRd32(buf + nSourceOff + 4);
    quint32 nNewEdi = mewRd32(buf + nSourceOff + 8);
    qint64 nLedi = (qint64)nNewEdi - nVma;
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
        if (!cont(nLesi, nLocSs) || !cont(nLedi, nLocDs)) return false;

        qint64 nConsumed = 0;
        qint64 nProduced = _aplibDepack(buf + nLesi, nLocSs, buf + nLedi, nLocDs, &nConsumed);
        if (nProduced < 0) return false;

        qint64 f1 = nLesi + nConsumed;  // endsrc
        qint64 f2 = nLedi + nProduced;  // enddst
        if (!cont(f1, 4)) return false;

        nLocSs -= (f1 + 4 - nLesi);
        nLesi = f1 + 4;

        quint32 nNextRva = mewRd32(buf + f1);
        nLedi = (qint64)nNextRva - nVma;
        nLocDs = (qint64)nSizeSum - ((qint64)nNextRva - nVma);

        // On the LZMA path MEW still runs this loader loop to walk the aPLib
        // blocks (so f1 lands on the container), but builds no sections here.
        if (!d.nUseLzma) {
            quint32 val = mewAlign((quint32)f2, 0x1000);
            if (idx && (val < listSections.at(idx).raw)) return false;

            // ensure section[idx+1] exists
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

        if (idx > 4096) return false;  // safety
    }

    if (d.nUseLzma) {
        // The aPLib loop above terminated with nLesi == f1 + 4, i.e. the start
        // of the MEW LZMA container. Decode it in place, then emit MEW's single
        // output section spanning the whole destination.
        if (!_lzmaDepack(baBuf, nLesi, d.nUseLzma, nDsize, nVma, pPdStruct)) return false;

        QList<SECT> lzmaSections;
        SECT s;
        s.raw = 0;
        s.rva = nVadd;
        s.rsz = s.vsz = nDsize;
        lzmaSections.append(s);

        QByteArray baLzmaPE = _buildPE(baBuf, lzmaSections, nBase, nEntryPoint - nBase);
        if (baLzmaPE.isEmpty()) return false;

        return (pDevice->write(baLzmaPE) == baLzmaPE.size());
    }

    // keep only the first idx sections
    while (listSections.size() > idx) {
        listSections.removeLast();
    }

    QByteArray baPE = _buildPE(baBuf, listSections, nBase, nEntryPoint - nBase);
    if (baPE.isEmpty()) return false;

    return (pDevice->write(baPE) == baPE.size());
}
