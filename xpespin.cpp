/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xpespin.h"

#include <cstring>

static inline quint32 spinRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint8 spinRol8(quint8 v, quint8 n)
{
    return (quint8)((v << (n & 7)) | (v >> ((8 - n) & 7)));
}

static inline quint8 spinRor8(quint8 v, quint8 n)
{
    return (quint8)((v >> (n & 7)) | (v << ((8 - n) & 7)));
}

static inline quint32 spinAlign(quint32 v, quint32 a)
{
    return (v + a - 1) & ~(a - 1);
}

// bounds test: [off, off+len) fits within a buffer of nSize bytes
static inline bool spinCont(qint64 off, qint64 len, qint64 nSize)
{
    return (off >= 0) && (len >= 0) && (off + len <= nSize);
}

// single-bit reader with the aPLib sentinel-bit refill scheme; returns -1 on OOB.
// *pS (source cursor) and *pMydl (bit buffer) are shared with the depack loop.
static int spinGetBit(const quint8 *pSrc, qint64 nSrcSize, qint64 *pS, quint8 *pMydl)
{
    quint8 olddl = *pMydl;
    *pMydl = (quint8)(*pMydl * 2);
    if (!(olddl & 0x7f)) {
        if ((*pS < 0) || (*pS >= nSrcSize - 1)) return -1;
        olddl = pSrc[*pS];
        *pMydl = (quint8)(olddl * 2 + 1);
        (*pS)++;
    }
    return (olddl >> 7) & 1;
}

XPESPIN::XPESPIN(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XPESPIN::~XPESPIN()
{
}

bool XPESPIN::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

bool XPESPIN::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XPESPIN s(pDevice);
    return s.isValid(pPdStruct);
}

XBinary::FT XPESPIN::getFileType()
{
    return FT_BINARY;
}

XPESPIN::INTERNAL_INFO XPESPIN::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// ---------------------------------------------------------------------------
// exec86 emulator + summit checksum
// ---------------------------------------------------------------------------

quint8 XPESPIN::_exec86(quint8 aelle, quint8 cielle, const quint8 *curremu, qint64 nEmuAvail, int *pRetval)
{
    int len = 0;
    *pRetval = 0;
    while (len < 0x24) {
        if (len >= nEmuAvail) {
            *pRetval = 1;
            return aelle;
        }
        quint8 opcode = curremu[len];
        len++;
        switch (opcode) {
            case 0xeb:
                len++;
                // fall through
            case 0x0a:
                len++;
                // fall through
            case 0x90:
            case 0xf8:
            case 0xf9:
                break;
            case 0x02:
                aelle += cielle;
                len++;
                break;
            case 0x2a:
                aelle -= cielle;
                len++;
                break;
            case 0x04:
                if (len >= nEmuAvail) { *pRetval = 1; return aelle; }
                aelle += curremu[len];
                len++;
                break;
            case 0x2c:
                if (len >= nEmuAvail) { *pRetval = 1; return aelle; }
                aelle -= curremu[len];
                len++;
                break;
            case 0x32:
                aelle ^= cielle;
                len++;
                break;
            case 0x34:
                if (len >= nEmuAvail) { *pRetval = 1; return aelle; }
                aelle ^= curremu[len];
                len++;
                break;
            case 0xfe:
                if ((len < nEmuAvail) && (curremu[len] == 0xc0))
                    aelle++;
                else
                    aelle--;
                len++;
                break;
            case 0xc0: {
                if (len >= nEmuAvail) { *pRetval = 1; return aelle; }
                quint8 support = curremu[len];
                len++;
                if (len >= nEmuAvail) { *pRetval = 1; return aelle; }
                if (support == 0xc0)
                    aelle = spinRol8(aelle, curremu[len]);
                else
                    aelle = spinRor8(aelle, curremu[len]);
                len++;
                break;
            }
            default:
                *pRetval = 1;
                return aelle;
        }
    }
    if ((len != 0x24) || (len >= nEmuAvail) || (curremu[len] != 0xaa)) {
        *pRetval = 1;
    }
    return aelle;
}

quint32 XPESPIN::_summit(const quint8 *pSrc, qint64 nSize)
{
    quint32 eax = 0xffffffff, ebx = 0xffffffff;
    while (nSize) {
        eax ^= ((quint32)(*pSrc++) << 8) & 0xff00;
        eax = (eax >> 3) & 0x1fffffff;
        for (int i = 0; i < 4; i++) {
            eax ^= (ebx >> 8) & 0xff;
            eax += 0x7801a108;
            eax ^= ebx;
            quint32 bb = ebx & 0xff;
            eax = (eax >> (bb & 31)) | (eax << ((32 - bb) & 31));
            quint32 swap = eax;
            eax = ebx;
            ebx = swap;
        }
        nSize--;
    }
    return ebx;
}

// aPLib depacker (== cli_unfsg); returns produced bytes or -1.
qint64 XPESPIN::_aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize)
{
    if ((nSrcSize <= 0) || (nDstSize <= 0)) return -1;
    qint64 s = 0, d = 0;
    quint8 mydl = 0x80;
    quint32 oldback = 0;
    int lostbit = 1;

    if ((s >= nSrcSize) || (d >= nDstSize)) return -1;
    pDst[d++] = pSrc[s++];

    for (;;) {
        int oob = spinGetBit(pSrc, nSrcSize, &s, &mydl);
        if (oob == -1) return -1;
        if (oob) {
            quint32 backsize = 0, backbytes = 0;
            int b = spinGetBit(pSrc, nSrcSize, &s, &mydl);
            if (b == -1) return -1;
            if (b) {
                int b2 = spinGetBit(pSrc, nSrcSize, &s, &mydl);
                if (b2 == -1) return -1;
                if (b2) {
                    lostbit = 1;
                    backsize++;
                    backbytes = 0x10;
                    while (backbytes < 0x100) {
                        int x = spinGetBit(pSrc, nSrcSize, &s, &mydl);
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
                    int x = spinGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (x == -1) return -1;
                    backsize = backsize * 2 + x;
                    oob = spinGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (oob == -1) return -1;
                } while (oob);
                backsize = backsize - 1 - lostbit;
                if (!backsize) {
                    backsize = 1;
                    do {
                        int x = spinGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = spinGetBit(pSrc, nSrcSize, &s, &mydl);
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
                        int x = spinGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = spinGetBit(pSrc, nSrcSize, &s, &mydl);
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
    return d;
}

// ---------------------------------------------------------------------------
// PE rebuild (blob of concatenated sections; 0x200-aligned)
// ---------------------------------------------------------------------------

QByteArray XPESPIN::_buildPE(const QByteArray &baBlob, const QList<SECT> &listSections, quint32 nImageBase, quint32 nOEP)
{
    int nSectCount = listSections.size();
    if (nSectCount <= 0) return QByteArray();


    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    quint32 nFirstRva = listSections.at(0).rva;
    quint32 nRawBase = spinAlign(nHeaderBase + 0x28 * nSectCount, 0x200);
    const bool bGhost = (nFirstRva > spinAlign(nRawBase, 0x1000));
    if (bGhost) nRawBase = spinAlign(nHeaderBase + 0x28 * (nSectCount + 1), 0x200);

    quint32 nRawTotal = nRawBase, nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += spinAlign(listSections.at(i).rsz, 0x200);
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
    _write_uint32(oh + 56, spinAlign(nMaxVEnd, 0x1000));
    _write_uint32(oh + 60, nRawBase);
    _write_uint16(oh + 68, 2);
    _write_uint32(oh + 92, 16);

    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;
    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = spinAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, nFirstRva - nGhostVA);
        _write_uint32(sec + 12, nGhostVA);
        _write_uint32(sec + 36, 0xE00000E0);
        sec += 0x28;
    }
    for (int i = 0; i < nSectCount; i++) {
        const SECT &u = listSections.at(i);
        quint32 nRsz = spinAlign(u.rsz, 0x200);
        char szName[9];
        snprintf(szName, sizeof(szName), ".clam%.2d", i + 1);
        memcpy(sec, szName, qMin<size_t>(8, strlen(szName)));
        _write_uint32(sec + 8, u.vsz ? u.vsz : u.rsz);
        _write_uint32(sec + 12, u.rva);
        _write_uint32(sec + 16, nRsz);
        _write_uint32(sec + 20, nRaw);
        _write_uint32(sec + 36, 0xE00000E0);
        if (((qint64)u.raw + u.rsz) <= baBlob.size()) {
            memcpy(baResult.data() + nRaw, baBlob.constData() + u.raw, u.rsz);
        }
        nRaw += nRsz;
        sec += 0x28;
    }
    return baResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XPESPIN::INTERNAL_INFO XPESPIN::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) return result;

    const quint32 nVep = pe.getOptionalHeader_AddressOfEntryPoint();
    const XPE_DEF::IMAGE_SECTION_HEADER &last = listSections.at(n - 1);

    if (nVep < last.VirtualAddress) return result;
    if (0x3217 - 4 > (qint64)last.VirtualAddress + last.SizeOfRawData) return result;
    if ((qint64)nVep >= (qint64)last.VirtualAddress + last.SizeOfRawData - 0x3217 - 4) return result;

    qint64 nEpOffset = pe.relAddressToOffset(nVep);
    if (nEpOffset == -1) return result;
    QByteArray baEp = read_array_process(nEpOffset, 16, pPdStruct);
    if (baEp.size() < 14) return result;

    if (memcmp(baEp.constData() + 4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) != 0) {
        return result;
    }

    result.bIsValid = true;
    result.sVersion = "1.3x";
    return result;
}

// ---------------------------------------------------------------------------
// unpack
// ---------------------------------------------------------------------------

bool XPESPIN::unpack(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pDevice) return false;
    if (!_detect(pPdStruct).bIsValid) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) return false;
    const int sectcnt = n - 1;

    const quint32 nVep = pe.getOptionalHeader_AddressOfEntryPoint();
    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();

    const qint64 nFileSize = getSize();
    QByteArray baSrc = read_array_process(0, nFileSize, pPdStruct);
    if (baSrc.size() != nFileSize) return false;
    quint8 *src = (quint8 *)baSrc.data();
    const qint64 ssize = nFileSize;

    const XPE_DEF::IMAGE_SECTION_HEADER &loader = listSections.at(sectcnt);
    const quint32 nLoaderRaw = loader.PointerToRawData;
    const quint32 nLoaderRsz = loader.SizeOfRawData;
    const quint32 nLoaderRva = loader.VirtualAddress;

    if (!spinCont(nLoaderRaw, nLoaderRsz, ssize) || (nLoaderRsz < 0x3300)) return false;

    // ---- Phase A: decrypt loader copy (spinned) ----
    QByteArray baSpin = baSrc.mid(nLoaderRaw, nLoaderRsz);
    quint8 *spin = (quint8 *)baSpin.data();
    const qint64 spinSize = baSpin.size();

    qint64 epA = (qint64)nVep - nLoaderRva;
    if ((epA < 0) || !spinCont(epA, 0x3300, spinSize)) return false;

    qint64 curr = epA + 0xdb;
    if (spin[curr] != 0xbb) return false;
    quint8 key8 = spin[curr + 1];
    curr += 5;
    if (spin[curr] != 0xb9) return false;
    quint32 len = spinRd32(spin + curr + 1);
    if (len != 0x11fe) return false;

    if (!spinCont(epA, (qint64)len + 0x1fe5 - 1, spinSize)) return false;

    // layer 1: xor backwards with key8--
    curr = epA + 0x1fe5 + len - 1;
    while (len--) {
        spin[curr] = spin[curr] ^ (key8--);
        curr--;
    }

    if (!spinCont(epA + 0x3217, 4, spinSize)) return false;

    curr = epA + 0x26eb;
    quint32 key32 = spinRd32(spin + curr);
    len = spinRd32(spin + curr + 5);
    if (len != 0x5a0) return false;

    curr = epA + 0x2d5;
    while (len--) {
        if (key32 & 1) {
            key32 = key32 >> 1;
            key32 ^= 0x8c328834;
        } else {
            key32 = key32 >> 1;
        }
        spin[curr] = spin[curr] ^ (key32 & 0xff);
        curr++;
    }

    // crc-derived key (summit over original file)
    len = (quint32)ssize - spinRd32(spin + epA + 0x429);
    if (len >= (quint32)ssize) return false;
    key32 = spinRd32(spin + epA + 0x3217) - _summit(src, len);

    // write decrypted loader back into src
    memcpy(src + nLoaderRaw, spin, nLoaderRsz);

    // ---- Phase B: decrypt sections in src ----
    qint64 epB = (qint64)nVep + nLoaderRaw - nLoaderRva;
    if (!spinCont(epB + 0x3300, 4, ssize)) return false;

    quint32 bitmap = spinRd32(src + epB + 0x3207);
    for (int j = 0; j < sectcnt; j++) {
        if (bitmap & 1) {
            quint32 size = listSections.at(j).SizeOfRawData;
            qint64 ptr = listSections.at(j).PointerToRawData;
            quint32 keydup = key32;
            if (!spinCont(ptr, size, ssize)) return false;
            while (size--) {
                if (!(keydup & 1)) {
                    keydup = keydup >> 1;
                    keydup ^= 0xed43af31;
                } else {
                    keydup = keydup >> 1;
                }
                src[ptr] = src[ptr] ^ (keydup & 0xff);
                ptr++;
            }
        }
        bitmap >>= 1;
    }

    curr = epB + 0x644;
    len = spinRd32(src + curr);
    if (len != 0x180) return false;
    quint32 key32b = spinRd32(src + curr + 0x0c);
    curr = epB + 0x28d3;
    if (!spinCont(curr, len, ssize)) return false;
    while (len--) {
        if (key32b & 1) {
            key32b = key32b >> 1;
            key32b ^= 0xed43af32;
        } else {
            key32b = key32b >> 1;
        }
        src[curr] = src[curr] ^ (key32b & 0xff);
        curr++;
    }

    // POLY1 via exec86
    curr = epB + 0x28dd;
    len = spinRd32(src + curr);
    if (len != 0x1a1) return false;
    curr += 0xf;
    qint64 emu = epB + 0x6d4;
    if (!spinCont(emu, len, ssize)) return false;
    while (len) {
        int fail = 0;
        src[emu] = _exec86(src[emu], (quint8)(len-- & 0xff), src + curr, ssize - curr, &fail);
        if (fail) return false;
        emu++;
    }

    // poly-decrypt sections
    bitmap = spinRd32(src + epB + 0x6f1);
    curr = epB + 0x755;
    for (int j = 0; j < sectcnt; j++) {
        if (bitmap & 1) {
            quint32 nlen = listSections.at(j).SizeOfRawData;
            emu = listSections.at(j).PointerToRawData;
            if (!spinCont(curr, 0x24, ssize)) return false;
            while (nlen) {
                int fail = 0;
                src[emu] = _exec86(src[emu], (quint8)(nlen-- & 0xff), src + curr, ssize - curr, &fail);
                if (fail) return false;
                emu++;
            }
        }
        bitmap >>= 1;
    }

    // ---- decompress ----
    bitmap = spinRd32(src + epB + 0x3061);
    quint32 bitman = bitmap;

    QList<QByteArray> sects;
    for (int j = 0; j < sectcnt; j++) {
        quint32 rsz = listSections.at(j).SizeOfRawData;
        quint32 vsz = listSections.at(j).Misc.VirtualSize;
        qint64 raw = listSections.at(j).PointerToRawData;
        if (!spinCont(raw, rsz, ssize)) return false;
        if (bitmap & 1) {
            QByteArray baOut(vsz, (char)0);
            if (_aplibDepack(src + raw, rsz, (quint8 *)baOut.data(), vsz) == -1) {
                return false;
            }
            sects.append(baOut);
        } else {
            sects.append(baSrc.mid(raw, rsz));
        }
        bitmap >>= 1;
    }

    // build the concatenated blob + section list
    QByteArray baBlob;
    QList<SECT> outSects;
    for (int j = 0; j < sectcnt; j++) {
        bool bComp = (bitman >> j) & 1;
        SECT s;
        s.rva = listSections.at(j).VirtualAddress;
        s.vsz = listSections.at(j).Misc.VirtualSize;
        s.rsz = bComp ? listSections.at(j).Misc.VirtualSize : listSections.at(j).SizeOfRawData;
        s.raw = (quint32)baBlob.size();
        outSects.append(s);
        baBlob.append(sects.at(j).constData(), qMin<int>(sects.at(j).size(), (int)s.rsz));
        if ((int)s.rsz > sects.at(j).size()) {
            baBlob.append(QByteArray((int)s.rsz - sects.at(j).size(), (char)0));
        }
    }

    QByteArray baPE = _buildPE(baBlob, outSects, nImageBase, listSections.at(0).VirtualAddress);
    if (baPE.isEmpty()) return false;

    return (pDevice->write(baPE) == baPE.size());
}
