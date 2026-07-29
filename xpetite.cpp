/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xpetite.h"

#include <climits>
#include <cstring>

static inline quint32 petRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 petAlign(quint32 v, quint32 a)
{
    return (v + a - 1) & ~(a - 1);
}

// unchecked 32-bit read at buffer offset
static inline quint32 petR32(const quint8 *buf, qint64 off)
{
    return petRd32(buf + off);
}

// bounds-checked 32-bit read; -1 if [off, off+4) is out of range
static qint64 petReadSafe(const quint8 *buf, quint32 bufsz, qint64 off)
{
    return ((off >= 0) && (off + 4 <= (qint64)bufsz)) ? (qint64)petRd32(buf + off) : -1;
}

// buffer-relative offset of an RVA
static inline qint64 petRel(quint32 nMinRva, quint32 rva)
{
    return (qint64)rva - (qint64)nMinRva;
}

// bounds test: [off, off+len) fits within bufsz
static inline bool petCont(quint32 bufsz, qint64 off, qint64 len)
{
    return (off >= 0) && (len >= 0) && ((off + len) <= (qint64)bufsz);
}

// RVA validity test for the op-table walk (top bit is a flag, masked off)
static bool petValidRva(quint32 v, quint32 nMinRva, quint32 nMaxRva)
{
    v &= 0x7fffffff;
    return (v >= nMinRva) && (v < nMaxRva);
}

// Walk the op stream at buffer offset pk. Returns the op count if it terminates
// cleanly on a zero srva with every referenced RVA in range, else -1.
static int petParseOps(const quint8 *buf, quint32 bufsz, quint32 nMinRva, quint32 nMaxRva, qint64 pk)
{
    int nOps = 0;
    while (nOps < 4096) {
        qint64 sv = petReadSafe(buf, bufsz, pk);
        if (sv < 0) return -1;
        if (sv == 0) return (nOps >= 2) ? nOps : -1;
        quint32 nSize = (quint32)sv & 0x7fffffff;
        if ((quint32)sv != nSize) {  // copy op {srva|flag, src, dst}
            qint64 s = petReadSafe(buf, bufsz, pk + 4), dd = petReadSafe(buf, bufsz, pk + 8);
            if ((s < 0) || (dd < 0) || (!petValidRva((quint32)s, nMinRva, nMaxRva)) || (!petValidRva((quint32)dd, nMinRva, nMaxRva))) return -1;
            pk += 0xc;
        } else {  // section op {srva, size, thisrva}
            if (!petValidRva((quint32)sv, nMinRva, nMaxRva)) return -1;
            qint64 tr = petReadSafe(buf, bufsz, pk + 8);
            if ((tr < 0) || (!petValidRva((quint32)tr, nMinRva, nMaxRva))) return -1;
            pk += 0x10;
        }
        nOps++;
    }
    return -1;
}

XPETITE::XPETITE(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XPETITE::~XPETITE()
{
}

bool XPETITE::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XPETITE::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XPETITE p(pDevice);
    return p.isValid(pPdStruct);
}

XBinary::FT XPETITE::getFileType()
{
    return FT_BINARY;
}

QString XPETITE::getVersion()
{
    INTERNAL_INFO info = *static_cast<INTERNAL_INFO *>(getInternalInfo());
    return info.bIsValid ? info.sVersion : QString();
}

XPETITE::INTERNAL_INFO XPETITE::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XPETITE::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = _getInternalInfo(pPdStruct);
        setIsInternalInfoHandled(true);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XPETITE::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XPETITE::setInternalInfo(void *pInternalInfo)
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

int XPETITE::_doubledl(const quint8 *buf, qint64 bufsz, qint64 *pSrcOff, quint8 *pMydl)
{
    quint8 olddl = *pMydl;
    *pMydl = (quint8)(olddl * 2);
    if (!(olddl & 0x7f)) {
        if ((*pSrcOff < 0) || (*pSrcOff >= bufsz - 1)) {
            return -1;
        }
        olddl = buf[*pSrcOff];
        *pMydl = (quint8)(olddl * 2 + 1);
        (*pSrcOff)++;
    }
    return (olddl >> 7) & 1;
}

// ---------------------------------------------------------------------------
// operations-table locator
// ---------------------------------------------------------------------------

qint64 XPETITE::_findOpTable(const quint8 *buf, quint32 bufsz, quint32 nMinRva, quint32 nLoaderRva, quint32 nLoaderVsz, quint32 nImageBase)
{
    const quint32 nMaxRva = nMinRva + bufsz;

    const qint64 nLo = (qint64)nLoaderRva - nMinRva;
    if ((nLo < 0) || (nLo >= (qint64)bufsz)) return -1;
    const qint64 nHi = qMin<qint64>((qint64)bufsz, nLo + nLoaderVsz);
    const quint32 nLoaderBase = nImageBase + nLoaderRva;

    qint64 nBestPk = -1;
    int nBestOps = 0;
    for (qint64 i = nLo; i + 5 <= nHi; i++) {
        if (buf[i] != 0xB8) continue;                        // mov eax, imm32
        if (petRd32(buf + i + 1) != nLoaderBase) continue;   // imm32 == loader base
        for (qint64 k = i + 5; (k + 6 <= nHi) && (k < i + 5 + 0x140); k++) {
            if (buf[k] != 0x8D) continue;                    // lea reg, [eax + disp32]
            if ((buf[k + 1] & 0xC7) != 0x80) continue;       //   mod=10, rm=000 (eax)
            qint32 nImm = (qint32)petRd32(buf + k + 2);
            if ((nImm < 0x100) || ((quint32)nImm >= nLoaderVsz)) continue;
            // eax may have been nudged before the lea, so snap forward to the op start.
            for (int s = 0; s < 0x40; s += 4) {
                int nOps = petParseOps(buf, bufsz, nMinRva, nMaxRva, nLo + nImm + s);
                if (nOps > nBestOps) {
                    nBestOps = nOps;
                    nBestPk = nLo + nImm + s;
                }
            }
        }
    }
    return nBestPk;
}

// ---------------------------------------------------------------------------
// core inflate (petite_inflate2x_1to9)
// ---------------------------------------------------------------------------

bool XPETITE::_usectRvaLess(const USECT &a, const USECT &b)
{
    return a.rva < b.rva;
}

bool XPETITE::_inflate(quint8 *buf, quint32 nMinRva, quint32 bufsz, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase,
                       quint32 nPep, int nVersion, QList<USECT> *pOut, quint32 *pEncEp)
{
    quint32 grown = 0x355, skew = 0x35;
    if (nVersion != 2) {
        grown = 0x323;
        skew = 0x34;
    }

    const quint32 nLoaderRva = listSections.at(nSectCount - 1).VirtualAddress;
    const quint32 nLoaderVsz = qMax(listSections.at(nSectCount - 1).Misc.VirtualSize, listSections.at(nSectCount - 1).SizeOfRawData);

    // The op-table offset varies per Petite build (the loader computes it as
    // "mov eax, loaderbase; lea reg, [eax+imm]"), so recover it rather than use a
    // fixed offset. Fall back to the historical constant if the loader can't be read.
    qint64 pk = _findOpTable(buf, bufsz, nMinRva, nLoaderRva, nLoaderVsz, nImageBase);
    if (pk == -1) {
        pk = petRel(nMinRva, nLoaderRva) + ((nVersion == 2) ? 0x1b8 : 0x178);
    }

    QList<USECT> usects;
    quint32 bottom = 0, enc_ep = 0, irva = 0, workdone = 0;
    int mangled = 0, check4resources = 0;

    for (;;) {
        if (!petCont(bufsz, pk, 4)) return false;
        quint32 srva = petR32(buf, pk);

        if (!srva) {
            if (usects.isEmpty()) return false;
            int j = usects.size();

            // sort by rva
            std::stable_sort(usects.begin(), usects.end(), _usectRvaLess);

            // virtual sizes
            for (int t = 0; t < j - 1; t++) {
                if (usects[t].vsz != usects[t + 1].rva - usects[t].rva) {
                    usects[t].vsz = usects[t + 1].rva - usects[t].rva;
                }
            }

            // decrypt old entry point
            if (enc_ep) {
                quint32 virtaddr = nPep + 5 + nImageBase, tmpep;
                int rndm = 0, dummy = 1;
                qint64 thunk = petRel(nMinRva, irva);

                if (nVersion == 2) {
                    while (dummy && petCont(bufsz, thunk, 4)) {
                        quint32 api;
                        if (!petR32(buf, thunk)) {
                            workdone = 1;
                            break;
                        }
                        qint64 imports = petRel(nMinRva, petR32(buf, thunk));
                        thunk += 4;
                        dummy = 0;

                        while (petCont(bufsz, imports, 4)) {
                            dummy = 0;
                            imports += 4;
                            if (!(api = petR32(buf, imports - 4))) {
                                dummy = 1;
                                break;
                            }
                            if ((api != (api | 0x80000000)) && mangled && (--rndm < 0)) {
                                api = virtaddr;
                                virtaddr += 5;
                                rndm = virtaddr & 7;
                            } else {
                                api = 0xbff01337;
                            }
                            if (listSections.at(nSectCount - 1).VirtualAddress + nImageBase < api) enc_ep--;
                            if (api < virtaddr) enc_ep--;
                            tmpep = (enc_ep & 0xfffffff8) >> 3 & 0x1fffffff;
                            enc_ep = (enc_ep & 7) << 29 | tmpep;
                        }
                    }
                } else {
                    workdone = 1;
                }
                enc_ep = nPep + 5 + enc_ep;
                if (workdone != 1) {
                    enc_ep = usects.at(0).rva;
                }
            }

            // compact data into sequential raw offsets
            for (int t = 0; t < j; t++) {
                usects[t].raw = (t > 0) ? (usects[t - 1].raw + usects[t - 1].rsz) : 0;
                if (usects[t].rsz != 0) {
                    if (petCont(bufsz, (qint64)usects[t].raw, usects[t].rsz)) {
                        memmove(buf + usects[t].raw, buf + petRel(nMinRva, usects[t].rva), usects[t].rsz);
                    } else {
                        usects[t].raw = (t > 0) ? usects[t - 1].raw : 0;
                        usects[t].rsz = 0;
                    }
                }
            }

            *pOut = usects;
            *pEncEp = enc_ep;
            return true;
        }

        quint32 size = srva & 0x7fffffff;
        if (srva != size) {
            // copy packed data op
            check4resources = 0;
            if (!petCont(bufsz, pk + 4, 8)) return false;
            bottom = petR32(buf, pk + 8);
            if (bottom > 0xFFFFFFFFu - 4) return false;
            bottom += 4;

            qint64 ssrc = petRel(nMinRva, petR32(buf, pk + 4)) - (qint64)(size - 1) * 4;
            qint64 ddst = petRel(nMinRva, petR32(buf, pk + 8)) - (qint64)(size - 1) * 4;
            if (!petCont(bufsz, ssrc, (qint64)size * 4) || !petCont(bufsz, ddst, (qint64)size * 4)) return false;
            memmove(buf + ddst, buf + ssrc, (size_t)size * 4);
            pk += 0x0c;
        } else {
            quint32 check1, check2;
            quint8 mydl = 0;
            quint8 goback;

            if (!petCont(bufsz, pk + 4, 8)) return false;
            size = petR32(buf, pk + 4);
            quint32 thisrva = petR32(buf, pk + 8);
            pk += 0x10;

            if (usects.size() >= 96) return false;

            USECT us;
            us.rva = thisrva;
            us.rsz = size;
            us.vsz = ((int)(bottom - thisrva) > 0) ? (bottom - thisrva) : size;
            us.raw = 0;

            if (!size) {
                usects.append(us);
                continue;
            }

            qint64 ssrc = petRel(nMinRva, srva);
            qint64 ddst = petRel(nMinRva, thisrva);

            int q;
            for (q = 0; q < nSectCount; q++) {
                quint32 sbb = listSections.at(q).VirtualAddress, sbbsz = listSections.at(q).Misc.VirtualSize;
                if (!((us.rva >= sbb) && ((quint64)us.rva + us.vsz <= (quint64)sbb + sbbsz))) continue;
                if (!check4resources) {
                    us.rva = sbb;
                    us.rsz = thisrva - sbb + size;
                }
                break;
            }
            if (q == nSectCount) return false;

            usects.append(us);

            if (size < 0x10000) {
                check1 = 0x0FFFFC060;
                check2 = 0x0FFFFFC60;
                goback = 5;
            } else if (size < 0x40000) {
                check1 = 0x0FFFF8180;
                check2 = 0x0FFFFF980;
                goback = 7;
            } else {
                check1 = 0x0FFFF8300;
                check2 = 0x0FFFFFB00;
                goback = 8;
            }

            if (!petCont(bufsz, ssrc, 1) || !petCont(bufsz, ddst, 1)) return false;
            size--;
            buf[ddst++] = buf[ssrc++];
            int backbytes = 0, oldback = 0, addsize;

            while (size > 0) {
                int oob = _doubledl(buf, bufsz, &ssrc, &mydl);
                if (oob == -1) return false;
                if (!oob) {
                    if (!petCont(bufsz, ssrc, 1) || !petCont(bufsz, ddst, 1)) return false;
                    buf[ddst++] = (quint8)(buf[ssrc++] ^ (size & 0xff));
                    size--;
                } else {
                    addsize = 0;
                    backbytes++;
                    for (;;) {
                        if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                        if (backbytes >= INT_MAX / 2) return false;
                        backbytes = backbytes * 2 + oob;
                        if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                        if (!oob) break;
                    }
                    backbytes -= 3;
                    quint32 backsize;
                    if (backbytes >= 0) {
                        backsize = goback;
                        do {
                            if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                            if (backbytes >= INT_MAX / 2) return false;
                            backbytes = backbytes * 2 + oob;
                            backsize--;
                        } while (backsize);
                        backbytes ^= 0xffffffff;
                        addsize += 1 + (backbytes < (int)check2) + (backbytes < (int)check1);
                        oldback = backbytes;
                    } else {
                        backsize = backbytes + 1;
                        backbytes = oldback;
                    }

                    if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                    backsize = backsize * 2 + oob;
                    if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                    backsize = backsize * 2 + oob;
                    if (!backsize) {
                        backsize++;
                        for (;;) {
                            if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                            backsize = backsize * 2 + oob;
                            if ((oob = _doubledl(buf, bufsz, &ssrc, &mydl)) == -1) return false;
                            if (!oob) break;
                        }
                        backsize += 2;
                    }
                    backsize += addsize;
                    size -= backsize;
                    if (!petCont(bufsz, ddst, backsize) || !petCont(bufsz, ddst + backbytes, backsize)) return false;
                    while (backsize--) {
                        buf[ddst] = buf[ddst + backbytes];
                        ddst++;
                    }
                    backbytes = 0;
                }
            }

            // strip trailing petite loader code
            {
                int j = usects.size();
                int strippetite = 0;
                quint32 reloc = 0;

                if ((usects[j - 1].rsz > grown) && petCont(bufsz, ddst - grown + 5 + 0x4f, 8) && (petR32(buf, ddst - grown + 5 + 0x4f) == 0x645ec033) &&
                    (petR32(buf, ddst - grown + 5 + 0x4f + 4) == 0x1b8b188b)) {
                    reloc = 0;
                    strippetite = 1;
                }
                if (!strippetite && (usects[j - 1].rsz > grown + skew) && petCont(bufsz, ddst - grown + 5 + 0x4f - skew, 8) && (petR32(buf, ddst - grown + 5 + 0x4f - skew) == 0x645ec033) &&
                    (petR32(buf, ddst - grown + 5 + 0x4f + 4 - skew) == 0x1b8b188b)) {
                    reloc = skew;
                    strippetite = 1;
                }

                if (strippetite && petCont(bufsz, ddst - grown + 0x0f - 8 - reloc, 8)) {
                    quint32 test1 = petR32(buf, ddst - grown + 0x0f - 8 - reloc) ^ 0x9d6661aa;
                    quint32 test2 = petR32(buf, ddst - grown + 0x0f - 4 - reloc) ^ 0xe908c483;
                    if ((test1 == test2) && petCont(bufsz, ddst - grown + 0x0f - reloc, 0x1c0 - 0x0f + 4)) {
                        irva = petR32(buf, ddst - grown + 0x121 - reloc);
                        enc_ep = petR32(buf, ddst - grown + 0x0f - reloc) ^ test1;
                        mangled = (petR32(buf, ddst - grown + 0x1c0 - reloc) != 0x90909090);
                    }
                    usects[j - 1].rsz -= grown + reloc;
                }
            }
            check4resources++;
        }
    }
}

// ---------------------------------------------------------------------------
// PE rebuild (sections read from the compacted buffer at .raw)
// ---------------------------------------------------------------------------

QByteArray XPETITE::_buildPE(const QByteArray &baBuf, const QList<USECT> &listOut, quint32 nImageBase, quint32 nOEP, quint32 nResRva, quint32 nResSize)
{
    int nSectCount = listOut.size();
    if (nSectCount <= 0) return QByteArray();

    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    quint32 nFirstRva = listOut.at(0).rva;
    quint32 nRawBase = petAlign(nHeaderBase + 0x28 * nSectCount, 0x200);
    const bool bGhost = (nFirstRva > petAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = petAlign(nHeaderBase + 0x28 * (nSectCount + 1), 0x200);
    }

    quint32 nRawTotal = nRawBase, nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += petAlign(listOut.at(i).rsz, 0x200);
        nMaxVEnd = qMax(nMaxVEnd, listOut.at(i).rva + qMax(listOut.at(i).vsz, listOut.at(i).rsz));
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
    _write_uint32(oh + 56, petAlign(nMaxVEnd, 0x1000));
    _write_uint32(oh + 60, nRawBase);
    _write_uint16(oh + 68, 2);
    _write_uint32(oh + 92, 16);
    // resource data directory (index 2)
    _write_uint32(oh + 0x60 + 2 * 8, nResRva);
    _write_uint32(oh + 0x60 + 2 * 8 + 4, nResSize);

    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;
    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = petAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, nFirstRva - nGhostVA);
        _write_uint32(sec + 12, nGhostVA);
        _write_uint32(sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    for (int i = 0; i < nSectCount; i++) {
        const USECT &u = listOut.at(i);
        quint32 nRsz = petAlign(u.rsz, 0x200);
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

XPETITE::INTERNAL_INFO XPETITE::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n < 1) return result;

    qint64 nEpOffset = pe.relAddressToOffset(pe.getOptionalHeader_AddressOfEntryPoint());
    if (nEpOffset == -1) return result;

    QByteArray baEp = read_array_process(nEpOffset, 0x100, pPdStruct);
    if (baEp.size() < 0x84) return result;
    const quint8 *ep = (const quint8 *)baEp.constData();

    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();

    int found = 2;
    if ((ep[0] != 0xB8) || (petRd32(ep + 1) != listSections.at(n - 1).VirtualAddress + nImageBase)) {
        if ((n < 2) || (ep[0] != 0xB8) || (petRd32(ep + 1) != listSections.at(n - 2).VirtualAddress + nImageBase)) {
            found = 0;
        } else {
            found = 1;
        }
    }

    if (!found) return result;

    // level-zero compression is not supported
    if (petRd32(ep + 0x80) == 0x163c988d) {
        return result;
    }

    result.bIsValid = true;
    result.nVersion = found;
    result.sVersion = (found == 2) ? "2.x" : "2.x (level 1)";
    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XPETITE::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XPETITE::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    if (!_detect(pPdStruct).bIsValid) {
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->sFileName = getUnpackedFileName(getDevice());

    if (!_unpackToBuffer(pContext->baData, pPdStruct)) {
        delete pContext;
        return false;
    }

    pState->pContext = pContext;
    pState->nNumberOfRecords = (pContext->baData.size() > 0) ? 1 : 0;

    return (pState->nNumberOfRecords > 0);
}

XBinary::ARCHIVERECORD XPETITE::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};

    if ((!pState) || (!pState->pContext)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if (pState->nCurrentIndex != 0) {
        return result;
    }

    result.nStreamOffset = 0;
    result.nStreamSize = pContext->baData.size();
    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, pContext->sFileName);
    result.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, getSize());
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, (qint64)pContext->baData.size());
    result.mapProperties.insert(FPART_PROP_HANDLEMETHOD, (qint32)HANDLE_METHOD_FILE);
    result.mapProperties.insert(FPART_PROP_ISFOLDER, false);
    result.mapProperties.insert(FPART_PROP_INFO, QString("Petite %1").arg(getVersion()));

    return result;
}

bool XPETITE::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if ((!pState) || (!pState->pContext)) {
        return false;
    }

    pState->nCurrentIndex++;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XPETITE::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

    if (pState->pContext) {
        delete (UNPACK_CONTEXT *)pState->pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}

bool XPETITE::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    const QByteArray &baData = pContext->baData;
    qint64 nOffset = 0;
    const qint64 nChunkSize = 0x100000;

    while ((nOffset < baData.size()) && isPdStructNotCanceled(pPdStruct)) {
        qint64 nCurrentChunkSize = qMin(nChunkSize, (qint64)baData.size() - nOffset);

        if (pDevice->write(baData.constData() + nOffset, nCurrentChunkSize) != nCurrentChunkSize) {
            return false;
        }

        nOffset += nCurrentChunkSize;
    }

    return isPdStructNotCanceled(pPdStruct) && (nOffset == baData.size());
}

bool XPETITE::_unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n < 1) return false;

    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();
    const quint32 nVep = pe.getOptionalHeader_AddressOfEntryPoint();

    quint32 nMin = 0xFFFFFFFF, nMax = 0;
    for (int i = 0; i < n; i++) {
        nMin = qMin(nMin, listSections.at(i).VirtualAddress);
        nMax = qMax(nMax, listSections.at(i).VirtualAddress + qMax(listSections.at(i).Misc.VirtualSize, listSections.at(i).SizeOfRawData));
    }
    if (nMax <= nMin) return false;
    quint32 dsize = nMax - nMin;
    if (dsize > (256u * 1024 * 1024)) return false;

    QByteArray baBuf(dsize, (char)0);
    for (int i = 0; i < n; i++) {
        if (!listSections.at(i).PointerToRawData) continue;
        quint32 nUrsz = listSections.at(i).SizeOfRawData;
        if (!nUrsz) continue;
        qint64 nOff = (qint64)listSections.at(i).VirtualAddress - nMin;
        if ((nOff < 0) || ((quint64)nOff + nUrsz > dsize)) return false;
        QByteArray baSect = read_array_process(listSections.at(i).PointerToRawData, nUrsz, pPdStruct);
        if ((quint32)baSect.size() != nUrsz) return false;
        memcpy(baBuf.data() + nOff, baSect.constData(), nUrsz);
    }

    int nSectCount = n - ((info.nVersion == 1) ? 1 : 0);
    if (nSectCount < 1) return false;

    XPE_DEF::IMAGE_DATA_DIRECTORY resDir = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE);

    QList<USECT> listOut;
    quint32 nEncEp = 0;
    if (!_inflate((quint8 *)baBuf.data(), nMin, dsize, listSections, nSectCount, nImageBase, nVep, info.nVersion, &listOut, &nEncEp)) {
        return false;
    }

    QByteArray baPE = _buildPE(baBuf, listOut, nImageBase, nEncEp, resDir.VirtualAddress, resDir.Size);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}
