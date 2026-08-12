/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xfsg.h"

#include <cstring>

static inline quint32 fsgRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 fsgAlign(quint32 nValue, quint32 nAlign)
{
    return (nValue + nAlign - 1) & ~(nAlign - 1);
}

// single-bit reader with the aPLib sentinel-bit refill scheme; returns -1 on OOB.
// *pS (source cursor) and *pMydl (bit buffer) are shared with the depack loop.
static int fsgGetBit(const quint8 *pSrc, qint64 nSrcSize, qint64 *pS, quint8 *pMydl)
{
    quint8 olddl = *pMydl;
    *pMydl = (quint8)(*pMydl * 2);
    if (!(olddl & 0x7f)) {
        if ((*pS < 0) || (*pS >= nSrcSize - 1)) {
            return -1;
        }
        olddl = pSrc[*pS];
        *pMydl = (quint8)(olddl * 2 + 1);
        (*pS)++;
    }
    return (olddl >> 7) & 1;
}

// bounds test used by the FSG stub-pointer chain walk
static bool fsgInSrc(quint32 nRva, quint32 nLen, quint32 nSrcVA, quint64 nSsize)
{
    return (nRva >= nSrcVA) && ((quint64)(nRva - nSrcVA) + nLen <= nSsize);
}

XFSG::XFSG(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XFSG::~XFSG()
{
}

bool XFSG::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XFSG::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XFSG fsg(pDevice);
    return fsg.isValid(pPdStruct);
}

XBinary::FT XFSG::getFileType()
{
    return FT_BINARY;
}

QString XFSG::getVersion()
{
    INTERNAL_INFO info = *static_cast<INTERNAL_INFO *>(getInternalInfo());
    return info.bIsValid ? info.sVersion : QString();
}

// ---------------------------------------------------------------------------
// aPLib-style depacker (FSG). Clean-room reimplementation.
// ---------------------------------------------------------------------------

qint64 XFSG::_aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed)
{
    if ((nSrcSize <= 0) || (nDstSize <= 0)) {
        return -1;
    }

    qint64 s = 0, d = 0;
    quint8 mydl = 0x80;
    quint32 oldback = 0;
    int lostbit = 1;

    if ((s >= nSrcSize) || (d >= nDstSize)) {
        return -1;
    }
    pDst[d++] = pSrc[s++];  // first literal

    for (;;) {
        int oob = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
        if (oob == -1) {
            return -1;
        }

        if (oob) {
            quint32 backsize = 0, backbytes = 0;
            int b = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
            if (b == -1) return -1;

            if (b) {
                int b2 = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                if (b2 == -1) return -1;

                if (b2) {
                    lostbit = 1;
                    backsize++;
                    backbytes = 0x10;
                    while (backbytes < 0x100) {
                        int x = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
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
                    if (!backbytes) break;  // end-of-stream marker
                    backsize += 2;
                    oldback = backbytes;
                    lostbit = 0;
                }
            } else {
                backsize = 1;
                do {
                    int x = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (x == -1) return -1;
                    backsize = backsize * 2 + x;
                    oob = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                    if (oob == -1) return -1;
                } while (oob);

                backsize = backsize - 1 - lostbit;
                if (!backsize) {
                    backsize = 1;
                    do {
                        int x = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
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
                        int x = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (x == -1) return -1;
                        backsize = backsize * 2 + x;
                        oob = fsgGetBit(pSrc, nSrcSize, &s, &mydl);
                        if (oob == -1) return -1;
                    } while (oob);
                    if (backbytes >= 0x7d00) backsize++;
                    if (backbytes >= 0x500) backsize++;
                    if (backbytes <= 0x7f) backsize += 2;
                    oldback = backbytes;
                }
                lostbit = 0;
            }

            if ((backbytes == 0) || ((qint64)backbytes > d) || (d + (qint64)backsize > nDstSize)) {
                return -1;
            }
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

    if (pnSrcConsumed) {
        *pnSrcConsumed = s;
    }
    return d;
}

// ---------------------------------------------------------------------------
// minimal analysis-PE rebuild
// ---------------------------------------------------------------------------

QByteArray XFSG::_rebuildPE(const QByteArray &baBlob, const QList<SECTIONINFO> &listSections, quint32 nImageBase, quint32 nOEP)
{
    if (listSections.isEmpty()) {
        return QByteArray();
    }

    const int nSects = listSections.size();
    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;  // DOS + PE sig + file hdr + opt hdr (PE32)

    quint32 nRawBase = fsgAlign(nHeaderBase + 0x28 * nSects, 0x200);
    const bool bGhost = (listSections.at(0).nRva > fsgAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = fsgAlign(nHeaderBase + 0x28 * (nSects + 1), 0x200);
    }

    // total raw size
    quint32 nRawTotal = nRawBase;
    quint32 nMaxVirtualEnd = 0;
    for (int i = 0; i < nSects; i++) {
        nRawTotal += fsgAlign(listSections.at(i).nRsz, 0x200);
        nMaxVirtualEnd = qMax(nMaxVirtualEnd, listSections.at(i).nRva + qMax(listSections.at(i).nVsz, listSections.at(i).nRsz));
    }

    QByteArray baResult(nRawTotal, (char)0);
    char *p = baResult.data();

    // DOS header
    _write_uint16(p + 0, 0x5A4D);   // 'MZ'
    _write_uint32(p + 0x3C, 0x40);  // e_lfanew

    char *pe = p + 0x40;
    _write_uint32(pe + 0, 0x00004550);  // 'PE\0\0'

    // IMAGE_FILE_HEADER
    char *fh = pe + 4;
    _write_uint16(fh + 0, 0x014C);            // Machine i386
    _write_uint16(fh + 2, (quint16)(nSects + (bGhost ? 1 : 0)));  // NumberOfSections
    _write_uint16(fh + 16, 0x00E0);           // SizeOfOptionalHeader
    _write_uint16(fh + 18, 0x010F);           // Characteristics (exe, 32-bit, no relocs)

    // IMAGE_OPTIONAL_HEADER32
    char *oh = fh + 20;
    _write_uint16(oh + 0, 0x010B);            // Magic PE32
    _write_uint32(oh + 16, nOEP);             // AddressOfEntryPoint
    _write_uint32(oh + 28, nImageBase);       // ImageBase
    _write_uint32(oh + 32, 0x1000);           // SectionAlignment
    _write_uint32(oh + 36, 0x200);            // FileAlignment
    _write_uint16(oh + 40, 4);                // MajorOSVersion
    _write_uint16(oh + 48, 4);                // MajorSubsystemVersion
    _write_uint32(oh + 56, fsgAlign(nMaxVirtualEnd, 0x1000));  // SizeOfImage
    _write_uint32(oh + 60, nRawBase);         // SizeOfHeaders
    _write_uint16(oh + 68, 2);                // Subsystem (GUI)
    _write_uint32(oh + 92, 16);               // NumberOfRvaAndSizes

    // section table
    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;

    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = fsgAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, listSections.at(0).nRva - nGhostVA);  // VirtualSize
        _write_uint32(sec + 12, nGhostVA);                          // VirtualAddress
        _write_uint32(sec + 16, 0);                                 // SizeOfRawData
        _write_uint32(sec + 20, 0);                                 // PointerToRawData
        _write_uint32(sec + 36, 0xE00000E0);                        // Characteristics
        sec += 0x28;
    }

    for (int i = 0; i < nSects; i++) {
        const SECTIONINFO &s = listSections.at(i);
        char szName[9];
        snprintf(szName, sizeof(szName), ".clam%.2d", i + 1);
        memcpy(sec, szName, qMin<size_t>(8, strlen(szName)));

        quint32 nRsz = fsgAlign(s.nRsz, 0x200);
        _write_uint32(sec + 8, s.nVsz ? s.nVsz : s.nRsz);  // VirtualSize
        _write_uint32(sec + 12, s.nRva);                   // VirtualAddress
        _write_uint32(sec + 16, nRsz);                     // SizeOfRawData
        _write_uint32(sec + 20, nRaw);                     // PointerToRawData
        _write_uint32(sec + 36, 0xE00000E0);               // Characteristics

        if (((qint64)s.nRaw + s.nRsz) <= baBlob.size()) {
            memcpy(baResult.data() + nRaw, baBlob.constData() + s.nRaw, s.nRsz);
        }

        nRaw += nRsz;
        sec += 0x28;
    }

    return baResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

bool XFSG::_findEmptyPair(XPE *pPE, qint32 *pnIndex)
{
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pPE->getSectionHeaders();

    for (int i = 0; i + 1 < listSections.size(); i++) {
        if ((listSections.at(i).SizeOfRawData == 0) && (listSections.at(i).Misc.VirtualSize != 0) && (listSections.at(i + 1).SizeOfRawData != 0) &&
            (listSections.at(i + 1).Misc.VirtualSize != 0)) {
            *pnIndex = i;
            return true;
        }
    }

    return false;
}

XFSG::INTERNAL_INFO XFSG::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    qint32 nIndex = -1;
    if (!_findEmptyPair(&pe, &nIndex)) {
        return result;
    }

    qint64 nEpOffset = pe.relAddressToOffset(pe.getOptionalHeader_AddressOfEntryPoint());
    if (nEpOffset == -1) {
        return result;
    }

    QByteArray baEp = read_array_process(nEpOffset, 0x20, pPdStruct);
    if (baEp.size() < 0x20) {
        return result;
    }
    const quint8 *ep = (const quint8 *)baEp.constData();
    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();

    if ((ep[0] == 0x87) && (ep[1] == 0x25)) {
        result.bIsValid = true;
        result.nVersion = 200;
        result.sVersion = "2.0";
    } else if (ep[0] == 0xBE) {
        // minimum section RVA
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
        quint32 nMinRva = 0xFFFFFFFF;
        for (int i = 0; i < listSections.size(); i++) {
            nMinRva = qMin(nMinRva, listSections.at(i).VirtualAddress);
        }
        quint32 nPtr = fsgRd32(ep + 1) - nImageBase;
        // The FSG 1.33 loader stub lives inside a section (the entry point is in
        // section space). Require AddressOfEntryPoint >= nMinRva so that packers
        // whose stub is embedded in the PE header and which happen to begin with
        // 0xBE (e.g. MEW's "mov esi") are not misdetected as FSG 1.33.
        quint32 nAoe = pe.getOptionalHeader_AddressOfEntryPoint();
        if ((nPtr < nMinRva) && (nAoe >= nMinRva)) {
            result.bIsValid = true;
            result.nVersion = 133;
            result.sVersion = "1.33";
        }
    }

    return result;
}

XFSG::INTERNAL_INFO XFSG::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XFSG::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = _getInternalInfo(pPdStruct);
        setIsInternalInfoHandled(true);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XFSG::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XFSG::setInternalInfo(void *pInternalInfo)
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
// streaming API
// ---------------------------------------------------------------------------

bool XFSG::_unpackV200(XPE *pPE, qint32 nIndex, QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pPE->getSectionHeaders();
    if (nIndex + 1 >= listSections.size()) {
        return false;
    }

    const XPE_DEF::IMAGE_SECTION_HEADER &secDst = listSections.at(nIndex);
    const XPE_DEF::IMAGE_SECTION_HEADER &secSrc = listSections.at(nIndex + 1);
    const quint32 nImageBase = (quint32)pPE->getOptionalHeader_ImageBase();

    const quint32 nSsize = secSrc.SizeOfRawData;
    const quint32 nDsize = secDst.Misc.VirtualSize;
    if ((nSsize <= 0x19) || (nDsize <= nSsize)) {
        return false;
    }

    qint64 nEpOffset = pPE->relAddressToOffset(pPE->getOptionalHeader_AddressOfEntryPoint());
    QByteArray baEp = read_array_process(nEpOffset, 0x20, pPdStruct);
    if (baEp.size() < 6) return false;

    QByteArray baSrc = read_array_process(secSrc.PointerToRawData, nSsize, pPdStruct);
    if ((quint32)baSrc.size() != nSsize) return false;
    const quint8 *src = (const quint8 *)baSrc.constData();

    quint32 newedx = fsgRd32((const quint8 *)baEp.constData() + 2) - nImageBase;
    if (!fsgInSrc(newedx, 4, secSrc.VirtualAddress, nSsize)) return false;
    const quint8 *dst = src + (newedx - secSrc.VirtualAddress);

    newedx = fsgRd32(dst) - nImageBase;
    if (!fsgInSrc(newedx, 4, secSrc.VirtualAddress, nSsize)) return false;
    dst = src + (newedx - secSrc.VirtualAddress);
    if (!fsgInSrc(newedx, 32, secSrc.VirtualAddress, nSsize)) return false;

    quint32 newedi = fsgRd32(dst) - nImageBase;
    quint32 newesi = fsgRd32(dst + 4) - nImageBase;
    quint32 newebx = fsgRd32(dst + 16) - nImageBase;

    if (newedi != secDst.VirtualAddress) return false;
    if ((newesi < secSrc.VirtualAddress) || (newesi - secSrc.VirtualAddress >= nSsize)) return false;
    if (!fsgInSrc(newebx, 16, secSrc.VirtualAddress, nSsize)) return false;

    quint32 nOEP = fsgRd32(src + (newebx + 12 - secSrc.VirtualAddress)) - nImageBase;

    QByteArray baDest(nDsize, (char)0);
    quint32 nSrcStart = newesi - secSrc.VirtualAddress;
    qint64 nProduced = _aplibDepack(src + nSrcStart, (qint64)nSsize - nSrcStart, (quint8 *)baDest.data(), nDsize, nullptr);
    if (nProduced <= 0) return false;

    QList<SECTIONINFO> listOut;
    SECTIONINFO si;
    si.nRva = newedi;
    si.nRaw = 0;
    si.nRsz = (quint32)nProduced;
    si.nVsz = (quint32)nProduced;
    listOut.append(si);

    QByteArray baPE = _rebuildPE(baDest, listOut, nImageBase, nOEP);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}

bool XFSG::_sectionRvaLess(const SECTIONINFO &a, const SECTIONINFO &b)
{
    return a.nRva < b.nRva;
}

bool XFSG::_unpackV133(XPE *pPE, qint32 nIndex, QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pPE->getSectionHeaders();
    if (nIndex + 1 >= listSections.size()) {
        return false;
    }

    const XPE_DEF::IMAGE_SECTION_HEADER &secDst = listSections.at(nIndex);
    const XPE_DEF::IMAGE_SECTION_HEADER &secSrc = listSections.at(nIndex + 1);
    const quint32 nImageBase = (quint32)pPE->getOptionalHeader_ImageBase();

    const quint32 nSsize = secSrc.SizeOfRawData;
    const quint32 nDsize = secDst.Misc.VirtualSize;
    if ((nSsize <= 0x19) || (nDsize <= nSsize)) return false;

    qint64 nEpOffset = pPE->relAddressToOffset(pPE->getOptionalHeader_AddressOfEntryPoint());
    QByteArray baEp = read_array_process(nEpOffset, 0xC0, pPdStruct);
    if (baEp.size() < 0xC0) return false;
    const quint8 *ep = (const quint8 *)baEp.constData();

    quint32 nSupportRva = fsgRd32(ep + 1) - nImageBase;
    qint64 nSupportOffset = pPE->relAddressToOffset(nSupportRva);
    if (nSupportOffset == -1) return false;

    quint32 nGp = (quint32)(secSrc.PointerToRawData - nSupportOffset);
    if ((nGp < 12) || (nGp > 0x10000)) return false;

    QByteArray baSupport = read_array_process(nSupportOffset, nGp, pPdStruct);
    if ((quint32)baSupport.size() != nGp) return false;
    const quint8 *support = (const quint8 *)baSupport.constData();

    quint32 newedi = fsgRd32(support + 4) - nImageBase;
    quint32 newesi = fsgRd32(support + 8) - nImageBase;

    if ((newesi < secSrc.VirtualAddress) || (newesi - secSrc.VirtualAddress >= nSsize)) return false;
    if (newedi != secDst.VirtualAddress) return false;

    int nSectCnt = 0;
    quint32 t;
    for (t = 12; t < nGp - 4; t += 4) {
        quint32 rva = fsgRd32(support + t);
        if (!rva) break;
        rva -= nImageBase + 1;
        nSectCnt++;
        if ((rva < secDst.VirtualAddress) || (rva - secDst.VirtualAddress >= nDsize)) break;
    }
    if ((t >= nGp - 4) || fsgRd32(support + t)) return false;

    QList<quint32> listRva;
    listRva.append(newedi);
    for (int k = 1; k <= nSectCnt; k++) {
        listRva.append(fsgRd32(support + 8 + k * 4) - 1 - nImageBase);
    }

    QByteArray baSrc = read_array_process(secSrc.PointerToRawData, nSsize, pPdStruct);
    if ((quint32)baSrc.size() != nSsize) return false;
    const quint8 *src = (const quint8 *)baSrc.constData();

    quint32 nOEP = pPE->getOptionalHeader_AddressOfEntryPoint() + 161 + 6 + fsgRd32(ep + 163);

    QByteArray baDest(nDsize, (char)0);
    QList<SECTIONINFO> listOut;
    qint64 nSrcPos = newesi - secSrc.VirtualAddress;
    qint64 nDstPos = 0;

    for (int k = 0; k <= nSectCnt; k++) {
        qint64 nConsumed = 0;
        qint64 nProduced = _aplibDepack(src + nSrcPos, (qint64)nSsize - nSrcPos, (quint8 *)baDest.data() + nDstPos, (qint64)nDsize - nDstPos, &nConsumed);
        if (nProduced < 0) return false;

        SECTIONINFO si;
        si.nRva = listRva.at(k);
        si.nRaw = (quint32)nDstPos;
        si.nRsz = (quint32)nProduced;
        si.nVsz = 0;
        listOut.append(si);

        nSrcPos += nConsumed;
        nDstPos += nProduced;
        if (!isPdStructNotCanceled(pPdStruct)) return false;
    }

    std::sort(listOut.begin(), listOut.end(), _sectionRvaLess);

    quint32 nLast = nDsize;
    for (int k = 0; k < listOut.size(); k++) {
        if (k + 1 < listOut.size()) {
            listOut[k].nVsz = listOut.at(k + 1).nRva - listOut.at(k).nRva;
            if (nLast >= listOut[k].nVsz) nLast -= listOut[k].nVsz;
        } else {
            listOut[k].nVsz = nLast;
        }
    }

    QByteArray baPE = _rebuildPE(baDest, listOut, nImageBase, nOEP);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}

bool XFSG::_unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    qint32 nIndex = -1;
    if (!_findEmptyPair(&pe, &nIndex)) return false;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    if (info.nVersion == 200) {
        return _unpackV200(&pe, nIndex, baOut, pPdStruct);
    } else if (info.nVersion == 133) {
        return _unpackV133(&pe, nIndex, baOut, pPdStruct);
    }

    return false;
}

QMap<XBinary::UNPACK_PROP, QVariant> XFSG::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XFSG::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    if (pState->pContext && !finishUnpack(pState, nullptr)) {
        return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

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

XBinary::ARCHIVERECORD XFSG::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};

    if ((!pState) || (!pState->pContext) || !isPdStructNotCanceled(pPdStruct)) {
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
    result.mapProperties.insert(FPART_PROP_INFO, QString("FSG %1").arg(getVersion()));

    return result;
}

bool XFSG::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if ((!pState) || (!pState->pContext) || !isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XFSG::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();

    return true;
}

bool XFSG::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    return writeUnpackData(pState, pDevice, pContext->baData, pPdStruct);
}
