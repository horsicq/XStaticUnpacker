/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xfsg.h"
#include "xmaterializedunpackguard.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <climits>
#include <cstring>

static inline quint32 fsgRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

// FSG 1.1/1.2 hide the v100 loader behind a fixed single-layer byte-decryptor.
// The stub is a fixed 0x80 bytes at the entry point and the 0xF4-byte encrypted
// body follows at EP+0x80. Between the loop instructions the stub inserts
// EB 02 CD 20 (jmp $+2 ; int 0x20) anti-disassembly padding, so the transform
// cannot be read at fixed EP offsets - but the transform itself is CONSTANT
// across every observed build: add 0x72, add 0xEA, xor 0xB6, add 0x46, xor 0x02,
// which reduces to the stateless per-byte map below (0x72+0xEA == 0x5C mod 256).
// Verified byte-exact against the pre-pack oracles on all three local samples
// (1.1/in_fpc, 1.2/in_fpc, 1.2/in_tcc). A build using a different transform
// would decrypt to garbage and fail the v100 opener check at the call sites, so
// this stays fail-closed without disassembling the loop.
static inline quint8 fsgDecryptByte(quint8 x)
{
    quint8 t = (quint8)(x + 0x5C);
    t = (quint8)(t ^ 0xB6);
    t = (quint8)(t + 0x46);
    t = (quint8)(t ^ 0x02);
    return t;
}

static void fsgDecryptStub(QByteArray *pBa)
{
    if (!pBa) return;
    quint8 *p = (quint8 *)pBa->data();
    for (int i = 0; i < pBa->size(); i++) {
        p[i] = fsgDecryptByte(p[i]);
    }
}

// Encrypted-stub geometry, shared by _detect and _resolveOep.
static const qint64 FSG_ENC_STUB_SIZE = 0x80;
static const qint64 FSG_ENC_BODY_SIZE = 0xF4;

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
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XFSG::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XFSG::~XFSG()
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

XFSG::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XFSG::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive && !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XFSG::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XFSG> guardedThis(this);
    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XFSG::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XFSG fsg(pDevice);
    return fsg.isValid(pPdStruct);
}

XBinary::FT XFSG::getFileType()
{
    return FT_PE32_FSG;
}

QString XFSG::getVersion()
{
    QPointer<XFSG> guardedThis(this);
    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo());
    return (guardedThis && pInfo && pInfo->bIsValid) ? pInfo->sVersion : QString();
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

QByteArray XFSG::_rebuildPE(const QByteArray &baBlob, const QList<SECTIONINFO> &listSections, quint32 nImageBase, quint32 nOEP, qint64 nOutputLimit)
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
    quint64 nRawTotal = nRawBase;
    quint32 nMaxVirtualEnd = 0;
    for (int i = 0; i < nSects; i++) {
        nRawTotal += fsgAlign(listSections.at(i).nRsz, 0x200);
        nMaxVirtualEnd = qMax(nMaxVirtualEnd, listSections.at(i).nRva + qMax(listSections.at(i).nVsz, listSections.at(i).nRsz));
    }

    if ((nRawTotal > INT_MAX) || ((nOutputLimit >= 0) && (nRawTotal > (quint64)nOutputLimit))) return QByteArray();
    QByteArray baResult((int)nRawTotal, (char)0);
    char *p = baResult.data();

    // DOS header
    _write_uint16(p + 0, 0x5A4D);   // 'MZ'
    _write_uint32(p + 0x3C, 0x40);  // e_lfanew

    char *pe = p + 0x40;
    _write_uint32(pe + 0, 0x00004550);  // 'PE\0\0'

    // IMAGE_FILE_HEADER
    char *fh = pe + 4;
    _write_uint16(fh + 0, 0x014C);                                // Machine i386
    _write_uint16(fh + 2, (quint16)(nSects + (bGhost ? 1 : 0)));  // NumberOfSections
    _write_uint16(fh + 16, 0x00E0);                               // SizeOfOptionalHeader
    _write_uint16(fh + 18, 0x010F);                               // Characteristics (exe, 32-bit, no relocs)

    // IMAGE_OPTIONAL_HEADER32
    char *oh = fh + 20;
    _write_uint16(oh + 0, 0x010B);                             // Magic PE32
    _write_uint32(oh + 16, nOEP);                              // AddressOfEntryPoint
    _write_uint32(oh + 28, nImageBase);                        // ImageBase
    _write_uint32(oh + 32, 0x1000);                            // SectionAlignment
    _write_uint32(oh + 36, 0x200);                             // FileAlignment
    _write_uint16(oh + 40, 4);                                 // MajorOSVersion
    _write_uint16(oh + 48, 4);                                 // MajorSubsystemVersion
    _write_uint32(oh + 56, fsgAlign(nMaxVirtualEnd, 0x1000));  // SizeOfImage
    _write_uint32(oh + 60, nRawBase);                          // SizeOfHeaders
    _write_uint16(oh + 68, 2);                                 // Subsystem (GUI)
    _write_uint32(oh + 92, 16);                                // NumberOfRvaAndSizes

    // section table
    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;

    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = fsgAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, listSections.at(0).nRva - nGhostVA);  // VirtualSize
        _write_uint32(sec + 12, nGhostVA);                           // VirtualAddress
        _write_uint32(sec + 16, 0);                                  // SizeOfRawData
        _write_uint32(sec + 20, 0);                                  // PointerToRawData
        _write_uint32(sec + 36, 0xE00000E0);                         // Characteristics
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

    // Read enough for the encrypted-stub arm (0x80); the plaintext arms only
    // need the first 0x20, so keep that guard and let the new arm require 0x80.
    QByteArray baEp = read_array_process(nEpOffset, FSG_ENC_STUB_SIZE, pPdStruct);
    if (baEp.size() < 0x20) {
        return result;
    }
    const quint8 *ep = (const quint8 *)baEp.constData();
    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();

    // The 1.x loader stubs live inside a section while their support table sits
    // in the PE header, so `support < minSectionRva <= AddressOfEntryPoint`.
    // This is also what keeps packers whose stub is embedded in the header and
    // happens to begin with 0xBE (MEW's "mov esi") from being read as FSG.
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    quint32 nMinRva = 0xFFFFFFFF;
    for (int i = 0; i < listSections.size(); i++) {
        nMinRva = qMin(nMinRva, listSections.at(i).VirtualAddress);
    }
    const quint32 nAoe = pe.getOptionalHeader_AddressOfEntryPoint();
    const auto isPlausibleSupport = [&](quint32 nSupportRva) -> bool { return (nSupportRva < nMinRva) && (nAoe >= nMinRva); };

    if ((ep[0] == 0x87) && (ep[1] == 0x25)) {
        result.bIsValid = true;
        result.nVersion = 200;
        result.sVersion = "2.0";
    } else if (ep[0] == 0xBE) {
        quint32 nPtr = fsgRd32(ep + 1) - nImageBase;
        if (isPlausibleSupport(nPtr)) {
            result.bIsValid = true;
            result.nVersion = 133;
            result.sVersion = "1.33";
            result.nSupportRva = nPtr;
            result.nJeOffset = 161;
        }
    } else if ((ep[0] == 0xBB) && (ep[5] == 0xBF) && (ep[10] == 0xBE) && (ep[15] == 0x53)) {
        // Shared 1.0/1.3 and 1.31 opener:
        //   mov ebx,support / mov edi,dest / mov esi,src / push ebx
        // followed by the generation-specific get-bit routine setup.
        const quint32 nPtr = fsgRd32(ep + 1) - nImageBase;
        if (isPlausibleSupport(nPtr)) {
            if ((ep[16] == 0xE8) && (fsgRd32(ep + 17) == 0x0000000A) && (ep[21] == 0x02) && (ep[22] == 0xD2) && (ep[23] == 0x75) && (ep[24] == 0x05) &&
                (ep[25] == 0x8A) && (ep[26] == 0x16) && (ep[27] == 0x46) && (ep[28] == 0x12) && (ep[29] == 0xD2) && (ep[30] == 0xC3)) {
                result.bIsValid = true;
                result.nVersion = 100;
                result.sVersion = "1.0-1.3";
                result.nJeOffset = 224;
            } else if ((ep[16] == 0xBB) && (ep[21] == 0xB2) && (ep[22] == 0x80) && (ep[23] == 0xA4) && (ep[24] == 0xB6) && (ep[25] == 0x80) && (ep[26] == 0xFF) &&
                       (ep[27] == 0xD3) && (ep[28] == 0x73) && (ep[29] == 0xF9)) {
                result.bIsValid = true;
                result.nVersion = 131;
                result.sVersion = "1.31";
                result.nJeOffset = 218;
            }
            if (result.bIsValid) {
                result.nSupportRva = nPtr;
                result.nDestVa = fsgRd32(ep + 6);
                result.nSrcVa = fsgRd32(ep + 11);
                result.bWordList = true;
            }
        }
    }

    // FSG 1.1/1.2: the v100 loader wrapped by a fixed byte-decryptor (see
    // fsgDecryptByte). ep[0]==0xE8 does not collide with the arms above, which
    // require ep[0] in {0x87, 0xBE, 0xBB}. Decrypt the 0xF4-byte body at EP+0x80,
    // then require the plaintext v100 opener (BB.. BF.. BE.. 53) before claiming
    // the family - that check is what makes a wrong transform fail closed rather
    // than yield a wrong image. The support/dest/src fields come from the
    // DECRYPTED opener, not the encrypted entry point.
    else if ((ep[0] == 0xE8) && (baEp.size() >= FSG_ENC_STUB_SIZE)) {
        const quint32 nBodyRva = nAoe + (quint32)FSG_ENC_STUB_SIZE;
        const qint64 nBodyOffset = pe.relAddressToOffset(nBodyRva);
        if (nBodyOffset != -1) {
            QByteArray baBody = read_array_process(nBodyOffset, FSG_ENC_BODY_SIZE, pPdStruct);
            if (baBody.size() == FSG_ENC_BODY_SIZE) {
                fsgDecryptStub(&baBody);
                const quint8 *b = (const quint8 *)baBody.constData();
                if ((b[0] == 0xBB) && (b[5] == 0xBF) && (b[10] == 0xBE) && (b[15] == 0x53)) {
                    const quint32 nPtr = fsgRd32(b + 1) - nImageBase;
                    if (isPlausibleSupport(nPtr)) {
                        result.bIsValid = true;
                        result.nVersion = 112;
                        result.sVersion = "1.1/1.2";
                        result.nSupportRva = nPtr;
                        result.nDestVa = fsgRd32(b + 6);
                        result.nSrcVa = fsgRd32(b + 11);
                        result.bWordList = true;
                        result.bEncryptedStub = true;
                        // OEP lives inside the encrypted body; _resolveOep scans
                        // the decrypted stub instead of trusting a fixed nJeOffset.
                    }
                }
            }
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
    QPointer<XFSG> guardedThis(this);
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

        const auto memoryMap = guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
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

void *XFSG::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XFSG> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
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

bool XFSG::_unpackV200(XPE *pPE, qint32 nIndex, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
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
    if ((nSsize <= 0x19) || (nDsize <= nSsize) || ((nOutputLimit >= 0) && ((quint64)nDsize > (quint64)nOutputLimit))) {
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

    QByteArray baPE = _rebuildPE(baDest, listOut, nImageBase, nOEP, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}

bool XFSG::_sectionRvaLess(const SECTIONINFO &a, const SECTIONINFO &b)
{
    return a.nRva < b.nRva;
}

bool XFSG::_unpackV133(XPE *pPE, qint32 nIndex, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
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
    if ((nSsize <= 0x19) || (nDsize <= nSsize) || ((nOutputLimit >= 0) && ((quint64)nDsize > (quint64)nOutputLimit))) return false;

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

    QByteArray baPE = _rebuildPE(baDest, listOut, nImageBase, nOEP, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}

// FSG 1.0/1.3, 1.31 and 1.1/1.2.  These predate the 32-bit support table of
// 1.33: the destination and the packed stream come from entry-point immediates
// (or, when the stub is encrypted, from the section pair), and the per-section
// RVA list is a 16-bit record list stored in the PE header.
//
// Record grammar, walked from the start of the table:
//   1  -> the next dword is the rebuilt import-table VA (record is 6 bytes)
//   2  -> end of list
//   W  -> section VA = (W - 2) << 12          (the stub does `dec edi` twice
//                                              before `shl edi, 0xC`)
bool XFSG::_unpackV1x(XPE *pPE, qint32 nIndex, const INTERNAL_INFO &info, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pPE->getSectionHeaders();
    if (nIndex + 1 >= listSections.size()) return false;

    const XPE_DEF::IMAGE_SECTION_HEADER &secDst = listSections.at(nIndex);
    const XPE_DEF::IMAGE_SECTION_HEADER &secSrc = listSections.at(nIndex + 1);
    const quint32 nImageBase = (quint32)pPE->getOptionalHeader_ImageBase();

    const quint32 nSsize = secSrc.SizeOfRawData;
    const quint32 nDsize = secDst.Misc.VirtualSize;
    if ((nSsize <= 0x19) || (nDsize <= nSsize) || ((nOutputLimit >= 0) && ((quint64)nDsize > (quint64)nOutputLimit))) return false;

    const quint32 nDestRva = info.nDestVa - nImageBase;
    const quint32 nSrcRva = info.nSrcVa - nImageBase;
    if (nDestRva != secDst.VirtualAddress) return false;
    if ((nSrcRva < secSrc.VirtualAddress) || (nSrcRva - secSrc.VirtualAddress >= nSsize)) return false;

    qint64 nSupportOffset = pPE->relAddressToOffset(info.nSupportRva);
    if (nSupportOffset == -1) return false;
    const qint64 nGpSigned = (qint64)secSrc.PointerToRawData - nSupportOffset;
    if ((nGpSigned < 4) || (nGpSigned > 0x10000)) return false;
    const quint32 nGp = (quint32)nGpSigned;

    QByteArray baSupport = read_array_process(nSupportOffset, nGp, pPdStruct);
    if ((quint32)baSupport.size() != nGp) return false;
    const quint8 *support = (const quint8 *)baSupport.constData();

    QList<quint32> listRva;
    listRva.append(nDestRva);
    bool bTerminated = false;
    for (quint32 t = 0; t + 2 <= nGp;) {
        const quint32 w = (quint32)support[t] | ((quint32)support[t + 1] << 8);
        if (w == 2) {
            bTerminated = true;
            break;
        }
        if (w == 1) {
            if (t + 6 > nGp) return false;  // import record
            t += 6;
            continue;
        }
        const quint32 nRva = ((w - 2) << 12) - nImageBase;
        if ((nRva < secDst.VirtualAddress) || (nRva - secDst.VirtualAddress >= nDsize)) return false;
        listRva.append(nRva);
        if (listRva.size() > 96) return false;
        t += 2;
    }
    if (!bTerminated) return false;

    QByteArray baSrc = read_array_process(secSrc.PointerToRawData, nSsize, pPdStruct);
    if ((quint32)baSrc.size() != nSsize) return false;
    const quint8 *src = (const quint8 *)baSrc.constData();

    quint32 nOEP = 0;
    if (!_resolveOep(pPE, info, &nOEP, pPdStruct)) return false;

    QByteArray baDest(nDsize, (char)0);
    QList<SECTIONINFO> listOut;
    qint64 nSrcPos = nSrcRva - secSrc.VirtualAddress;
    qint64 nDstPos = 0;

    for (int k = 0; k < listRva.size(); k++) {
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

    QByteArray baPE = _rebuildPE(baDest, listOut, nImageBase, nOEP, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}

// The original entry point is the target of the stub's single `0F 84` (je),
// anchored by the preceding `FE 0F` / `FE 0E` (`dec byte ptr [edi]`).  The
// anchor is located rather than trusted so a stub that shifted by a byte fails
// closed instead of producing a plausible-looking wrong entry point.
bool XFSG::_resolveOep(XPE *pPE, const INTERNAL_INFO &info, quint32 *pnOEP, PDSTRUCT *pPdStruct)
{
    if (!pnOEP) return false;

    // FSG 1.1/1.2: the `0F 84` OEP jump lives inside the encrypted body. Decrypt
    // it, then scan for exactly one `0F 84` preceded by `FE` (its anchor is at
    // stub+225, one byte later than v100's plaintext 224, so it must be scanned
    // rather than trusted). A non-unique or absent anchor fails closed.
    if (info.bEncryptedStub) {
        const quint32 nAoe = pPE->getOptionalHeader_AddressOfEntryPoint();
        const qint64 nBodyOffset = pPE->relAddressToOffset(nAoe + (quint32)FSG_ENC_STUB_SIZE);
        if (nBodyOffset == -1) return false;
        QByteArray baBody = read_array_process(nBodyOffset, FSG_ENC_BODY_SIZE, pPdStruct);
        if (baBody.size() != FSG_ENC_BODY_SIZE) return false;
        fsgDecryptStub(&baBody);
        const quint8 *body = (const quint8 *)baBody.constData();
        int nHit = -1;
        for (int i = 2; i + 6 <= baBody.size(); i++) {
            if ((body[i] == 0x0F) && (body[i + 1] == 0x84) && (body[i - 2] == 0xFE)) {
                if (nHit != -1) return false;  // must be unique
                nHit = i;
            }
        }
        if (nHit == -1) return false;
        *pnOEP = nAoe + (quint32)FSG_ENC_STUB_SIZE + (quint32)nHit + 6 + fsgRd32(body + nHit + 2);
        return true;
    }

    if (info.nJeOffset < 0) return false;

    const quint32 nAoe = pPE->getOptionalHeader_AddressOfEntryPoint();
    const qint64 nEpOffset = pPE->relAddressToOffset(nAoe);
    if (nEpOffset == -1) return false;

    const qint64 nNeeded = (qint64)info.nJeOffset + 6;
    QByteArray baStub = read_array_process(nEpOffset, nNeeded + 0x40, pPdStruct);
    if (baStub.size() < nNeeded) return false;
    const quint8 *stub = (const quint8 *)baStub.constData();

    if ((stub[info.nJeOffset] != 0x0F) || (stub[info.nJeOffset + 1] != 0x84)) return false;
    if ((info.nJeOffset >= 2) && (stub[info.nJeOffset - 2] != 0xFE)) return false;

    *pnOEP = nAoe + (quint32)info.nJeOffset + 6 + fsgRd32(stub + info.nJeOffset + 2);

    return true;
}

bool XFSG::_unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    qint32 nIndex = -1;
    if (!_findEmptyPair(&pe, &nIndex)) return false;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    if (info.nVersion == 200) {
        return _unpackV200(&pe, nIndex, baOut, nOutputLimit, pPdStruct);
    } else if (info.nVersion == 133) {
        return _unpackV133(&pe, nIndex, baOut, nOutputLimit, pPdStruct);
    } else if (info.bWordList) {
        // Includes the encrypted 1.1/1.2 stub: its support/dest/src fields were
        // read from the DECRYPTED v100 opener in _detect, and _resolveOep
        // decrypts the body to recover the OEP, so the word-list path applies
        // unchanged - the aPLib payload itself is not encrypted.
        return _unpackV1x(&pe, nIndex, info, baOut, nOutputLimit, pPdStruct);
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
    if (!pState) return false;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool { return !pPdStruct || isPdStructLifetimeAlive(progressLifetime); };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XFSG> guardedThis(this);

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

    XFSG worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
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
    pContext->sInfo = QString("FSG %1").arg(info.sVersion);
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

XBinary::ARCHIVERECORD XFSG::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XFSG> guardedThis(this);
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

bool XFSG::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XFSG::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XFSG::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XFSG> guardedThis(this);
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
