/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xnspack.h"
#include "xmaterializedunpackguard.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <cstring>
#include <vector>

static inline quint32 nspRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 nspAlign(quint32 nValue, quint32 nAlign)
{
    return (nValue + nAlign - 1) & ~(nAlign - 1);
}

XNSPACK::XNSPACK(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XNSPACK::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XNSPACK::~XNSPACK()
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

XNSPACK::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XNSPACK::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive &&
           !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XNSPACK::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XNSPACK> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XNSPACK::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XNSPACK nsp(pDevice);
    return nsp.isValid(pPdStruct);
}

XBinary::FT XNSPACK::getFileType()
{
    return FT_PE32_NSPACK;
}

XNSPACK::INTERNAL_INFO XNSPACK::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XNSPACK::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XNSPACK> guardedThis(this);
    const bool bAlreadyHandled = guardedThis->isInternalInfoHandled();
    if (!guardedThis) return false;

    if (!bAlreadyHandled) {
        const quint64 nTransaction =
            guardedThis->beginInternalInfoTransaction();
        if (!nTransaction) return false;

        // The transaction supplies the recursion sentinel. Keep every
        // source-derived value local until the same binding is revalidated.
        guardedThis->m_internalInfo = INTERNAL_INFO();
        INTERNAL_INFO info = guardedThis->_getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }

        const auto memoryMap =
            guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        info.memoryMap = memoryMap;

        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
        guardedThis->m_internalInfo = info;
        if (!guardedThis->commitInternalInfoTransaction(
                nTransaction,
                static_cast<XBinary::INTERNAL_INFO *>(
                    &guardedThis->m_internalInfo))) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
    }

    return true;
}

void *XNSPACK::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XNSPACK> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XNSPACK::setInternalInfo(void *pInternalInfo)
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
// range decoder primitives
// ---------------------------------------------------------------------------

quint8 XNSPACK::_getByte(NSP_STATE *s)
{
    if (s->pSrcCurr >= s->pSrcEnd) {
        s->nError = 1;
        return 0xff;
    }
    return *(s->pSrcCurr++);
}

int XNSPACK::_getBit(NSP_STATE *s, quint32 nIndex)
{
    if (nIndex >= s->nTableEntries) {
        s->nError = 1;
        return 0xff;
    }

    quint16 *pv = &s->pTable[nIndex];
    quint32 nval = (quint32)(*pv) * (s->nBitmap >> 0xb);

    if (s->nOldval < nval) {
        s->nBitmap = nval;
        nval = *pv;
        quint32 sval = 0x800 - nval;
        sval = (quint32)(((qint32)sval) >> 5);
        sval += nval;
        *pv = (quint16)sval;
        if (s->nBitmap < 0x1000000) {
            s->nOldval = (s->nOldval << 8) | _getByte(s);
            s->nBitmap <<= 8;
        }
        return 0;
    }

    s->nBitmap -= nval;
    s->nOldval -= nval;
    nval = *pv;
    nval -= (nval >> 5);
    *pv = (quint16)nval;
    if (s->nBitmap < 0x1000000) {
        s->nOldval = (s->nOldval << 8) | _getByte(s);
        s->nBitmap <<= 8;
    }
    return 1;
}

quint32 XNSPACK::_get100Size(NSP_STATE *s, quint32 nBase, quint32 nMatchByte)
{
    quint32 count = 1;
    while (count < 0x100) {
        quint32 lpos = nMatchByte & 0xff;
        nMatchByte = (nMatchByte & 0xffffff00) | ((lpos << 1) & 0xff);
        lpos >>= 7;
        quint32 tpos = lpos + 1;
        tpos <<= 8;
        tpos += count;
        tpos = _getBit(s, nBase + tpos);
        count = (count * 2) | tpos;
        if (lpos != tpos) {
            while (count < 0x100) {
                count = (count * 2) | _getBit(s, nBase + count);
            }
        }
    }
    return count & 0xff;
}

quint32 XNSPACK::_get100(NSP_STATE *s, quint32 nBase)
{
    quint32 count = 1;
    while (count < 0x100) {
        count = (count * 2) | _getBit(s, nBase + count);
    }
    return count & 0xff;
}

quint32 XNSPACK::_getN(NSP_STATE *s, quint32 nBase, quint32 nBits)
{
    quint32 count = 1;
    quint32 bc = nBits;
    while (bc--) {
        count = count * 2 + _getBit(s, nBase + count);
    }
    return count - (1 << (nBits & 0xff));
}

quint32 XNSPACK::_getNSize(NSP_STATE *s, quint32 nBase, quint32 nBackSize)
{
    if (!_getBit(s, nBase)) {
        return _getN(s, nBase + (nBackSize << 3) + 2, 3);
    }
    if (!_getBit(s, nBase + 1)) {
        return 8 + _getN(s, nBase + (nBackSize << 3) + 0x82, 3);
    }
    return 0x10 + _getN(s, nBase + 0x102, 8);
}

quint32 XNSPACK::_getBB(NSP_STATE *s, quint32 nBase, quint32 nBack)
{
    quint32 pos = 1;
    quint32 bb = 0;
    if ((qint32)nBack <= 0) {
        return 0;
    }
    for (quint32 i = 0; i < nBack; i++) {
        quint32 bit = _getBit(s, nBase + pos);
        pos = (pos * 2) + bit;
        bb |= (bit << i);
    }
    return bb;
}

quint32 XNSPACK::_getBitmap(NSP_STATE *s, quint32 nBits)
{
    quint32 retv = 0;
    if ((qint32)nBits <= 0) {
        return 0;
    }
    while (nBits--) {
        s->nBitmap >>= 1;
        retv <<= 1;
        if (s->nOldval >= s->nBitmap) {
            s->nOldval -= s->nBitmap;
            retv |= 1;
        }
        if (s->nBitmap < 0x1000000) {
            s->nBitmap <<= 8;
            s->nOldval = (s->nOldval << 8) | _getByte(s);
        }
    }
    return retv;
}

// ---------------------------------------------------------------------------
// core decompressor
// ---------------------------------------------------------------------------

bool XNSPACK::_decompress(quint32 nTre, quint32 nAllocsz, quint32 nFirstByte, const quint8 *pSrc, quint32 nSsize, quint8 *pDst, quint32 nDsize, quint16 *pTable,
                          quint32 nTableEntries)
{
    quint32 nInit = (0x300u << ((nAllocsz + nTre) & 0xff)) + 0x736;
    if (nTableEntries < nInit) {
        return false;
    }
    for (quint32 k = 0; k < nInit; k++) {
        pTable[k] = 0x400;
    }

    NSP_STATE st;
    st.nError = 0;
    st.nOldval = 0;
    st.pSrcCurr = pSrc;
    st.nBitmap = 0xffffffff;
    st.pSrcEnd = pSrc + nSsize - 13;
    st.pTable = pTable;
    st.nTableEntries = nTableEntries;

    for (int i = 0; i < 5; i++) {
        st.nOldval = (st.nOldval << 8) | _getByte(&st);
    }
    if (st.nError) {
        return false;
    }

    quint32 nPrevBit = 0;
    quint32 nDone = 0;
    quint32 backbytes = 1, oldback = 1, old_oldback = 1, old_old_oldback = 1;
    quint32 damian = 0;
    quint32 put = (1u << (nAllocsz & 0xff)) - 1;
    quint32 bielle = 0;
    quint32 firstMask = (1u << (nFirstByte & 0xff)) - 1;

    for (;;) {
        if (st.nError) return false;

        quint32 backsize = firstMask & nDone;
        quint32 tpos;

        if (!_getBit(&st, (damian << 4) + backsize)) {
            // literal
            quint32 shft = (8 - (nTre & 0xff)) & 0xff;
            tpos = (bielle >> shft) + ((put & nDone) << (nTre & 0xff));
            tpos *= 3;
            tpos <<= 8;

            if ((qint32)damian >= 4) {
                damian -= ((qint32)damian >= 0xa) ? 6 : 3;
            } else {
                damian = 0;
            }

            if (nPrevBit) {
                if (backbytes > nDone) return false;
                quint32 matchByte = pDst[nDone - backbytes];
                bielle = _get100Size(&st, tpos + 0x736, matchByte);
                nPrevBit = 0;
            } else {
                bielle = _get100(&st, tpos + 0x736);
            }

            if (nDone >= nDsize) return false;
            pDst[nDone++] = (quint8)bielle;
            if (nDone >= nDsize) return true;
            continue;
        }

        // match
        bielle = nPrevBit = 1;

        if (_getBit(&st, damian + 0xc0)) {
            if (!_getBit(&st, damian + 0xcc)) {
                tpos = damian + 0xf;
                tpos <<= 4;
                tpos += backsize;
                if (!_getBit(&st, tpos)) {
                    if (!nDone) return false;
                    damian = 2 * ((qint32)damian >= 7 ? 1 : 0) + 9;
                    if (backbytes > nDone) return false;
                    bielle = pDst[nDone - backbytes];
                    if (nDone >= nDsize) return false;
                    pDst[nDone++] = (quint8)bielle;
                    if (nDone >= nDsize) return true;
                    continue;
                } else {
                    backsize = _getNSize(&st, 0x534, backsize);
                    damian = ((qint32)damian >= 7) ? 1 : 0;
                    damian = ((damian - 1) & 0xfffffffd) + 0xb;
                }
            } else {
                if (!_getBit(&st, damian + 0xd8)) {
                    tpos = oldback;
                } else {
                    if (!_getBit(&st, damian + 0xe4)) {
                        tpos = old_oldback;
                    } else {
                        tpos = old_old_oldback;
                        old_old_oldback = old_oldback;
                    }
                    old_oldback = oldback;
                }
                oldback = backbytes;
                backbytes = tpos;

                backsize = _getNSize(&st, 0x534, backsize);
                damian = ((qint32)damian >= 7) ? 1 : 0;
                damian = ((damian - 1) & 0xfffffffd) + 0xb;
            }
        } else {
            old_old_oldback = old_oldback;
            old_oldback = oldback;
            oldback = backbytes;

            damian = ((qint32)damian >= 7) ? 1 : 0;
            damian = ((damian - 1) & 0xfffffffd) + 0xa;

            backsize = _getNSize(&st, 0x332, backsize);

            tpos = ((qint32)backsize >= 4) ? 3 : backsize;
            tpos <<= 6;
            tpos = _getN(&st, 0x1b0 + tpos, 6);

            quint32 temp;
            if (tpos >= 4) {
                quint32 sbits = tpos;
                sbits >>= 1;
                sbits--;
                temp = (tpos & bielle) | 2;
                temp <<= (sbits & 0xff);
                if ((qint32)tpos < 0xe) {
                    temp += _getBB(&st, (temp - tpos) + 0x2af, sbits);
                } else {
                    sbits += 0xfffffffc;
                    tpos = _getBitmap(&st, sbits);
                    tpos <<= 4;
                    temp += tpos;
                    temp += _getBB(&st, 0x322, 4);
                }
            } else {
                temp = tpos;
            }
            backbytes = temp + 1;
        }

        // checkloop_and_backcopy
        if (!backbytes) return true;
        if (backbytes > nDone) return false;

        backsize += 2;
        if (((quint64)nDone + backsize > nDsize) || (backbytes > nDone)) {
            return false;
        }

        do {
            pDst[nDone] = pDst[nDone - backbytes];
            nDone++;
        } while (--backsize && nDone < nDsize);
        bielle = pDst[nDone - 1];

        if (nDone >= nDsize) return true;
    }
}

// ---------------------------------------------------------------------------
// E8/E9 CALL/JMP address de-filter
// ---------------------------------------------------------------------------

// To improve compression, NsPack rewrites the operand of every E8 (CALL) and
// E9 (JMP rel32) in the original image: the little-endian relative target is
// biased by its own buffer offset and stored big-endian (so similar targets
// share high bytes). The decompressor reproduces those filtered operands
// verbatim, so the rebuilt image needs the inverse pass to become runnable.
//
// The packer applies the filter in a single naive forward pass over the whole
// decompressed blob (every 0xE8/0xE9 byte, data included, then skip the 4
// operand bytes), so reversing it with the identical scan restores the stream
// exactly - bytes that merely look like an opcode are handled the same on both
// sides. For each opcode at offset i the stored value is (rel + (i + 1)) in
// big-endian, hence rel = big_endian(operand) - (i + 1), written back little-
// endian.
void XNSPACK::_deFilterCallJmp(quint8 *pData, quint32 nSize)
{
    if ((!pData) || (nSize < 5)) {
        return;
    }

    for (quint32 i = 0; i + 5 <= nSize;) {
        if ((pData[i] == 0xE8) || (pData[i] == 0xE9)) {
            quint32 nBE = ((quint32)pData[i + 1] << 24) | ((quint32)pData[i + 2] << 16) | ((quint32)pData[i + 3] << 8) | (quint32)pData[i + 4];
            quint32 nRel = nBE - (i + 1);
            pData[i + 1] = (quint8)(nRel & 0xff);
            pData[i + 2] = (quint8)((nRel >> 8) & 0xff);
            pData[i + 3] = (quint8)((nRel >> 16) & 0xff);
            pData[i + 4] = (quint8)((nRel >> 24) & 0xff);
            i += 5;
        } else {
            i++;
        }
    }
}

// ---------------------------------------------------------------------------
// import directory reconstruction
// ---------------------------------------------------------------------------

// NsPack keeps a compact per-DLL descriptor stream (located via the loader's
// [ebp-0x20f] field) that its runtime loader walks to rebuild the original IAT
// via LoadLibrary/GetProcAddress. Each descriptor is:
//     u32 marker(!=0) | u32 dllNameOffset | u32 firstThunkRva | u32 nameAdvance
//     then 1-byte function-name lengths, terminated by a 0 byte.
// DLL names live in the loader's name table (RVA loaderRva-0xd3); function names
// are concatenated in the decompressed blob at (descriptorStart + nameAdvance),
// a leading 0xFF marking an import-by-ordinal. We decode that and synthesize a
// standard IMAGE_IMPORT_DESCRIPTOR table (+ INT/hint-name/DLL strings), point
// each FirstThunk at the real IAT, and fill that IAT with a copy of the INT.
QByteArray XNSPACK::_reconstructImports(QByteArray *pBaBlob, quint32 nRva, quint32 nImpRva, quint32 *pnDescSize, PDSTRUCT *pPdStruct)
{
    if (pnDescSize) *pnDescSize = 0;
    if ((!pBaBlob) || pBaBlob->isEmpty()) return QByteArray();

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return QByteArray();

    // The NsPack loader sits at the entry point (2.x reaches it through an E9
    // redirector). Follow that, then confirm the common stub prologue. The import
    // header fields ([loader-0x20f], loaderRva-0xd3) are shared by 2.x and 3.x;
    // other layouts (e.g. 1.4) simply fail the range check below and yield no imports.
    quint32 nEpRva = pe.getOptionalHeader_AddressOfEntryPoint();
    qint64 nLoaderOffset = pe.relAddressToOffset(nEpRva);
    if (nLoaderOffset == -1) return QByteArray();
    QByteArray baEp = read_array_process(nLoaderOffset, 8, pPdStruct);
    if ((baEp.size() >= 5) && ((quint8)baEp.at(0) == 0xe9)) {
        nEpRva = nspRd32((const quint8 *)baEp.constData() + 1) + nEpRva + 5;
        nLoaderOffset = pe.relAddressToOffset(nEpRva);
        if (nLoaderOffset == -1) return QByteArray();
        baEp = read_array_process(nLoaderOffset, 8, pPdStruct);
    }
    if ((baEp.size() < 8) || (memcmp(baEp.constData(), "\x9c\x60\xe8\x00\x00\x00\x00\x5d", 8) != 0)) return QByteArray();
    XADDR nLoaderRva = pe.offsetToRelAddress(nLoaderOffset);
    if (nLoaderRva == (XADDR)-1) return QByteArray();

    QByteArray baDescField = read_array_process(nLoaderOffset - 0x20f, 4, pPdStruct);
    if (baDescField.size() < 4) return QByteArray();
    quint32 nDescRva = nspRd32((const quint8 *)baDescField.constData());
    quint32 nDllTblRva = (quint32)nLoaderRva - 0xd3;

    const quint32 nBlobSize = (quint32)pBaBlob->size();
    if ((nDescRva < nRva) || ((quint64)(nDescRva - nRva) + 16 > (quint64)nBlobSize)) return QByteArray();
    const quint8 *blob = (const quint8 *)pBaBlob->constData();

    struct RFUNC {
        bool bOrd;
        quint32 nOrd;
        QString sName;
        quint32 nIatRva;
    };
    struct RDLL {
        QString sName;
        quint32 nFirstThunk;
        QList<RFUNC> listFuncs;
    };
    QList<RDLL> listDlls;

    quint32 d = nDescRva - nRva;
    qint32 nGuard = 0;
    while (nGuard++ < 4096) {
        if ((quint64)d + 16 > nBlobSize) return QByteArray();
        quint32 nMarker = nspRd32(blob + d);
        quint32 nNameOff = nspRd32(blob + d + 4);
        quint32 nIat = nspRd32(blob + d + 8);
        if ((nMarker == 0) && (nNameOff == 0) && (nIat == 0)) break;  // end of list
        quint32 nNameAdvance = nspRd32(blob + d + 12);

        quint32 lp = d + 16;
        QList<quint32> listLengths;
        while ((lp < nBlobSize) && (blob[lp] != 0)) {
            listLengths.append(blob[lp]);
            lp++;
        }
        if (lp >= nBlobSize) return QByteArray();

        qint64 nDllNameOffset = pe.relAddressToOffset(nDllTblRva + nNameOff);
        if (nDllNameOffset == -1) return QByteArray();
        QByteArray baDllName = read_array_process(nDllNameOffset, 64, pPdStruct);
        int nZero = baDllName.indexOf('\0');
        if (nZero >= 0) baDllName.truncate(nZero);
        if (baDllName.isEmpty()) return QByteArray();

        RDLL rdll;
        rdll.sName = QString::fromLatin1(baDllName);
        rdll.nFirstThunk = nIat;

        quint32 fb = d + nNameAdvance;
        quint32 slot = nIat;
        for (int i = 0; i < listLengths.size(); i++) {
            quint32 L = listLengths.at(i);
            if ((quint64)fb + L + 5 > nBlobSize) return QByteArray();
            RFUNC f = {};
            f.nIatRva = slot;
            if (blob[fb] == 0xff) {
                f.bOrd = true;
                f.nOrd = nspRd32(blob + fb + 1) & 0x7fffffff;
            } else {
                f.bOrd = false;
                f.sName = QString::fromLatin1((const char *)(blob + fb), (int)L);
            }
            rdll.listFuncs.append(f);
            fb += L;
            slot += 4;
        }
        listDlls.append(rdll);
        d = lp + 1;
    }
    if (listDlls.isEmpty()) return QByteArray();

    // ---- lay out the import section: [descriptors][INTs][hint/names][dll strings] ----
    const quint32 nDescSize = (quint32)(listDlls.size() + 1) * 20;
    quint32 nCur = nDescSize;
    QList<quint32> listIntRva;
    for (int i = 0; i < listDlls.size(); i++) {
        listIntRva.append(nCur);
        nCur += (quint32)(listDlls.at(i).listFuncs.size() + 1) * 4;
    }
    QMap<QString, quint32> mapHintName;
    quint32 nNamesStart = nCur;
    QByteArray baNames;
    for (int i = 0; i < listDlls.size(); i++) {
        for (int j = 0; j < listDlls.at(i).listFuncs.size(); j++) {
            const RFUNC &f = listDlls.at(i).listFuncs.at(j);
            if ((!f.bOrd) && (!mapHintName.contains(f.sName))) {
                mapHintName.insert(f.sName, nNamesStart + (quint32)baNames.size());
                baNames.append((char)0);
                baNames.append((char)0);  // hint
                baNames.append(f.sName.toLatin1());
                baNames.append((char)0);
                if (baNames.size() & 1) baNames.append((char)0);
            }
        }
    }
    nCur = nNamesStart + (quint32)baNames.size();
    QMap<QString, quint32> mapDllStr;
    quint32 nDllStart = nCur;
    QByteArray baDllStrings;
    for (int i = 0; i < listDlls.size(); i++) {
        const QString &s = listDlls.at(i).sName;
        if (!mapDllStr.contains(s)) {
            mapDllStr.insert(s, nDllStart + (quint32)baDllStrings.size());
            baDllStrings.append(s.toLatin1());
            baDllStrings.append((char)0);
        }
    }
    const quint32 nImpSize = nDllStart + (quint32)baDllStrings.size();

    QByteArray baSection(nImpSize, (char)0);
    char *ps = baSection.data();
    char *pBlobW = pBaBlob->data();

    for (int i = 0; i < listDlls.size(); i++) {
        const RDLL &dll = listDlls.at(i);
        char *pd = ps + i * 20;
        _write_uint32(pd + 0, nImpRva + listIntRva.at(i));       // OriginalFirstThunk (INT)
        _write_uint32(pd + 12, nImpRva + mapDllStr.value(dll.sName));  // Name
        _write_uint32(pd + 16, dll.nFirstThunk);                 // FirstThunk (real IAT)
        for (int j = 0; j < dll.listFuncs.size(); j++) {
            const RFUNC &f = dll.listFuncs.at(j);
            quint32 nEntry = f.bOrd ? (0x80000000u | f.nOrd) : (nImpRva + mapHintName.value(f.sName));
            _write_uint32(ps + listIntRva.at(i) + j * 4, nEntry);
            // fill the real IAT slot (inside the decompressed blob) with the same value
            if ((f.nIatRva >= nRva) && ((quint64)(f.nIatRva - nRva) + 4 <= (quint64)nBlobSize)) {
                _write_uint32(pBlobW + (f.nIatRva - nRva), nEntry);
            }
        }
    }
    memcpy(ps + nNamesStart, baNames.constData(), baNames.size());
    memcpy(ps + nDllStart, baDllStrings.constData(), baDllStrings.size());

    if (pnDescSize) *pnDescSize = nDescSize;
    return baSection;
}

// ---------------------------------------------------------------------------
// minimal single-section PE rebuild
// ---------------------------------------------------------------------------

QByteArray XNSPACK::_buildPE(const QByteArray &baBlob, quint32 nRva, quint32 nImageBase, quint32 nOEP, const QByteArray &baImportSection, quint32 nImpRva,
                             quint32 nDescSize)
{
    const bool bImports = !baImportSection.isEmpty();
    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    const quint32 nBaseSecs = 1 + (bImports ? 1 : 0);  // .clam01 [+ .idata]
    quint32 nRawBase = nspAlign(nHeaderBase + 0x28 * nBaseSecs, 0x200);
    const bool bGhost = (nRva > nspAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = nspAlign(nHeaderBase + 0x28 * (nBaseSecs + 1), 0x200);
    }
    const quint32 nNumSections = nBaseSecs + (bGhost ? 1 : 0);

    const quint32 nRsz = nspAlign((quint32)baBlob.size(), 0x200);
    const quint32 nImpRaw = nRawBase + nRsz;
    const quint32 nImpRsz = bImports ? nspAlign((quint32)baImportSection.size(), 0x200) : 0;
    QByteArray baResult(nImpRaw + nImpRsz, (char)0);
    char *p = baResult.data();

    _write_uint16(p + 0, 0x5A4D);
    _write_uint32(p + 0x3C, 0x40);
    char *pe = p + 0x40;
    _write_uint32(pe + 0, 0x00004550);

    char *fh = pe + 4;
    _write_uint16(fh + 0, 0x014C);
    _write_uint16(fh + 2, (quint16)nNumSections);
    _write_uint16(fh + 16, 0x00E0);
    _write_uint16(fh + 18, 0x010F);

    quint32 nImageEnd = nspAlign(nRva + (quint32)baBlob.size(), 0x1000);
    if (bImports) nImageEnd = nspAlign(nImpRva + (quint32)baImportSection.size(), 0x1000);

    char *oh = fh + 20;
    _write_uint16(oh + 0, 0x010B);
    _write_uint32(oh + 16, nOEP);
    _write_uint32(oh + 28, nImageBase);
    _write_uint32(oh + 32, 0x1000);
    _write_uint32(oh + 36, 0x200);
    _write_uint16(oh + 40, 4);
    _write_uint16(oh + 48, 4);
    _write_uint32(oh + 56, nImageEnd);
    _write_uint32(oh + 60, nRawBase);
    _write_uint16(oh + 68, 2);
    _write_uint32(oh + 92, 16);
    if (bImports) {
        _write_uint32(oh + 104, nImpRva);     // DataDirectory[1] (import) RVA
        _write_uint32(oh + 108, nDescSize);   // DataDirectory[1] size
    }

    char *sec = oh + 0xE0;
    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = nspAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, nRva - nGhostVA);
        _write_uint32(sec + 12, nGhostVA);
        _write_uint32(sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    memcpy(sec, ".clam01", 7);
    _write_uint32(sec + 8, (quint32)baBlob.size());
    _write_uint32(sec + 12, nRva);
    _write_uint32(sec + 16, nRsz);
    _write_uint32(sec + 20, nRawBase);
    _write_uint32(sec + 36, 0xE00000E0);

    memcpy(baResult.data() + nRawBase, baBlob.constData(), baBlob.size());

    if (bImports) {
        sec += 0x28;
        memcpy(sec, ".idata", 6);
        _write_uint32(sec + 8, (quint32)baImportSection.size());
        _write_uint32(sec + 12, nImpRva);
        _write_uint32(sec + 16, nImpRsz);
        _write_uint32(sec + 20, nImpRaw);
        _write_uint32(sec + 36, 0xC0000040);
        memcpy(baResult.data() + nImpRaw, baImportSection.constData(), baImportSection.size());
    }

    return baResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

qint64 XNSPACK::_findStartOfStuff(quint32 nSec0Vsize, PDSTRUCT *pPdStruct)
{
    const qint64 nFileSize = getSize();
    if (nFileSize < 14) return -1;

    char needle[4];
    _write_uint32(needle, nSec0Vsize);

    qint64 nBest = -1;
    qint64 nFrom = 0;
    while (true) {
        qint64 nHit = find_array(nFrom, nFileSize - nFrom, needle, 4, pPdStruct);
        if (nHit == -1) break;
        nFrom = nHit + 1;

        qint64 nSos = nHit - 9;  // dsize sits at sos+9
        if ((nSos < 0) || (nSos <= nBest)) continue;

        QByteArray baHdr = read_array_process(nSos, 14, pPdStruct);
        if (baHdr.size() < 14) continue;
        const quint8 *h = (const quint8 *)baHdr.constData();

        quint8 c = h[0];
        if (c >= 0xe1) continue;
        // mode-byte split -> the range-coder table shift must be sane
        quint32 nFirstByte = 0;
        if (c >= 0x2d) { nFirstByte = c / 0x2d; c = (quint8)(c - 0x2d * nFirstByte); }
        quint32 nAllocsz = 0;
        if (c >= 9) { nAllocsz = c / 9; c = (quint8)(c - 9 * nAllocsz); }
        if (((nAllocsz + (quint32)c) & 0xff) > 12) continue;

        quint32 nSsize = nspRd32(h + 5);
        if ((nSsize <= 13) || ((quint64)nSos + nSsize > (quint64)nFileSize)) continue;

        nBest = nSos;
    }
    return nBest;
}

XNSPACK::INTERNAL_INFO XNSPACK::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    if (listSections.isEmpty()) {
        return result;
    }

    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();
    quint32 nEpRva = pe.getOptionalHeader_AddressOfEntryPoint();
    qint64 nRep = pe.relAddressToOffset(nEpRva);
    if (nRep == -1) {
        return result;
    }

    QByteArray baSrc = read_array_process(nRep, 24, pPdStruct);
    if (baSrc.size() < 24) {
        return result;
    }
    quint32 nEprva = nEpRva;

    if ((quint8)baSrc.at(0) == 0xe9) {
        nEprva = nspRd32((const quint8 *)baSrc.constData() + 1) + nEpRva + 5;
        nRep = pe.relAddressToOffset(nEprva);
        if (nRep == -1) return result;
        baSrc = read_array_process(nRep, 24, pPdStruct);
        if (baSrc.size() < 24) return result;
    }

    const quint8 *src = (const quint8 *)baSrc.constData();
    // Common NsPack loader-stub prologue (1.x/2.x/3.x): pushfd; pushad; call$+5; pop ebp.
    if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d", 8) != 0) {
        return result;
    }
    const bool b2x = (memcmp(src + 8, "\xb8\x07\x00\x00\x00", 5) == 0);
    const quint32 nSec0Vsize = listSections.at(0).Misc.VirtualSize;

    qint64 nStartOfStuff = -1;
    quint32 nOEP = listSections.at(0).VirtualAddress;

    if (b2x) {
        // ---- NsPack 2.x: EP-stub-relative delta locates the start-of-stuff ----
        quint32 nNowinldr = 0x54 - nspRd32(src + 17);
        if ((qint64)nRep - nNowinldr < 0) {
            return result;
        }
        QByteArray baDelta = read_array_process(nRep - nNowinldr, 4, pPdStruct);
        if (baDelta.size() < 4) return result;

        nStartOfStuff = nRep + nspRd32((const quint8 *)baDelta.constData());
        QByteArray baSos0 = read_array_process(nStartOfStuff, 20, pPdStruct);
        if (baSos0.size() < 20) return result;
        if (nspRd32((const quint8 *)baSos0.constData()) == 0) {
            nStartOfStuff += 4;  // skip a leading zero dword
        }

        // OEP: the 2.x stub reaches the original entry via a jmp at EP+0x27a.
        quint32 nOepJmpRva = nEprva + 0x27a;
        qint64 nRepOEP = pe.relAddressToOffset(nOepJmpRva);
        if (nRepOEP != -1) {
            QByteArray baOEP = read_array_process(nRepOEP, 5, pPdStruct);
            if (baOEP.size() >= 5) nOEP = nOepJmpRva + 5 + nspRd32((const quint8 *)baOEP.constData() + 1);
        }
    } else {
        // ---- NsPack 1.4 / 3.x: the loader is at the entry point itself. Its
        // start-of-stuff isn't reachable by the 2.x delta, so locate the nsp0
        // block header directly (its dsize field == section[0].VirtualSize) and
        // recover the OEP from the loader's tail (popad; popfd; jmp <into image>).
        nStartOfStuff = _findStartOfStuff(nSec0Vsize, pPdStruct);
        if (nStartOfStuff == -1) return result;

        QByteArray baLoader = read_array_process(nRep, 0x600, pPdStruct);
        const quint32 nSec1Rva = (listSections.size() > 1) ? listSections.at(1).VirtualAddress : 0xFFFFFFFF;
        for (int i = 0; i + 7 <= baLoader.size(); i++) {
            const quint8 *q = (const quint8 *)baLoader.constData() + i;
            if ((q[0] == 0x61) && (q[1] == 0x9d) && (q[2] == 0xe9)) {
                quint32 nTgt = (quint32)nEprva + (quint32)i + 2 + 5 + nspRd32(q + 3);
                if ((nTgt >= listSections.at(0).VirtualAddress) && (nTgt < nSec1Rva)) {
                    nOEP = nTgt;
                    break;
                }
            }
        }
    }

    QByteArray baSos = read_array_process(nStartOfStuff, 14, pPdStruct);
    if (baSos.size() < 14) return result;
    const quint8 *sos = (const quint8 *)baSos.constData();

    quint32 nSsize = nspRd32(sos + 5);
    quint32 nDsize = nspRd32(sos + 9);
    if (!nSsize || !nDsize || (nDsize != nSec0Vsize)) {
        return result;
    }

    result.bIsValid = true;
    result.nStartOfStuff = nStartOfStuff;
    result.nSsize = nSsize;
    result.nDsize = nDsize;
    result.nOEP = nOEP;
    result.nRva = listSections.at(0).VirtualAddress;
    result.nImageBase = nImageBase;

    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XNSPACK::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XNSPACK::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool {
        return !pPdStruct || isPdStructLifetimeAlive(progressLifetime);
    };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XNSPACK> guardedThis(this);

    if (pState->pContext || !pState->baUnpackSourceToken.isEmpty()) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pOldContext || !pLifetimeState->setContexts.contains(pOldContext) ||
            (pOldContext->pOwnerState != pState) ||
            (pOldContext->baToken != pState->baUnpackSourceToken)) return false;
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
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;
    const qint64 nSourceSize = guardedSource->size();
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || (nSourceSize < 0)) return false;
    QScopedPointer<XMaterializedUnpackGuard> pSourceGuard(XMaterializedUnpackGuard::bind(guardedSource.data(), pPdStruct));
    if (!isProgressAlive() || !pSourceGuard || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    QScopedPointer<QIODevice> pSnapshot(createFileBuffer(nSourceSize, pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pSnapshot ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;
    const bool bCopied = copyDeviceMemory(guardedSource.data(), 0, pSnapshot.data(), 0, nSourceSize, pPdStruct);
    if (!isProgressAlive() || !bCopied || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    XNSPACK worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !info.bIsValid) return false;
    QByteArray baData;
    const bool bUnpacked = worker._unpackToBuffer(baData, pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !bUnpacked || baData.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
    pContext->baData = baData;
    pContext->sFileName = sFileName;
    pContext->sInfo = QString("NsPack %1").arg(worker.getVersion());
    pContext->pSourceDevice = guardedSource;
    pContext->pOwnerState = pState;
    pContext->baToken = QUuid::createUuid().toRfc4122();
    pContext->nDeviceGeneration = nGeneration;
    pContext->nSourceSize = nSourceSize;
    pContext->nCurrentOffset = 0;
    pContext->nCurrentIndex = 0;
    if (pContext->baToken.isEmpty()) return false;
    const bool bSourceFinal = pSourceGuard->validateAndFinalize(pPdStruct);
    if (!isProgressAlive() || !bSourceFinal || !guardedThis || !guardedSource ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
        !isPdStructNotCanceled(pPdStruct)) return false;
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

XBinary::ARCHIVERECORD XNSPACK::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XNSPACK> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize)) return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return result;

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

bool XNSPACK::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= 1) ||
        (pState->nNumberOfRecords != 1) || (pState->nTotalSize != pContext->nSourceSize)) return false;

    return false;
}

bool XNSPACK::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
    if (!pContext || !pLifetimeState->setContexts.contains(pContext) ||
        (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return false;
    pLifetimeState->setContexts.remove(pContext);
    *pState = UNPACK_STATE();
    delete pContext;
    return true;
}

bool XNSPACK::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XNSPACK> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !guardedOutput || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nCurrentIndex != 0) || (pState->nNumberOfRecords != 1) ||
        (pState->nTotalSize != pContext->nSourceSize)) return false;

    const bool bOpen = guardedOutput->isOpen();
    if (!guardedThis || !guardedOutput || !bOpen) return false;
    const bool bWritable = guardedOutput->isWritable();
    if (!guardedThis || !guardedOutput || !bWritable) return false;
    const bool bSequential = guardedOutput->isSequential();
    if (!guardedThis || !guardedOutput || bSequential) return false;
    const QIODevice::OpenMode openMode = guardedOutput->openMode();
    if (!guardedThis || !guardedOutput ||
        (openMode & (QIODevice::Append | QIODevice::Text)) ||
        !isResizeEnable(guardedOutput.data())) return false;
    QPointer<QIODevice> guardedSource(pContext->pSourceDevice);
    if (guardedSource && devicesAlias(guardedSource.data(), guardedOutput.data())) return false;
    if (!guardedThis || !guardedOutput) return false;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis || !guardedOutput ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return false;

    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    const bool bResult = writeUnpackData(&writeState, guardedOutput.data(), pContext->baData, pPdStruct);
    const bool bSourceCurrent = bResult && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bAuthenticated = bSourceCurrent && guardedThis && guardedOutput && pLifetimeState->bOwnerAlive &&
                                pLifetimeState->setContexts.contains(pContext) &&
                                (pState->pContext == pContext) && (pContext->pOwnerState == pState) &&
                                (pState->baUnpackSourceToken == pContext->baToken) &&
                                (pState->nCurrentIndex == pContext->nCurrentIndex) &&
                                (pState->nCurrentOffset == pContext->nCurrentOffset) &&
                                (pState->nNumberOfRecords == 1) &&
                                (pState->nTotalSize == pContext->nSourceSize);
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

bool XNSPACK::_unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    if (!isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    qint64 nAvail = getSize() - info.nStartOfStuff;
    if (nAvail <= 13) return false;
    QByteArray baStuff = read_array_process(info.nStartOfStuff, nAvail, pPdStruct);
    if (baStuff.size() <= 13) return false;
    const quint8 *stuff = (const quint8 *)baStuff.constData();

    quint8 c = stuff[0];
    if (c >= 0xe1) return false;

    quint32 nFirstByte = 0;
    if (c >= 0x2d) {
        nFirstByte = c / 0x2d;
        c = (quint8)(c - 0x2d * nFirstByte);
    }
    quint32 nAllocsz = 0;
    if (c >= 9) {
        nAllocsz = c / 9;
        c = (quint8)(c - 9 * nAllocsz);
    }
    quint32 nTre = c;

    quint32 nShift = (nTre + nAllocsz) & 0xff;
    if (nShift > 12) return false;
    quint32 nTableEntries = (0x300u << nShift) + 0x736;

    quint32 nDsize = nspRd32(stuff + 9);
    quint32 nSsize = nspRd32(stuff + 5);
    if ((nSsize <= 13) || (nDsize != info.nDsize)) return false;

    std::vector<quint16> table(nTableEntries);
    QByteArray baDest(nDsize, (char)0);

    if (!_decompress(nTre, nAllocsz, nFirstByte, stuff + 0xd, (quint32)baStuff.size(), (quint8 *)baDest.data(), nDsize, table.data(), nTableEntries)) {
        return false;
    }

    _deFilterCallJmp((quint8 *)baDest.data(), nDsize);

    quint32 nImpRva = nspAlign(info.nRva + (quint32)baDest.size(), 0x1000);
    quint32 nDescSize = 0;
    QByteArray baImports = _reconstructImports(&baDest, info.nRva, nImpRva, &nDescSize, pPdStruct);

    QByteArray baPE = _buildPE(baDest, info.nRva, info.nImageBase, info.nOEP, baImports, nImpRva, nDescSize);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}
