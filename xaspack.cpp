/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xaspack.h"
#include "xmaterializedunpackguard.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <climits>
#include <cstring>
#include <vector>

// Stub layout table.  `nEpBuffOff` is relative to AddressOfEntryPoint; every
// other offset is relative to (AddressOfEntryPoint - 1), which is where the
// stub's own base pointer lands.  The values were derived per generation from
// the packed corpus: the entry signature identifies the stub build, the
// `68 00 00 00 00 c3` marker at nEpBuffOff confirms it, and the remaining
// offsets locate the block table, the two constant decoder tables, the
// call/jmp filter marker byte and the stored original entry point.
namespace {

struct ASPACK_LAYOUT {
    XASPACK::AVER version;
    const char *pszSignature;  // exact bytes required at the entry point
    int nSignatureSize;
    quint32 nEpBuffOff;  // "\x68\x00\x00\x00\x00\xc3" marker, EP-relative
    quint32 nBlocksOff;
    quint32 nBlockStride;  // bytes per block-table entry
    quint32 nStrMltOff;
    quint32 nCompBOff;
    quint32 nWrkbufOff;
    quint32 nOepOff;
    const char *pszVersion;
};

// ASPack 2.00 and 2.01/2.1 keep the original entry point in the stub data area
// instead of an immediate, and their block table uses 8-byte entries like 2.12.
const ASPACK_LAYOUT g_aspackLayouts[] = {
    {XASPACK::AVER_212, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8, 0x3b9, 0x57c, 8, 0x70e, 0x6d6, 0x148, 0x39b, "2.12"},
    {XASPACK::AVER_22, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8, 0x414, 0x5d0, 12, 0x6ca, 0x692, 0x145, 0x3f6, "2.2"},
    {XASPACK::AVER_OTHER, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8, 0x41f, 0x5d8, 12, 0x76a, 0x732, 0x13a, 0x401, "2.xx"},
    {XASPACK::AVER_242, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8, 0x42b, 0x5e4, 12, 0x776, 0x73e, 0x148, 0x40d, "2.42"},
    {XASPACK::AVER_200, "\x60\xe8\x70\x05\x00\x00\xeb", 7, 0x4fb, 0x0de, 8, 0x623, 0x5eb, 0x292, 0x0d2, "2.00"},
    {XASPACK::AVER_201, "\x60\xe8\x72\x05\x00\x00\xeb", 7, 0x4fd, 0x0de, 8, 0x625, 0x5ed, 0x294, 0x0d2, "2.01/2.1"},
};

const ASPACK_LAYOUT *aspackLayout(XASPACK::AVER version)
{
    for (const ASPACK_LAYOUT &layout : g_aspackLayouts) {
        if (layout.version == version) return &layout;
    }
    return nullptr;
}

// The 0x72-byte constant table the decoder indexes as `stuff[]`.  Requiring it
// at the layout's offset keeps detection specific to a real ASPack stub.
const quint8 g_aspackCompBTable[0x72] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x14, 0x18, 0x1c,
    0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x70, 0x80, 0xa0, 0xc0, 0xe0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02,
    0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0a, 0x0a,
    0x0b, 0x0b, 0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12};

}  // namespace

static inline quint32 aspRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 aspAlign(quint32 v, quint32 a)
{
    return (v + a - 1) & ~(a - 1);
}

static inline quint32 aspRol32(quint32 v, quint32 n)
{
    n &= 31;
    return n ? ((v << n) | (v >> (32 - n))) : v;
}

XASPACK::XASPACK(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XASPACK::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XASPACK::~XASPACK()
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

XASPACK::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XASPACK::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive &&
           !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XASPACK::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XASPACK> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XASPACK::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XASPACK a(pDevice);
    return a.isValid(pPdStruct);
}

XBinary::FT XASPACK::getFileType()
{
    return FT_PE32_ASPACK;
}

QString XASPACK::getVersion()
{
    QPointer<XASPACK> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo());
    return (guardedThis && pInfo && pInfo->bIsValid) ? pInfo->sVersion
                                                     : QString();
}

XASPACK::INTERNAL_INFO XASPACK::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XASPACK::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XASPACK> guardedThis(this);
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

void *XASPACK::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XASPACK> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XASPACK::setInternalInfo(void *pInternalInfo)
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
// bit-stream + Huffman decoder
// ---------------------------------------------------------------------------

int XASPACK::_readstream(ASPK *s)
{
    while (s->bitpos >= 8) {
        if (s->input >= s->iend) return 0;
        s->hash = (s->hash << 8) | *s->input;
        s->input++;
        s->bitpos -= 8;
    }
    return 1;
}

quint32 XASPACK::_getdec(ASPK *s, quint8 which, int *err)
{
    quint32 ret;
    quint8 pos;
    quint32 *d3 = s->decarray3[which];
    quint32 *d4 = s->decarray4[which];

    *err = 1;
    if (!_readstream(s)) return 0;

    ret = (s->hash >> (8 - s->bitpos)) & 0xfffe00;

    if (ret < d3[8]) {
        if ((ret >> 16) >= 0x100) return 0;
        if (!(pos = s->dict_helper[which].ends[ret >> 16]) || pos >= 24) return 0;
    } else {
        if (ret < d3[10]) {
            pos = (ret < d3[9]) ? 9 : 10;
        } else if (ret < d3[11]) {
            pos = 11;
        } else if (ret < d3[12]) {
            pos = 12;
        } else if (ret < d3[13]) {
            pos = 13;
        } else if (ret < d3[14]) {
            pos = 14;
        } else {
            pos = 15;
        }
    }

    s->bitpos += pos;
    ret = ((ret - d3[pos - 1]) >> (24 - pos)) + d4[pos];

    if (ret >= s->dict_helper[which].size) return 0;
    ret = s->dict_helper[which].starts[ret];

    *err = 0;
    return ret;
}

quint8 XASPACK::_buildArray(ASPK *s, quint8 *array, quint8 which)
{
    quint32 sum = 0, counter = 23, i, endoff = 0, bus[18], dict[18];
    quint32 *d3 = s->decarray3[which];
    quint32 *d4 = s->decarray4[which];

    memset(bus, 0, sizeof(bus));
    memset(dict, 0, sizeof(dict));

    for (i = 0; i < s->dict_helper[which].size; i++) {
        if (array[i] > 17) return 0;
        bus[array[i]]++;
    }

    d3[0] = 0;
    d4[0] = 0;
    i = 0;
    while (counter >= 9) {
        sum += (bus[i + 1] << counter);
        if (sum > 0x1000000) return 0;

        d3[i + 1] = sum;
        d4[i + 1] = dict[i + 1] = bus[i] + d4[i];

        if (counter >= 0x10) {
            quint32 old = endoff;
            endoff = d3[i + 1] >> 0x10;
            if (endoff < old) return 0;
            quint32 remaining = endoff - old;
            if (remaining > 0) {
                if (old + remaining > 0x100) return 0;
                memset(s->dict_helper[which].ends + old, i + 1, remaining);
            }
        }
        i++;
        counter--;
    }

    if (sum != 0x1000000) return 0;

    for (i = 0; i < s->dict_helper[which].size; i++) {
        if (array[i]) {
            if (array[i] > 17) return 0;
            if (dict[array[i]] >= s->dict_helper[which].size) return 0;
            s->dict_helper[which].starts[dict[array[i]]] = i;
            dict[array[i]]++;
        }
    }

    return 1;
}

quint8 XASPACK::_getbits(ASPK *s, quint32 num, int *err)
{
    if (!_readstream(s)) {
        *err = 1;
        return 0;
    }
    *err = 0;
    quint8 retvalue = (quint8)(((s->hash >> (8 - s->bitpos)) & 0xffffff) >> (24 - num));
    s->bitpos += num;
    return retvalue;
}

int XASPACK::_buildDicts(ASPK *s)
{
    unsigned int counter;
    quint32 ret;
    int oob;

    if (!_getbits(s, 1, &oob)) memset(s->decrypt_dict, 0, 0x2f5);
    if (oob) return 0;

    for (counter = 0; counter < 19; counter++) {
        s->array1[counter] = _getbits(s, 4, &oob);
        if (oob) return 0;
    }

    if (!_buildArray(s, s->array1, 3)) return 0;

    counter = 0;
    while (counter < 757) {
        ret = _getdec(s, 3, &oob);
        if (oob) return 0;
        if (ret >= 16) {
            if (ret != 16) {
                if (ret == 17)
                    ret = 3 + _getbits(s, 3, &oob);
                else
                    ret = 11 + _getbits(s, 7, &oob);
                if (oob) return 0;
                while (ret) {
                    if (counter >= 757) break;
                    s->array2[1 + counter] = 0;
                    counter++;
                    ret--;
                }
            } else {
                ret = 3 + _getbits(s, 2, &oob);
                if (oob) return 0;
                while (ret) {
                    if (counter >= 757) break;
                    s->array2[1 + counter] = s->array2[counter];
                    counter++;
                    ret--;
                }
            }
        } else {
            s->array2[1 + counter] = (s->decrypt_dict[counter] + ret) & 0xF;
            counter++;
        }
    }

    if (!_buildArray(s, &s->array2[1], 0) || !_buildArray(s, &s->array2[722], 1) || !_buildArray(s, &s->array2[750], 2)) return 0;

    s->dict_ok = 0;
    for (counter = 0; counter < 8; counter++) {
        if (s->array2[750 + counter] != 3) {
            s->dict_ok = 1;
            break;
        }
    }

    memcpy(s->decrypt_dict, &s->array2[1], 757);
    return 1;
}

int XASPACK::_decrypt(ASPK *s, const quint8 *stuff, quint32 size, quint8 *output)
{
    quint32 gen, backsize, backbytes, useold, counter = 0;
    quint32 hist[4] = {0, 0, 0, 0};
    int oob;

    while (counter < size) {
        gen = _getdec(s, 0, &oob);
        if (oob) return 0;
        if (gen < 256) {
            output[counter] = (quint8)gen;
            counter++;
            continue;
        }
        if (gen >= 720) {
            if (!_buildDicts(s)) return 0;
            continue;
        }
        backbytes = (gen - 256) >> 3;
        backsize = ((gen - 256) & 7) + 2;
        if ((backsize - 2) == 7) {
            quint8 hlp;
            gen = _getdec(s, 1, &oob);
            if (oob || gen >= 0x56) return 0;
            hlp = stuff[gen + 0x1c];
            if (!_readstream(s)) return 0;
            backsize += stuff[gen] + (((s->hash >> (8 - s->bitpos)) & 0xffffff) >> (0x18 - hlp));
            s->bitpos += hlp;
        }

        useold = s->init_array[backbytes];
        gen = stuff[backbytes + 0x38];

        if (!s->dict_ok || gen < 3) {
            if (!_readstream(s)) return 0;
            useold += ((s->hash >> (8 - s->bitpos)) & 0xffffff) >> (24 - gen);
            s->bitpos += gen;
        } else {
            gen -= 3;
            if (!_readstream(s)) return 0;
            useold += ((((s->hash >> (8 - s->bitpos)) & 0xffffff) >> (24 - gen)) * 8);
            s->bitpos += gen;
            useold += _getdec(s, 2, &oob);
            if (oob) return 0;
        }

        if (useold < 3) {
            backbytes = hist[useold];
            if (useold != 0) {
                hist[useold] = hist[0];
                hist[0] = backbytes;
            }
        } else {
            hist[2] = hist[1];
            hist[1] = hist[0];
            hist[0] = backbytes = useold - 3;
        }

        backbytes++;
        if (!backbytes || backbytes > counter || backsize > size - counter) return 0;
        while (backsize--) {
            output[counter] = output[counter - backbytes];
            counter++;
        }
    }

    return 1;
}

int XASPACK::_decompBlock(ASPK *s, quint32 size, const quint8 *stuff, quint8 *output)
{
    memset(s->decarray3, 0, sizeof(s->decarray3));
    memset(s->decarray4, 0, sizeof(s->decarray4));
    memset(s->decrypt_dict, 0, 757);
    s->bitpos = 0x20;
    if (!_buildDicts(s)) return 0;
    return _decrypt(s, stuff, size, output);
}

// carve the next per-dict starts[]/ends[] slice out of the 0x1800 work buffer;
// advances *ppWrkbuf past the slice
void XASPACK::_initDict(ASPK *s, quint8 **ppWrkbuf, int n, quint32 sz)
{
    quint8 *wrkbuf = *ppWrkbuf;
    s->dict_helper[n].starts = (quint32 *)wrkbuf;
    s->dict_helper[n].ends = &wrkbuf[sz * sizeof(quint32)];
    s->dict_helper[n].size = sz;
    *ppWrkbuf = &wrkbuf[sz * sizeof(quint32) + 0x100];
}

// ---------------------------------------------------------------------------
// multi-section PE rebuild (sections mapped by RVA, raw == rva)
// ---------------------------------------------------------------------------

QByteArray XASPACK::_buildPE(const QByteArray &baImage, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase,
                            quint32 nOEP, qint64 nOutputLimit)
{
    if (nSectCount <= 0) return QByteArray();

    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    quint32 nFirstRva = listSections.at(0).VirtualAddress;
    quint32 nRawBase = aspAlign(nHeaderBase + 0x28 * nSectCount, 0x200);
    const bool bGhost = (nFirstRva > aspAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = aspAlign(nHeaderBase + 0x28 * (nSectCount + 1), 0x200);
    }

    quint64 nRawTotal = nRawBase;
    quint32 nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += aspAlign(listSections.at(i).Misc.VirtualSize, 0x200);
        nMaxVEnd = qMax(nMaxVEnd, listSections.at(i).VirtualAddress + listSections.at(i).Misc.VirtualSize);
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
    _write_uint32(oh + 56, aspAlign(nMaxVEnd, 0x1000));
    _write_uint32(oh + 60, nRawBase);
    _write_uint16(oh + 68, 2);
    _write_uint32(oh + 92, 16);

    char *sec = oh + 0xE0;
    quint32 nRaw = nRawBase;

    if (bGhost) {
        memcpy(sec, ".ghost", 6);
        quint32 nGhostVA = aspAlign(nRawBase, 0x1000);
        _write_uint32(sec + 8, nFirstRva - nGhostVA);
        _write_uint32(sec + 12, nGhostVA);
        _write_uint32(sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    for (int i = 0; i < nSectCount; i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &s = listSections.at(i);
        quint32 nVsz = s.Misc.VirtualSize;
        quint32 nRsz = aspAlign(nVsz, 0x200);
        char szName[9];
        snprintf(szName, sizeof(szName), ".clam%.2d", i + 1);
        memcpy(sec, szName, qMin<size_t>(8, strlen(szName)));
        _write_uint32(sec + 8, nVsz);
        _write_uint32(sec + 12, s.VirtualAddress);
        _write_uint32(sec + 16, nRsz);
        _write_uint32(sec + 20, nRaw);
        _write_uint32(sec + 36, 0xE00000E0);

        if (((qint64)s.VirtualAddress + nVsz) <= baImage.size()) {
            memcpy(baResult.data() + nRaw, baImage.constData() + s.VirtualAddress, nVsz);
        }

        nRaw += nRsz;
        sec += 0x28;
    }

    return baResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XASPACK::INTERNAL_INFO XASPACK::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.version = AVER_NONE;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    qint64 nEpOffset = pe.relAddressToOffset(pe.getOptionalHeader_AddressOfEntryPoint());
    if (nEpOffset == -1) {
        return result;
    }

    QByteArray baEp = read_array_process(nEpOffset, 0x800, pPdStruct);
    if (baEp.size() < 0x3bf) {
        return result;
    }
    const char *ep = baEp.constData();
    const qint64 nEpSize = baEp.size();

    const char kMark[] = "\x68\x00\x00\x00\x00\xc3";
    for (const ASPACK_LAYOUT &layout : g_aspackLayouts) {
        if (nEpSize < layout.nSignatureSize) continue;
        if (memcmp(ep, layout.pszSignature, (size_t)layout.nSignatureSize) != 0) continue;
        if (nEpSize < (qint64)layout.nEpBuffOff + 6) continue;
        if (memcmp(ep + layout.nEpBuffOff, kMark, 6) != 0) continue;
        // The constant decoder table is stored (AddressOfEntryPoint - 1)-relative.
        const qint64 nCompBEpOff = (qint64)layout.nCompBOff - 1;
        if ((nCompBEpOff < 0) || (nEpSize < nCompBEpOff + (qint64)sizeof(g_aspackCompBTable))) continue;
        if (memcmp(ep + nCompBEpOff, g_aspackCompBTable, sizeof(g_aspackCompBTable)) != 0) continue;

        result.version = layout.version;
        result.sVersion = layout.pszVersion;
        result.bIsValid = true;
        return result;
    }

    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XASPACK::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XASPACK::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool {
        return !pPdStruct || isPdStructLifetimeAlive(progressLifetime);
    };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XASPACK> guardedThis(this);

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

    XASPACK worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !info.bIsValid) return false;
    QByteArray baData;
    const bool bUnpacked = worker._unpackToBuffer(baData, nOutputLimit, pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !bUnpacked || baData.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new UNPACK_CONTEXT);
    pContext->baData = baData;
    pContext->sFileName = sFileName;
    pContext->sInfo = QString("ASPack %1").arg(info.sVersion);
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

XBinary::ARCHIVERECORD XASPACK::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XASPACK> guardedThis(this);
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

bool XASPACK::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

    // A one-record materialized stream has no successor.  Failed movement is
    // non-mutating so callers can safely retry or finish the current state.
    return false;
}

bool XASPACK::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XASPACK::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XASPACK> guardedThis(this);
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

bool XASPACK::_unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    if (!isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    int nSectCount = listSections.size();
    if (nSectCount < 1) return false;

    const quint32 nImageBase = (quint32)pe.getOptionalHeader_ImageBase();
    const quint32 nEp = pe.getOptionalHeader_AddressOfEntryPoint() - 1;

    const ASPACK_LAYOUT *pLayout = aspackLayout(info.version);
    if (!pLayout) return false;
    const quint32 nBlocksOff = pLayout->nBlocksOff;
    const quint32 nStrMltOff = pLayout->nStrMltOff;
    const quint32 nCompBOff = pLayout->nCompBOff;
    const quint32 nWrkbufOff = pLayout->nWrkbufOff;
    const quint32 nOepOff = pLayout->nOepOff;
    const quint32 nBlockStride = pLayout->nBlockStride;

    quint32 nImageSize = 0;
    for (int i = 0; i < nSectCount; i++) {
        nImageSize = qMax(nImageSize, listSections.at(i).VirtualAddress + listSections.at(i).Misc.VirtualSize);
    }
    if (!nImageSize || (nImageSize > (256u * 1024 * 1024)) ||
        ((nOutputLimit >= 0) && ((quint64)nImageSize > (quint64)nOutputLimit))) return false;

    QByteArray baImage(nImageSize, (char)0);
    for (int i = 0; i < nSectCount; i++) {
        quint32 nRsz = listSections.at(i).SizeOfRawData;
        if (!nRsz) continue;
        quint32 nRva = listSections.at(i).VirtualAddress;
        if (((quint64)nRva + nRsz) > nImageSize) return false;
        QByteArray baSect = read_array_process(listSections.at(i).PointerToRawData, nRsz, pPdStruct);
        if ((quint32)baSect.size() != nRsz) return false;
        memcpy(baImage.data() + nRva, baSect.constData(), nRsz);
    }
    quint8 *image = (quint8 *)baImage.data();

    QByteArray baWrk(0x1800, (char)0);
    quint8 *wrkbuf = (quint8 *)baWrk.data();
    ASPK st;
    memset(&st, 0, sizeof(st));

    _initDict(&st, &wrkbuf, 0, 721);
    _initDict(&st, &wrkbuf, 1, 28);
    _initDict(&st, &wrkbuf, 2, 8);
    _initDict(&st, &wrkbuf, 3, 19);
    st.decrypt_dict = wrkbuf;

    st.hash = 0x10000;

    quint32 j = 0;
    for (quint32 i = 0; i < 58; i++) {
        st.init_array[i] = j;
        if (nEp + i + nStrMltOff < nImageSize) {
            j += (1u << image[nEp + i + nStrMltOff]);
        }
    }

    if (((quint64)nEp + nCompBOff + 0x72) > nImageSize) return false;
    const quint8 *stuff = image + nEp + nCompBOff;

    if (((quint64)nEp + nBlocksOff + 8) > nImageSize) return false;
    const quint8 *blocks = image + nEp + nBlocksOff;
    quint32 block_rva = 1, block_size = 0;
    bool bFiltered = false;

    while (((quint64)(blocks - image) + 8 <= nImageSize) && (block_rva = aspRd32(blocks)) && (block_size = aspRd32(blocks + 4)) &&
           (((quint64)block_rva + block_size) <= nImageSize)) {
        if (!isPdStructNotCanceled(pPdStruct)) return false;

        std::vector<quint8> inbuf((size_t)block_size + 0x10e, 0);
        memcpy(inbuf.data(), image + block_rva, block_size);
        st.input = inbuf.data();
        st.iend = inbuf.data() + block_size + 0x10e;

        if (!_decompBlock(&st, block_size, stuff, image + block_rva)) {
            return false;
        }

        if (!bFiltered && (block_size > 7)) {
            bFiltered = true;
            quint32 mark = image[nEp + nWrkbufOff];
            quint32 k = 0;
            while (k < block_size - 6) {
                quint8 cur = image[block_rva + k];
                if ((cur == 0xe8) || (cur == 0xe9)) {
                    quint8 *w = &image[block_rva + k + 1];
                    if (*w == mark) {
                        quint32 target = aspRd32(w) & 0xffffff00;
                        target = aspRol32(target, 0x18);
                        _write_uint32((char *)w, target - k);
                        k += 4;
                    }
                }
                k++;
            }
        }

        blocks += nBlockStride;
        if (nBlockStride != 8) {
            if ((quint64)(blocks - image) + 8 > nImageSize) break;
            block_size = aspRd32(blocks + 4);
            while ((block_size + 0x10e) == 0) {
                blocks += nBlockStride;
                if ((quint64)(blocks - image) + 8 > nImageSize) break;
                block_size = aspRd32(blocks + 4);
            }
        }
    }

    if (block_rva) {
        return false;
    }

    if ((nSectCount > 2) && (nEp == listSections.at(nSectCount - 2).VirtualAddress) && (!listSections.at(nSectCount - 1).SizeOfRawData)) {
        nSectCount -= 2;
    }

    if (((quint64)nEp + nOepOff + 4) > nImageSize) return false;
    quint32 nOEP = aspRd32(image + nEp + nOepOff);

    QByteArray baPE = _buildPE(baImage, listSections, nSectCount, nImageBase, nOEP, nOutputLimit);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}
