/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xaspack.h"

#include <cstring>
#include <vector>

// version-specific stub offsets
#define ASP_BLOCKS_212 0x57c
#define ASP_BLOCKS_OTHER 0x5d8
#define ASP_BLOCKS_242 0x5e4
#define ASP_STRMLT_212 0x70e
#define ASP_STRMLT_OTHER 0x76a
#define ASP_STRMLT_242 0x776
#define ASP_COMPB_212 0x6d6
#define ASP_COMPB_OTHER 0x732
#define ASP_COMPB_242 0x73e
#define ASP_WRKBUF_212 0x148
#define ASP_WRKBUF_OTHER 0x13a
#define ASP_WRKBUF_242 0x148
#define ASP_OEP_212 0x39b
#define ASP_OEP_OTHER 0x401
#define ASP_OEP_242 0x40d
#define ASP_EPBUFF_212 0x3b9
#define ASP_EPBUFF_OTHER 0x41f
#define ASP_EPBUFF_242 0x42b

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
    setIsArchive(true);
}

XASPACK::~XASPACK()
{
}

bool XASPACK::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XASPACK::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XASPACK a(pDevice);
    return a.isValid(pPdStruct);
}

XBinary::FT XASPACK::getFileType()
{
    return FT_BINARY;
}

QString XASPACK::getVersion()
{
    INTERNAL_INFO info = *static_cast<INTERNAL_INFO *>(getInternalInfo());
    return info.bIsValid ? info.sVersion : QString();
}

XASPACK::INTERNAL_INFO XASPACK::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XASPACK::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = _getInternalInfo(pPdStruct);
        setIsInternalInfoHandled(true);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XASPACK::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
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

QByteArray XASPACK::_buildPE(const QByteArray &baImage, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase, quint32 nOEP)
{
    if (nSectCount <= 0) return QByteArray();

    const quint32 nHeaderBase = 0x40 + 4 + 20 + 0xE0;
    quint32 nFirstRva = listSections.at(0).VirtualAddress;
    quint32 nRawBase = aspAlign(nHeaderBase + 0x28 * nSectCount, 0x200);
    const bool bGhost = (nFirstRva > aspAlign(nRawBase, 0x1000));
    if (bGhost) {
        nRawBase = aspAlign(nHeaderBase + 0x28 * (nSectCount + 1), 0x200);
    }

    quint32 nRawTotal = nRawBase;
    quint32 nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += aspAlign(listSections.at(i).Misc.VirtualSize, 0x200);
        nMaxVEnd = qMax(nMaxVEnd, listSections.at(i).VirtualAddress + listSections.at(i).Misc.VirtualSize);
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

    QByteArray baEp = read_array_process(nEpOffset, 0x480, pPdStruct);
    if (baEp.size() < 0x3bf) {
        return result;
    }
    const char *ep = baEp.constData();

    if (memcmp(ep, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8) != 0) {
        return result;
    }

    const char kMark[] = "\x68\x00\x00\x00\x00\xc3";
    if ((baEp.size() >= ASP_EPBUFF_212 + 6) && (memcmp(ep + ASP_EPBUFF_212, kMark, 6) == 0)) {
        result.version = AVER_212;
        result.sVersion = "2.12";
    } else if ((baEp.size() >= ASP_EPBUFF_OTHER + 6) && (memcmp(ep + ASP_EPBUFF_OTHER, kMark, 6) == 0)) {
        result.version = AVER_OTHER;
        result.sVersion = "2.xx";
    } else if ((baEp.size() >= ASP_EPBUFF_242 + 6) && (memcmp(ep + ASP_EPBUFF_242, kMark, 6) == 0)) {
        result.version = AVER_242;
        result.sVersion = "2.42";
    } else {
        return result;
    }

    result.bIsValid = true;
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

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) {
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

XBinary::ARCHIVERECORD XASPACK::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
    result.mapProperties.insert(FPART_PROP_INFO, QString("ASPack %1").arg(getVersion()));

    return result;
}

bool XASPACK::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if ((!pState) || (!pState->pContext) || !isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XASPACK::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XASPACK::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
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

bool XASPACK::_unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct)
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

    quint32 nBlocksOff, nStrMltOff, nCompBOff, nWrkbufOff, nOepOff;
    switch (info.version) {
        case AVER_212: nBlocksOff = ASP_BLOCKS_212; nStrMltOff = ASP_STRMLT_212; nCompBOff = ASP_COMPB_212; nWrkbufOff = ASP_WRKBUF_212; nOepOff = ASP_OEP_212; break;
        case AVER_242: nBlocksOff = ASP_BLOCKS_242; nStrMltOff = ASP_STRMLT_242; nCompBOff = ASP_COMPB_242; nWrkbufOff = ASP_WRKBUF_242; nOepOff = ASP_OEP_242; break;
        default: nBlocksOff = ASP_BLOCKS_OTHER; nStrMltOff = ASP_STRMLT_OTHER; nCompBOff = ASP_COMPB_OTHER; nWrkbufOff = ASP_WRKBUF_OTHER; nOepOff = ASP_OEP_OTHER; break;
    }

    quint32 nImageSize = 0;
    for (int i = 0; i < nSectCount; i++) {
        nImageSize = qMax(nImageSize, listSections.at(i).VirtualAddress + listSections.at(i).Misc.VirtualSize);
    }
    if (!nImageSize || (nImageSize > (256u * 1024 * 1024))) return false;

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

        if (info.version == AVER_212) {
            blocks += 8;
        } else {
            blocks += 12;
            if ((quint64)(blocks - image) + 8 > nImageSize) break;
            block_size = aspRd32(blocks + 4);
            while ((block_size + 0x10e) == 0) {
                blocks += 12;
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

    QByteArray baPE = _buildPE(baImage, listSections, nSectCount, nImageBase, nOEP);
    if (baPE.isEmpty()) return false;

    baOut = baPE;

    return true;
}
