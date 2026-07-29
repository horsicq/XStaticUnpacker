/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xautoit.h"

#include <cstring>

static inline quint32 aiRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 aiBe32(const quint8 *p)
{
    return (quint32)(((quint32)p[0] << 24) | ((quint32)p[1] << 16) | ((quint32)p[2] << 8) | p[3]);
}

// MSB-first bit reader for the AutoIt custom inflate stream.
struct AI_BITREADER {
    const quint8 *pInput;
    quint32 nCsize;
    quint32 full;
    quint32 bits_avail;
    quint32 cur_input;
    bool error;
};

static quint32 aiGetBits(AI_BITREADER *br, quint32 sz)
{
    br->full &= 0x0000ffff;  // clear high half
    if ((sz > br->bits_avail) && (((sz - br->bits_avail - 1) / 16 + 1) * 2 > br->nCsize - br->cur_input)) {
        br->error = true;
        return 0;
    }
    while (sz) {
        if (!br->bits_avail) {
            if (br->cur_input + 2 > br->nCsize) {
                br->error = true;
                return (br->full >> 16) & 0xffff;
            }
            quint32 low = br->full & 0xffff;
            low |= (quint32)br->pInput[br->cur_input++] << 8;
            low |= br->pInput[br->cur_input++];
            br->full = (br->full & 0xffff0000) | (low & 0xffff);
            br->bits_avail = 16;
        }
        br->full <<= 1;
        br->bits_avail--;
        sz--;
    }
    return (br->full >> 16) & 0xffff;
}

XAUTOIT::XAUTOIT(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XAUTOIT::~XAUTOIT()
{
}

bool XAUTOIT::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XAUTOIT::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XAUTOIT a(pDevice);
    return a.isValid(pPdStruct);
}

XBinary::FT XAUTOIT::getFileType()
{
    return FT_ARCHIVE;
}

// ---------------------------------------------------------------------------
// MT stream cipher
// ---------------------------------------------------------------------------

void XAUTOIT::_mtDecrypt(quint8 *pBuf, quint32 nSize, quint32 nSeed)
{
    quint32 mt[624];
    mt[0] = nSeed;
    for (unsigned i = 1; i < 624; i++) {
        mt[i] = i + 0x6c078965 * ((mt[i - 1] >> 30) ^ mt[i - 1]);
    }
    quint32 items = 1;
    quint32 nextIdx = 0;

    while (nSize--) {
        if (!--items) {
            items = 624;
            nextIdx = 0;
            unsigned i;
            for (i = 0; i < 227; i++)
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0u - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i + 397];
            for (; i < 623; i++)
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0u - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i - 227];
            mt[623] = ((((mt[623] ^ mt[0]) & 0x7ffffffe) ^ mt[623]) >> 1) ^ ((0u - (mt[0] & 1)) & 0x9908b0df) ^ mt[i - 227];
        }
        quint32 r = mt[nextIdx++];
        r ^= (r >> 11);
        r ^= ((r & 0xff3a58ad) << 7);
        r ^= ((r & 0xffffdf8c) << 15);
        r ^= (r >> 18);
        *pBuf++ ^= (quint8)(r >> 1);
    }
}

// ---------------------------------------------------------------------------
// custom inflate
// ---------------------------------------------------------------------------

bool XAUTOIT::_inflate(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize)
{
    quint32 cur_output = 0;

    AI_BITREADER br;
    br.pInput = pInput;
    br.nCsize = nCsize;
    br.full = 0;
    br.bits_avail = 0;
    br.cur_input = 8;
    br.error = false;

    while (!br.error && (cur_output < nUsize)) {
        if (aiGetBits(&br, 1)) {
            quint32 bb = aiGetBits(&br, 15);
            quint32 bs, addme = 0;
            if ((bs = aiGetBits(&br, 2)) == 3) {
                addme = 3;
                if ((bs = aiGetBits(&br, 3)) == 7) {
                    addme = 10;
                    if ((bs = aiGetBits(&br, 5)) == 31) {
                        addme = 41;
                        if ((bs = aiGetBits(&br, 8)) == 255) {
                            addme = 296;
                            while ((bs = aiGetBits(&br, 8)) == 255) addme += 255;
                        }
                    }
                }
            }
            bs += 3 + addme;
            if (br.error) break;
            if ((bb == 0) || (bb > cur_output) || ((quint64)cur_output + bs > nUsize)) {
                br.error = true;
                break;
            }
            while (bs--) {
                pOutput[cur_output] = pOutput[cur_output - bb];
                cur_output++;
            }
        } else {
            if (cur_output >= nUsize) break;
            pOutput[cur_output++] = (quint8)aiGetBits(&br, 8);
        }
    }

    // partial output is acceptable (matches reference behaviour)
    return (cur_output > 0);
}

// ---------------------------------------------------------------------------
// unicode -> ascii (for names)
// ---------------------------------------------------------------------------

quint32 XAUTOIT::_u2a(quint8 *pDest, quint32 nLen)
{
    quint8 *src = pDest;
    quint32 i, j;

    if (nLen < 2) return nLen;

    if ((nLen > 4) && (src[0] == 0xff) && (src[1] == 0xfe) && src[2]) {
        nLen -= 2;
        src += 2;
    } else {
        quint32 cnt = 0;
        j = (nLen > 20) ? 20 : (nLen & ~1u);
        for (i = 0; i < j; i += 2) cnt += (src[i] != 0 && src[i + 1] == 0);
        if (cnt * 4 < j) return nLen;
    }

    j = nLen;
    nLen >>= 1;
    for (i = 0; i < j; i += 2) *pDest++ = src[i];
    return nLen;
}

// ---------------------------------------------------------------------------
// EA05 record parser
// ---------------------------------------------------------------------------

QList<XAUTOIT::RECORD> XAUTOIT::_parseEA05(const quint8 *pData, qint64 nSize, qint64 nBase, PDSTRUCT *pPdStruct)
{
    QList<RECORD> listResult;

    if (nBase + 16 > nSize) return listResult;

    quint32 m4sum = 0;
    for (int i = 0; i < 16; i++) m4sum += pData[nBase + i];
    nBase += 16;

    while (isPdStructNotCanceled(pPdStruct)) {
        if (nBase + 8 > nSize) break;
        if (aiRd32(pData + nBase) != 0xceb06dff) break;  // FILE magic

        quint32 s1 = aiRd32(pData + nBase + 4) ^ 0x29bc;
        if ((qint32)s1 < 0) break;
        nBase += 8;
        if (nBase + s1 > nSize) break;
        nBase += s1;  // skip magic string

        if (nBase + 4 > nSize) break;
        quint32 s2 = aiRd32(pData + nBase) ^ 0x29ac;
        if ((qint32)s2 < 0) break;
        nBase += 4;
        if (nBase + s2 > nSize) break;

        QByteArray baName((const char *)(pData + nBase), (int)s2);
        _mtDecrypt((quint8 *)baName.data(), s2, s2 + 0xf25e);
        quint32 nNameLen = _u2a((quint8 *)baName.data(), s2);
        baName.resize((int)nNameLen);
        nBase += s2;

        if (nBase + 13 > nSize) break;
        quint8 comp = pData[nBase];
        quint32 csize = aiRd32(pData + nBase + 1) ^ 0x45aa;
        if ((qint32)csize < 0) break;

        if (!csize) {
            nBase += 13 + 16;
            continue;
        }
        nBase += 13 + 16;
        if (nBase + csize > nSize) break;

        QByteArray baInput((const char *)(pData + nBase), (int)csize);
        nBase += csize;
        _mtDecrypt((quint8 *)baInput.data(), csize, 0x22af + m4sum);

        QByteArray baOutput;
        if (comp == 1) {
            if (csize < 8) continue;
            if (aiRd32((const quint8 *)baInput.constData()) != 0x35304145) continue;  // "EA05"
            quint32 usize = aiBe32((const quint8 *)baInput.constData() + 4);
            if (!usize) usize = csize;
            if (usize > (256u * 1024 * 1024)) continue;
            baOutput.resize((int)usize);
            memset(baOutput.data(), 0, usize);
            if (!_inflate((const quint8 *)baInput.constData(), csize, (quint8 *)baOutput.data(), usize)) {
                continue;
            }
        } else {
            baOutput = baInput;
        }

        if (baOutput.size() < 4) continue;

        RECORD rec;
        rec.sName = QString::fromLatin1(baName.constData(), baName.size());
        if (rec.sName.isEmpty()) {
            rec.sName = QString("autoit_%1").arg(listResult.size(), 3, 10, QChar('0'));
        }
        rec.baData = baOutput;
        listResult.append(rec);

        if (listResult.size() > 100000) break;
    }

    return listResult;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XAUTOIT::INTERNAL_INFO XAUTOIT::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nMarkerOffset = -1;

    qint64 nSize = getSize();
    if (nSize < 24) return result;

    qint64 nOff = find_ansiString(0, nSize, "AU3!EA05", pPdStruct);
    if (nOff != -1) {
        result.bIsValid = true;
        result.nVersion = 5;
        result.sVersion = "EA05";
        result.nMarkerOffset = nOff;
        return result;
    }

    nOff = find_ansiString(0, nSize, "AU3!EA06", pPdStruct);
    if (nOff != -1) {
        result.bIsValid = true;
        result.nVersion = 6;
        result.sVersion = "EA06 (unsupported)";
        result.nMarkerOffset = nOff;
        return result;
    }

    return result;
}

XAUTOIT::INTERNAL_INFO XAUTOIT::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XAUTOIT::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(true);
        m_internalInfo = _getInternalInfo(pPdStruct);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XAUTOIT::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XAUTOIT::setInternalInfo(void *pInternalInfo)
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

QMap<XBinary::UNPACK_PROP, QVariant> XAUTOIT::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XAUTOIT::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;

    if (info.nVersion == 5) {
        QByteArray baFile = read_array_process(0, getSize(), pPdStruct);
        if (baFile.size() == getSize()) {
            // base = right after the "AU3!EA05" marker
            pContext->listRecords = _parseEA05((const quint8 *)baFile.constData(), baFile.size(), info.nMarkerOffset + 8, pPdStruct);
        }
    }
    // EA06: detected but not extracted (empty record list)

    pState->pContext = pContext;
    pState->nNumberOfRecords = pContext->listRecords.size();

    return true;
}

XBinary::ARCHIVERECORD XAUTOIT::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return result;

    const RECORD &rec = pContext->listRecords.at(nIndex);
    result.nStreamOffset = 0;
    result.nStreamSize = rec.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = rec.sName.isEmpty() ? QString("autoit_%1").arg(nIndex, 3, 10, QChar('0')) : rec.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)rec.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;

    return result;
}

bool XAUTOIT::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext || !pDevice) return false;

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return false;

    const QByteArray &baData = pContext->listRecords.at(nIndex).baData;
    return (pDevice->write(baData) == baData.size());
}

bool XAUTOIT::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState || !pState->pContext) return false;

    pState->nCurrentIndex++;
    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XAUTOIT::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) return false;

    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
        pContext->listRecords.clear();
        delete pContext;
        pState->pContext = nullptr;
    }

    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;

    return true;
}
