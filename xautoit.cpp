/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xautoit.h"
#include "xmaterializedunpackguard.h"
#include "xpe.h"

#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QUuid>

#include <climits>
#include <cstring>
#include <limits>
#include <new>

namespace {

const qint64 AI_RECORD_ACCOUNTING_OVERHEAD = 128;
const quint8 AI_V2_SIGNATURE[16] = {
    0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9,
    0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d,
};
const quint32 AI_V2_MAX_METADATA_SIZE = 1024 * 1024;

static QString aiUtf16LeString(const QByteArray &baData, quint32 nChars)
{
    if ((quint64)nChars * 2 != (quint64)baData.size()) return QString();
    QString result;
    result.reserve((int)nChars);
    const quint8 *pData = reinterpret_cast<const quint8 *>(baData.constData());
    for (quint32 i = 0; i < nChars; i++) {
        const quint16 nValue = (quint16)(pData[i * 2] | ((quint16)pData[i * 2 + 1] << 8));
        if (!nValue) break;
        result.append(QChar(nValue));
    }
    return result;
}

static QString aiSafeRecordName(QString sName)
{
    sName.replace(QLatin1Char('\\'), QLatin1Char('/'));
    while (sName.endsWith(QLatin1Char('/'))) sName.chop(1);
    const int nSlash = sName.lastIndexOf(QLatin1Char('/'));
    if (nSlash >= 0) sName = sName.mid(nSlash + 1);
    if ((sName == QStringLiteral(".")) || (sName == QStringLiteral(".."))) sName.clear();
    return sName;
}

static bool aiReserveRecord(XBinary::UNPACK_MEMORY_RESERVATION *pReservation, qint64 nDataSize, const QString &sName)
{
    if (!pReservation || !pReservation->isActive() || (nDataSize < 0)) return false;
    const quint64 nExtra = (quint64)nDataSize + (quint64)sName.size() * 2 + AI_RECORD_ACCOUNTING_OVERHEAD;
    if ((nExtra > (quint64)(std::numeric_limits<qint64>::max)()) ||
        ((quint64)pReservation->size() + nExtra > (quint64)(std::numeric_limits<qint64>::max)())) return false;
    return pReservation->resize(pReservation->size() + (qint64)nExtra);
}

}  // namespace

static inline quint32 aiRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}

static inline quint32 aiBe32(const quint8 *p)
{
    return (quint32)(((quint32)p[0] << 24) | ((quint32)p[1] << 16) | ((quint32)p[2] << 8) | p[3]);
}

struct AI_LAME_STATE {
    quint32 nIndex0;
    quint32 nIndex1;
    quint32 values[17];
};

static inline quint32 aiRotl32(quint32 nValue, quint32 nBits)
{
    return (nValue << nBits) | (nValue >> (32 - nBits));
}

// EA06 constructs a number in [1, 2) by writing the generated 32 bits into
// an IEEE-754 binary64 mantissa, then subtracts one.  Constructing the bit
// pattern explicitly avoids any dependency on x87 long-double precision.
static double aiLamePush(AI_LAME_STATE *pState)
{
    const quint32 nRolled = aiRotl32(pState->values[pState->nIndex0], 9) +
                                    aiRotl32(pState->values[pState->nIndex1], 13);
    pState->values[pState->nIndex0] = nRolled;
    if (pState->nIndex0 == 0) pState->nIndex0 = 16;
    else --pState->nIndex0;
    if (pState->nIndex1 == 0) pState->nIndex1 = 16;
    else --pState->nIndex1;

    const quint64 nBits = (static_cast<quint64>(0x3ff00000U | (nRolled >> 12)) << 32) |
                          (static_cast<quint64>(nRolled) << 20);
    double dValue = 0.0;
    static_assert(sizeof(dValue) == sizeof(nBits), "EA06 requires IEEE-754 binary64");
    memcpy(&dValue, &nBits, sizeof(dValue));
    return dValue - 1.0;
}

static void aiLameInit(AI_LAME_STATE *pState, quint32 nSeed)
{
    for (quint32 i = 0; i < 17; ++i) {
        nSeed *= 0x53A9B4FBU;
        nSeed = 1U - nSeed;
        pState->values[i] = nSeed;
    }
    pState->nIndex0 = 0;
    pState->nIndex1 = 10;
    for (quint32 i = 0; i < 9; ++i) aiLamePush(pState);
}

static quint8 aiLameNext(AI_LAME_STATE *pState)
{
    aiLamePush(pState);
    const double dValue = aiLamePush(pState) * 256.0;
    const qint32 nValue = static_cast<qint32>(dValue);
    return (nValue < 256) ? static_cast<quint8>(nValue) : 0xff;
}

static void aiLameDecrypt(quint8 *pData, quint32 nSize, quint16 nSeed)
{
    AI_LAME_STATE state = {};
    aiLameInit(&state, nSeed);
    while (nSize--) *pData++ ^= aiLameNext(&state);
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
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XAUTOIT::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XAUTOIT::~XAUTOIT()
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

XAUTOIT::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XAUTOIT::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive &&
           !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XAUTOIT::isValid(PDSTRUCT *pPdStruct)
{
    QPointer<XAUTOIT> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XAUTOIT::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XAUTOIT a(pDevice);
    return a.isValid(pPdStruct);
}

XBinary::FT XAUTOIT::getFileType()
{
    XPE pe(getDevice());

    if (pe.isValid() && pe.is64()) {
        return FT_PE64_AUTOIT;
    }

    return FT_PE32_AUTOIT;
}

QString XAUTOIT::getVersion()
{
    QPointer<XAUTOIT> guardedThis(this);
    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo());
    return (guardedThis && pInfo && pInfo->bIsValid) ? pInfo->sVersion : QString();
}

// ---------------------------------------------------------------------------
// AutoIt v2 linear-congruential stream cipher
// ---------------------------------------------------------------------------

void XAUTOIT::_v2Decrypt(quint8 *pBuf, quint32 nSize, quint32 nSeed)
{
    while (nSize--) {
        nSeed = nSeed * 214013U + 2531011U;
        *pBuf++ ^= static_cast<quint8>(nSeed >> 16);
    }
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

bool XAUTOIT::_inflate(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize, bool bEA06,
                       quint32 *pActualSize)
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
        bool bCopy = aiGetBits(&br, 1) != 0;
        if (bEA06) bCopy = !bCopy;
        if (bCopy) {
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

    if (pActualSize) *pActualSize = cur_output;
    // A declared EA05/EA06 output size is authoritative. Publishing a prefix
    // from a truncated bitstream would turn corruption into a successful file.
    return !br.error && (cur_output == nUsize);
}

bool XAUTOIT::_inflateV2(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize)
{
    if (!pInput || (nCsize < 8) || (memcmp(pInput, "JB01", 4) != 0) ||
        (aiBe32(pInput + 4) != nUsize) || (nUsize && !pOutput)) return false;

    AI_BITREADER br = {};
    br.pInput = pInput;
    br.nCsize = nCsize;
    br.cur_input = 8;

    quint32 nOutput = 0;
    while (!br.error && (nOutput < nUsize)) {
        const bool bMatch = aiGetBits(&br, 1) != 0;
        if (!bMatch) {
            pOutput[nOutput++] = static_cast<quint8>(aiGetBits(&br, 8));
            continue;
        }

        const quint32 nDistance = aiGetBits(&br, 13) + 3;
        const quint32 nLength = aiGetBits(&br, 4) + 3;
        if (br.error || (nDistance > nOutput) ||
            (static_cast<quint64>(nOutput) + nLength > nUsize)) return false;
        for (quint32 i = 0; i < nLength; ++i) {
            pOutput[nOutput] = pOutput[nOutput - nDistance];
            ++nOutput;
        }
    }

    return !br.error && (nOutput == nUsize);
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
// AutoIt v2 record parser
// ---------------------------------------------------------------------------

QList<XAUTOIT::RECORD> XAUTOIT::_parseV2(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                                         const QMap<UNPACK_PROP, QVariant> &mapProperties,
                                         UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct)
{
    QList<RECORD> listResult;
    if (!pData || !pRecordReservation || !pRecordReservation->isActive() ||
        (nSize < 25) || (nBase < 0) || (nBase > nSize - 25) ||
        (memcmp(pData + nBase, AI_V2_SIGNATURE, sizeof(AI_V2_SIGNATURE)) != 0) ||
        (aiRd32(pData + nSize - 4) != static_cast<quint32>(nBase))) return listResult;

    const qint64 nTrailer = nSize - 4;
    nBase += sizeof(AI_V2_SIGNATURE);
    if ((pData[nBase++] != 1) || (nBase > nTrailer - 4)) return listResult;

    const quint32 nPasswordSize = aiRd32(pData + nBase) ^ 0xfac1U;
    nBase += 4;
    if ((nPasswordSize > AI_V2_MAX_METADATA_SIZE) ||
        (static_cast<quint64>(nPasswordSize) > static_cast<quint64>(nTrailer - nBase))) return listResult;
    UNPACK_MEMORY_RESERVATION passwordReservation;
    if (!passwordReservation.acquire(mapProperties, nPasswordSize)) return listResult;
    QByteArray baPassword(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nPasswordSize));
    if (nPasswordSize) {
        _v2Decrypt(reinterpret_cast<quint8 *>(baPassword.data()), nPasswordSize, 0xc3d2U + nPasswordSize);
    }
    nBase += nPasswordSize;

    qint64 nPasswordSum = 0;
    for (char cValue : baPassword) nPasswordSum += static_cast<qint8>(cValue);
    const quint32 nDataSeed = static_cast<quint32>(nPasswordSum + 0x22af);

    const auto contains = [nTrailer](qint64 nOffset, quint64 nLength) -> bool {
        return (nOffset >= 0) && (nOffset <= nTrailer) &&
               (nLength <= static_cast<quint64>(nTrailer - nOffset));
    };

    while (isPdStructNotCanceled(pPdStruct) && (nBase < nTrailer)) {
        if (!contains(nBase, 4)) return QList<RECORD>();
        quint8 marker[4];
        memcpy(marker, pData + nBase, sizeof(marker));
        _v2Decrypt(marker, sizeof(marker), 0x16faU);
        if (memcmp(marker, "FILE", sizeof(marker)) != 0) return QList<RECORD>();
        nBase += 4;

        if (!contains(nBase, 4)) return QList<RECORD>();
        const quint32 nSourceSize = aiRd32(pData + nBase) ^ 0x29bcU;
        nBase += 4;
        if ((nSourceSize > AI_V2_MAX_METADATA_SIZE) || !contains(nBase, nSourceSize)) return QList<RECORD>();
        UNPACK_MEMORY_RESERVATION metadataReservation;
        if (!metadataReservation.acquire(mapProperties, static_cast<qint64>(nSourceSize) * 2)) return QList<RECORD>();
        QByteArray baSource(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nSourceSize));
        if (nSourceSize) {
            _v2Decrypt(reinterpret_cast<quint8 *>(baSource.data()), nSourceSize, 0xa25eU + nSourceSize);
        }
        nBase += nSourceSize;

        if (!contains(nBase, 4)) return QList<RECORD>();
        const quint32 nNameSize = aiRd32(pData + nBase) ^ 0x29acU;
        nBase += 4;
        if ((nNameSize > AI_V2_MAX_METADATA_SIZE) || !contains(nBase, nNameSize)) return QList<RECORD>();
        if (!metadataReservation.resize(static_cast<qint64>(nSourceSize + nNameSize) * 2)) return QList<RECORD>();
        QByteArray baName(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nNameSize));
        if (nNameSize) {
            _v2Decrypt(reinterpret_cast<quint8 *>(baName.data()), nNameSize, 0xf25eU + nNameSize);
        }
        nBase += nNameSize;

        if (!contains(nBase, 9)) return QList<RECORD>();
        const quint8 nCompression = pData[nBase++];
        const quint32 nCompressedSize = aiRd32(pData + nBase) ^ 0x45aaU;
        nBase += 4;
        const quint32 nUncompressedSize = aiRd32(pData + nBase) ^ 0x45aaU;
        nBase += 4;
        if (((nCompression != 0) && (nCompression != 1)) ||
            (nCompressedSize > static_cast<quint32>(INT_MAX)) ||
            (nUncompressedSize > 256U * 1024U * 1024U) ||
            !contains(nBase, nCompressedSize)) return QList<RECORD>();

        if ((nOutputLimit >= 0) &&
            (static_cast<quint64>(nUncompressedSize) > static_cast<quint64>(nOutputLimit))) {
            nBase += nCompressedSize;
            continue;
        }

        UNPACK_MEMORY_RESERVATION decodeReservation;
        if (!decodeReservation.acquire(mapProperties, nCompressedSize)) return QList<RECORD>();
        QByteArray baInput(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nCompressedSize));
        if (nCompressedSize) {
            _v2Decrypt(reinterpret_cast<quint8 *>(baInput.data()), nCompressedSize, nDataSeed);
        }
        nBase += nCompressedSize;

        QByteArray baOutput;
        if (nCompression == 1) {
            if ((static_cast<quint64>(nCompressedSize) + nUncompressedSize >
                 static_cast<quint64>((std::numeric_limits<qint64>::max)())) ||
                !decodeReservation.resize(static_cast<qint64>(nCompressedSize) + nUncompressedSize)) {
                return QList<RECORD>();
            }
            baOutput.resize(static_cast<int>(nUncompressedSize));
            if (!_inflateV2(reinterpret_cast<const quint8 *>(baInput.constData()), nCompressedSize,
                            reinterpret_cast<quint8 *>(baOutput.data()), nUncompressedSize)) {
                return QList<RECORD>();
            }
        } else {
            if (nCompressedSize != nUncompressedSize) return QList<RECORD>();
            baOutput = baInput;
        }

        const QString sSource = QString::fromLatin1(baSource.constData(), baSource.size());
        const QString sBuildName = QString::fromLatin1(baName.constData(), baName.size());
        RECORD record;
        record.sName = sSource.contains(QStringLiteral("AUTOIT SCRIPT"), Qt::CaseInsensitive)
                           ? QStringLiteral("autoit_script.aut")
                           : aiSafeRecordName(sSource);
        if (record.sName.isEmpty()) record.sName = aiSafeRecordName(sBuildName);
        if (record.sName.isEmpty()) {
            record.sName = QStringLiteral("autoit_%1.bin").arg(listResult.size(), 3, 10, QChar('0'));
        }
        if ((listResult.size() >= 100000) ||
            !aiReserveRecord(pRecordReservation, baOutput.size(), record.sName)) return QList<RECORD>();
        record.baData = baOutput;
        listResult.append(record);
    }

    if (!isPdStructNotCanceled(pPdStruct) || (nBase != nTrailer)) return QList<RECORD>();
    return listResult;
}

// ---------------------------------------------------------------------------
// EA05 record parser
// ---------------------------------------------------------------------------

QList<XAUTOIT::RECORD> XAUTOIT::_parseEA05(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                                          const QMap<UNPACK_PROP, QVariant> &mapProperties,
                                          UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct)
{
    QList<RECORD> listResult;

    if (!pData || !pRecordReservation || !pRecordReservation->isActive() || (nBase < 0) || (nBase > nSize - 16)) return listResult;

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

        UNPACK_MEMORY_RESERVATION metadataReservation;
        if (!metadataReservation.acquire(mapProperties, (qint64)s2 * 2)) return QList<RECORD>();
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
        if ((comp != 1) && (nOutputLimit >= 0) && ((quint64)csize > (quint64)nOutputLimit)) {
            nBase += csize;
            continue;
        }

        UNPACK_MEMORY_RESERVATION decodeReservation;
        if (!decodeReservation.acquire(mapProperties, csize)) return QList<RECORD>();
        QByteArray baInput((const char *)(pData + nBase), (int)csize);
        nBase += csize;
        _mtDecrypt((quint8 *)baInput.data(), csize, 0x22af + m4sum);

        QByteArray baOutput;
        if (comp == 1) {
            if (csize < 8) continue;
            if (aiRd32((const quint8 *)baInput.constData()) != 0x35304145) continue;  // "EA05"
            quint32 usize = aiBe32((const quint8 *)baInput.constData() + 4);
            if (!usize) usize = csize;
            if ((usize > (256u * 1024 * 1024)) ||
                ((nOutputLimit >= 0) && ((quint64)usize > (quint64)nOutputLimit))) continue;
            if ((quint64)csize + usize > (quint64)(std::numeric_limits<qint64>::max)() ||
                !decodeReservation.resize((qint64)csize + usize)) return QList<RECORD>();
            baOutput.resize((int)usize);
            memset(baOutput.data(), 0, usize);
            quint32 nActualSize = 0;
            if (!_inflate((const quint8 *)baInput.constData(), csize, (quint8 *)baOutput.data(), usize, false, &nActualSize)) {
                continue;
            }
            baOutput.resize(static_cast<int>(nActualSize));
        } else {
            baOutput = baInput;
        }

        if (baOutput.size() < 4) continue;

        RECORD rec;
        rec.sName = aiSafeRecordName(QString::fromLatin1(baName.constData(), baName.size()));
        if (rec.sName.isEmpty()) {
            rec.sName = QString("autoit_%1").arg(listResult.size(), 3, 10, QChar('0'));
        }
        if ((listResult.size() >= 100000) || !aiReserveRecord(pRecordReservation, baOutput.size(), rec.sName)) return QList<RECORD>();
        rec.baData = baOutput;
        listResult.append(rec);
    }

    return listResult;
}

// ---------------------------------------------------------------------------
// EA06 record parser
// ---------------------------------------------------------------------------

QList<XAUTOIT::RECORD> XAUTOIT::_parseEA06(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                                          const QMap<UNPACK_PROP, QVariant> &mapProperties,
                                          UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct)
{
    QList<RECORD> listResult;
    if (!pData || !pRecordReservation || !pRecordReservation->isActive() ||
        (nSize < 0) || (nBase < 0) || (nBase > nSize - 16)) return listResult;
    nBase += 16;  // header bytes whose checksum is unusable in the original format

    const auto contains = [nSize](qint64 nOffset, quint64 nLength) -> bool {
        return (nOffset >= 0) && (nOffset <= nSize) &&
               (nLength <= static_cast<quint64>(nSize - nOffset));
    };

    while (isPdStructNotCanceled(pPdStruct)) {
        if (!contains(nBase, 4)) break;
        if (aiRd32(pData + nBase) != 0x52ca436bU) break;
        if (!contains(nBase, 8)) return QList<RECORD>();

        const quint32 nMagicChars = aiRd32(pData + nBase + 4) ^ 0xadbcU;
        if ((nMagicChars > 0x10000U) || (nMagicChars > (UINT_MAX / 2U))) return QList<RECORD>();
        const quint32 nMagicBytes = nMagicChars * 2U;
        nBase += 8;
        if (!contains(nBase, nMagicBytes)) return QList<RECORD>();
        UNPACK_MEMORY_RESERVATION metadataReservation;
        if (!metadataReservation.acquire(mapProperties, (qint64)nMagicBytes * 2)) return QList<RECORD>();
        QByteArray baMagic(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nMagicBytes));
        aiLameDecrypt(reinterpret_cast<quint8 *>(baMagic.data()), nMagicBytes,
                      static_cast<quint16>(nMagicChars + 0xb33fU));
        const QString sMagic = aiUtf16LeString(baMagic, nMagicChars);
        const bool bScript = (sMagic == QStringLiteral(">>>AUTOIT SCRIPT<<<"));
        nBase += nMagicBytes;

        if (!contains(nBase, 4)) return QList<RECORD>();
        const quint32 nNameChars = aiRd32(pData + nBase) ^ 0xf820U;
        if ((nNameChars > 0x10000U) || (nNameChars > (UINT_MAX / 2U))) return QList<RECORD>();
        const quint32 nNameBytes = nNameChars * 2U;
        nBase += 4;
        if (!contains(nBase, nNameBytes)) return QList<RECORD>();
        if (!metadataReservation.resize((qint64)(nMagicBytes + nNameBytes) * 2)) return QList<RECORD>();
        QByteArray baName(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nNameBytes));
        aiLameDecrypt(reinterpret_cast<quint8 *>(baName.data()), nNameBytes,
                      static_cast<quint16>(nNameChars + 0xf479U));
        const QString sBuildName = aiUtf16LeString(baName, nNameChars);
        nBase += nNameBytes;

        if (!contains(nBase, 13)) return QList<RECORD>();
        const quint8 nCompression = pData[nBase];
        const quint32 nCompressedSize = aiRd32(pData + nBase + 1) ^ 0x87bcU;
        if ((nCompression != 0) && (nCompression != 1)) return QList<RECORD>();
        nBase += 13;
        if (!contains(nBase, 16)) return QList<RECORD>();
        nBase += 16;
        if (!nCompressedSize) continue;
        if ((nCompressedSize > (quint32)INT_MAX) || !contains(nBase, nCompressedSize)) return QList<RECORD>();
        if ((nCompression != 1) && (nOutputLimit >= 0) &&
            (static_cast<quint64>(nCompressedSize) > static_cast<quint64>(nOutputLimit))) {
            nBase += nCompressedSize;
            continue;
        }

        UNPACK_MEMORY_RESERVATION decodeReservation;
        if (!decodeReservation.acquire(mapProperties, nCompressedSize)) return QList<RECORD>();
        QByteArray baInput(reinterpret_cast<const char *>(pData + nBase), static_cast<int>(nCompressedSize));
        nBase += nCompressedSize;
        aiLameDecrypt(reinterpret_cast<quint8 *>(baInput.data()), nCompressedSize, 0x2477U);

        QByteArray baOutput;
        if (nCompression == 1) {
            if ((nCompressedSize < 8) ||
                (aiRd32(reinterpret_cast<const quint8 *>(baInput.constData())) != 0x36304145U)) return QList<RECORD>();
            quint32 nUncompressedSize = aiBe32(reinterpret_cast<const quint8 *>(baInput.constData()) + 4);
            if (!nUncompressedSize) nUncompressedSize = nCompressedSize;
            if (nUncompressedSize > (256U * 1024U * 1024U)) return QList<RECORD>();
            if ((nOutputLimit >= 0) &&
                (static_cast<quint64>(nUncompressedSize) > static_cast<quint64>(nOutputLimit))) continue;
            if ((quint64)nCompressedSize + nUncompressedSize > (quint64)(std::numeric_limits<qint64>::max)() ||
                !decodeReservation.resize((qint64)nCompressedSize + nUncompressedSize)) return QList<RECORD>();
            baOutput.resize(static_cast<int>(nUncompressedSize));
            memset(baOutput.data(), 0, nUncompressedSize);
            quint32 nActualSize = 0;
            if (!_inflate(reinterpret_cast<const quint8 *>(baInput.constData()), nCompressedSize,
                          reinterpret_cast<quint8 *>(baOutput.data()), nUncompressedSize, true, &nActualSize)) return QList<RECORD>();
            baOutput.resize(static_cast<int>(nActualSize));
        } else {
            baOutput = baInput;
        }

        if (baOutput.size() < 4) continue;
        RECORD record;
        record.sName = bScript ? QStringLiteral("autoit_script.au3.tokens") : aiSafeRecordName(sMagic);
        if (record.sName.isEmpty()) record.sName = aiSafeRecordName(sBuildName);
        if (record.sName.isEmpty()) {
            record.sName = QStringLiteral("autoit_%1.bin").arg(listResult.size(), 3, 10, QChar('0'));
        }
        if ((listResult.size() >= 100000) || !aiReserveRecord(pRecordReservation, baOutput.size(), record.sName)) return QList<RECORD>();
        record.baData = baOutput;
        listResult.append(record);
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

    // AutoIt v2 stores the absolute start of its binary container in the
    // final little-endian DWORD.  Requiring that backlink, the full signature,
    // and subtype 1 avoids treating signature bytes embedded in arbitrary PE
    // data as an AutoIt v2 container.
    if ((nSize >= 25) && isPdStructNotCanceled(pPdStruct)) {
        const quint32 nV2Offset = read_uint32(nSize - 4, false);
        if ((static_cast<quint64>(nV2Offset) <= static_cast<quint64>(nSize - 25))) {
            const QByteArray baV2Header = read_array_process(nV2Offset, 17, pPdStruct);
            if ((baV2Header.size() == 17) &&
                (memcmp(baV2Header.constData(), AI_V2_SIGNATURE, sizeof(AI_V2_SIGNATURE)) == 0) &&
                (static_cast<quint8>(baV2Header.at(16)) == 1)) {
                result.bIsValid = true;
                result.nVersion = 2;
                result.sVersion = QStringLiteral("v2");
                result.nMarkerOffset = nV2Offset;
                return result;
            }
        }
    }

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
        result.sVersion = "EA06";
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
    QPointer<XAUTOIT> guardedThis(this);
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

void *XAUTOIT::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XAUTOIT> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
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
    QPointer<XAUTOIT> guardedThis(this);

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
    const qint64 nSourceSize = guardedSource->size();
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || (nSourceSize < 0)) return false;

    QScopedPointer<UNPACK_CONTEXT> pContext(new (std::nothrow) UNPACK_CONTEXT);
    if (!pContext || !pContext->memoryReservation.acquire(mapProperties, 0)) return false;

    QScopedPointer<XMaterializedUnpackGuard> pSourceGuard(XMaterializedUnpackGuard::bind(guardedSource.data(), pPdStruct));
    if (!isProgressAlive() || !pSourceGuard || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    QScopedPointer<QIODevice> pSnapshot(createUnpackFileBuffer(nSourceSize, mapProperties, pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pSnapshot ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;
    const bool bCopied = copyDeviceMemory(guardedSource.data(), 0, pSnapshot.data(), 0, nSourceSize, pPdStruct);
    if (!isProgressAlive() || !bCopied || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;

    XAUTOIT worker(pSnapshot.data(), bIsImage, nModuleAddress);
    const INTERNAL_INFO info = worker._detect(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data()) || !info.bIsValid) return false;

    QList<RECORD> listRecords;
    {
        const qint64 nWorkerSize = worker.getSize();
        UNPACK_MEMORY_RESERVATION inputReservation;
        if ((nWorkerSize < 0) || !inputReservation.acquire(mapProperties, nWorkerSize)) return false;
        QByteArray baFile = worker.read_array_process(0, nWorkerSize, pPdStruct);
        if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data()) ||
            ((qint64)baFile.size() != nWorkerSize)) return false;
        if (info.nVersion == 2) {
            listRecords = worker._parseV2(reinterpret_cast<const quint8 *>(baFile.constData()),
                                          baFile.size(), info.nMarkerOffset, nOutputLimit,
                                          mapProperties, &pContext->memoryReservation, pPdStruct);
        } else if (info.nVersion == 5) {
            listRecords = worker._parseEA05(reinterpret_cast<const quint8 *>(baFile.constData()),
                                            baFile.size(), info.nMarkerOffset + 8, nOutputLimit,
                                            mapProperties, &pContext->memoryReservation, pPdStruct);
        } else if (info.nVersion == 6) {
            listRecords = worker._parseEA06(reinterpret_cast<const quint8 *>(baFile.constData()),
                                            baFile.size(), info.nMarkerOffset + 8, nOutputLimit,
                                            mapProperties, &pContext->memoryReservation, pPdStruct);
        }
        if (!isProgressAlive() || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data()) || listRecords.isEmpty()) return false;
    }
    if (!isProgressAlive() || !isPdStructNotCanceled(pPdStruct)) return false;

    pContext->listRecords = listRecords;
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
    pState->nNumberOfRecords = listRecords.size();
    pState->mapUnpackProperties = mapProperties;
    pState->pContext = pContext.data();
    pState->baUnpackSourceToken = pContext->baToken;
    pOwnerLifetimeState->setContexts.insert(pContext.take());
    if (!guardedThis || !pOwnerLifetimeState->bOwnerAlive) return false;
    return true;
}

XBinary::ARCHIVERECORD XAUTOIT::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize)) return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nNumberOfRecords != pContext->listRecords.size())) return result;
    const qint32 nIndex = pContext->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return result;

    const RECORD &rec = pContext->listRecords.at(nIndex);
    result.nStreamOffset = 0;
    result.nStreamSize = rec.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = rec.sName.isEmpty() ? QString("autoit_%1").arg(nIndex, 3, 10, QChar('0')) : rec.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)rec.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;

    return guardedThis ? result : ARCHIVERECORD();
}

bool XAUTOIT::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
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
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize)) return false;
    const qint32 nIndex = pContext->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listRecords.size())) return false;

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

    const QByteArray &baData = pContext->listRecords.at(nIndex).baData;
    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    const bool bResult = writeUnpackData(&writeState, guardedOutput.data(), baData, pPdStruct);
    const bool bSourceCurrent = bResult && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bAuthenticated = bSourceCurrent && guardedThis && guardedOutput && pLifetimeState->bOwnerAlive &&
                                pLifetimeState->setContexts.contains(pContext) &&
                                (pState->pContext == pContext) && (pContext->pOwnerState == pState) &&
                                (pState->baUnpackSourceToken == pContext->baToken) &&
                                (pState->nCurrentIndex == pContext->nCurrentIndex) &&
                                (pState->nCurrentOffset == pContext->nCurrentOffset) &&
                                (pState->nNumberOfRecords == pContext->listRecords.size()) &&
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

bool XAUTOIT::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XAUTOIT> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() ||
        !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nNumberOfRecords != pContext->listRecords.size()) ||
        (pState->nTotalSize != pContext->nSourceSize) ||
        (pContext->nCurrentIndex < 0) ||
        (pContext->nCurrentIndex >= pContext->listRecords.size() - 1)) return false;

    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) ||
        (pContext->nCurrentIndex >= pContext->listRecords.size() - 1)) return false;

    ++pContext->nCurrentIndex;
    pContext->nCurrentOffset = 0;
    pState->nCurrentIndex = pContext->nCurrentIndex;
    pState->nCurrentOffset = 0;
    return true;
}

bool XAUTOIT::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
