/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xsfx.h"

#include <QBuffer>
#include <QDir>
#include <QScopedValueRollback>
#include <QTemporaryFile>

#include <limits>
#include <new>

#include "subdevice.h"
#include "xelf.h"
#include "xmsdos.h"
#include "xpe.h"
#include "../XArchive/xfreearc.h"
#include "../XArchive/xsevenzip.h"
#include "../XArchive/xrar.h"
#include "../XArchive/xcab.h"
#include "../XArchive/xzpaq.h"
#include "../XArchive/xzip.h"

// A modeled ZPAQ segment can legitimately be much larger than the overlay
// signature window, so validation must be allowed to stream to EOF.  Keep the
// results of those four-zero terminator searches in absolute file coordinates:
// every later query either reuses a known result or searches only an uncovered
// gap.  The input extent is therefore the shared byte budget instead of an
// arbitrary per-candidate size cap.
struct XSFX_ZPAQ_SCAN_CACHE {
    enum { MAX_INTERVALS = 4096 };

    QPointer<QIODevice> pDevice;
    qint64 nDeviceSize = -1;
    qint64 nNoTerminatorFrom = -1;
    QMap<qint64, qint64> mapTerminatorBySearchStart;

    void bind(QIODevice *pNewDevice, qint64 nNewDeviceSize)
    {
        if ((pDevice != pNewDevice) || (nDeviceSize != nNewDeviceSize)) {
            pDevice = pNewDevice;
            nDeviceSize = nNewDeviceSize;
            nNoTerminatorFrom = -1;
            mapTerminatorBySearchStart.clear();
        }
    }

    qint64 findTerminator(XBinary *pBinary, qint64 nStart, qint64 nEnd,
                          XBinary::PDSTRUCT *pPdStruct)
    {
        if (!pBinary || !pDevice || (pBinary->getDevice() != pDevice) ||
            (nDeviceSize < 0) || (nStart < 0) || (nStart >= nEnd) ||
            (nEnd != nDeviceSize) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return -1;
        }
        if ((nNoTerminatorFrom >= 0) &&
            (nStart >= nNoTerminatorFrom)) {
            return -1;
        }

        // A predecessor covers all search starts through its first match, or
        // through EOF when it proved that no terminator remains.
        QMap<qint64, qint64>::const_iterator itUpper =
            mapTerminatorBySearchStart.upperBound(nStart);
        if (itUpper != mapTerminatorBySearchStart.constBegin()) {
            QMap<qint64, qint64>::const_iterator itPrevious = itUpper;
            --itPrevious;
            const qint64 nPreviousResult = itPrevious.value();
            const qint64 nPreviousEnd =
                (nPreviousResult >= 0) ? nPreviousResult : nEnd;
            if (nStart <= nPreviousEnd) return nPreviousResult;
        }

        // Stop at the next cached interval. Three bytes of look-ahead are
        // sufficient to catch a four-byte signature crossing that boundary.
        const QMap<qint64, qint64>::const_iterator itNext =
            mapTerminatorBySearchStart.lowerBound(nStart);
        const bool bHasNextInterval =
            (itNext != mapTerminatorBySearchStart.constEnd()) &&
            (itNext.key() < nEnd);
        qint64 nNextStart = bHasNextInterval ? itNext.key() : nEnd;
        qint64 nNextResult = bHasNextInterval ? itNext.value() : -1;
        bool bHasNext = bHasNextInterval;
        if ((nNoTerminatorFrom >= 0) &&
            (!bHasNext || (nNoTerminatorFrom < nNextStart))) {
            nNextStart = nNoTerminatorFrom;
            nNextResult = -1;
            bHasNext = true;
        }
        const qint64 nSearchEnd = bHasNext
            ? ((nNextStart > nEnd - 3) ? nEnd : nNextStart + 3)
            : nEnd;
        const qint64 nFound = pBinary->find_signature(
            nStart, nSearchEnd - nStart, "00000000", nullptr, pPdStruct);
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return -1;

        qint64 nResult = -1;
        if ((nFound >= nStart) && (!bHasNext || (nFound < nNextStart))) {
            nResult = nFound;
        } else if (bHasNext) {
            nResult = nNextResult;
        }
        if (nResult < 0) {
            nNoTerminatorFrom = (nNoTerminatorFrom < 0)
                ? nStart : qMin(nNoTerminatorFrom, nStart);
        }
        // A valid archive may contain very many tiny segments. Keep the cache
        // itself bounded; once full, later segment scans are still monotonic
        // within that candidate and do not require retained interval state.
        if (mapTerminatorBySearchStart.size() < MAX_INTERVALS) {
            mapTerminatorBySearchStart.insert(nStart, nResult);
        }
        return nResult;
    }
};

// Local FreeArc footer verification is deliberately bounded across all
// candidates in one SFX scan. A shared tuple cache avoids decoding the same
// corrupt control stream repeatedly, while the aggregate byte budget bounds
// distinct decoys as well.
struct XSFX_FREEARC_SCAN_CACHE {
    enum { MAX_RESULTS = 256 };

    QPointer<QIODevice> pDevice;
    qint64 nDeviceSize = -1;
    qint64 nRemainingOutput = 128LL * 1024 * 1024;
    QHash<QString, qint32> mapStatus;
    QHash<QString, qint64> mapExpectedCandidateOffset;

    void bind(QIODevice *pNewDevice, qint64 nNewDeviceSize)
    {
        if ((pDevice != pNewDevice) || (nDeviceSize != nNewDeviceSize)) {
            pDevice = pNewDevice;
            nDeviceSize = nNewDeviceSize;
            nRemainingOutput = 128LL * 1024 * 1024;
            mapStatus.clear();
            mapExpectedCandidateOffset.clear();
        }
    }

    bool lookup(const QString &sKey, qint32 *pnStatus) const
    {
        const QHash<QString, qint32>::const_iterator it = mapStatus.constFind(sKey);
        if (it == mapStatus.constEnd()) return false;
        if (pnStatus) *pnStatus = it.value();
        return true;
    }

    void remember(const QString &sKey, qint32 nStatus)
    {
        if ((mapStatus.size() < MAX_RESULTS) || mapStatus.contains(sKey)) {
            mapStatus.insert(sKey, nStatus);
        }
    }

    bool lookupExpectedCandidate(const QString &sKey,
                                 qint64 *pnCandidateOffset) const
    {
        const QHash<QString, qint64>::const_iterator it =
            mapExpectedCandidateOffset.constFind(sKey);
        if (it == mapExpectedCandidateOffset.constEnd()) return false;
        if (pnCandidateOffset) *pnCandidateOffset = it.value();
        return true;
    }

    void rememberExpectedCandidate(const QString &sKey,
                                   qint64 nCandidateOffset)
    {
        if ((mapExpectedCandidateOffset.size() < MAX_RESULTS) ||
            mapExpectedCandidateOffset.contains(sKey)) {
            mapExpectedCandidateOffset.insert(sKey, nCandidateOffset);
        }
    }

    bool charge(qint64 nOutputSize)
    {
        if ((nOutputSize < 0) || (nOutputSize > nRemainingOutput)) return false;
        nRemainingOutput -= nOutputSize;
        return true;
    }
};

namespace {

const qint64 SFX_OVERLAY_SCAN_LIMIT = 16LL * 1024 * 1024;
const qint32 SFX_ELF_TABLE_LIMIT = 4096;
const qint64 SFX_ZPAQ_METADATA_SCAN_LIMIT = 1024 * 1024;
const qint32 SFX_SIGNATURE_CANDIDATE_LIMIT = 256;
// FreeArc's aSCAN_MAX permits descriptors (including long method chains) up
// to 4096 bytes. Read the same bounded window so valid encrypted/composed
// footers are not rejected merely because their method descriptor exceeds 1 KiB.
const qint64 SFX_FREEARC_DESCRIPTOR_SCAN_LIMIT = 4096;
const qint64 SFX_FREEARC_HEADER_SIZE = 8;
const qint64 SFX_FREEARC_CONTROL_OUTPUT_LIMIT = 64LL * 1024 * 1024;
const quint64 SFX_FREEARC_LZMA_DICTIONARY_LIMIT = 64ULL * 1024 * 1024;
const qint64 SFX_FREEARC_MEMORY_LIMIT = 192LL * 1024 * 1024;
const quint64 SFX_FREEARC_CONTROL_BLOCK_LIMIT = 4096;
const QByteArray SFX_ZPAQFRANZ_START_TAG(
    "rVVboBqlhbQksmjLfITQlKVxMB8oUiezUpip3End", 40);
const QByteArray SFX_ZPAQFRANZ_END_TAG(
    "oOEik4pAXOyDLNTQ7zG2Jtc4eX5N0ESHsP6ApUzx", 40);

bool checkedExtent(quint64 nOffset, quint64 nSize, qint64 nFileSize, qint64 *pnEnd)
{
    if (!pnEnd || (nFileSize < 0)) return false;
    const quint64 nUnsignedFileSize = static_cast<quint64>(nFileSize);
    if ((nOffset > nUnsignedFileSize) || (nSize > nUnsignedFileSize - nOffset)) return false;
    *pnEnd = static_cast<qint64>(nOffset + nSize);
    return true;
}

bool checkedTableExtent(quint64 nOffset, quint64 nEntrySize, quint64 nCount,
                        qint64 nFileSize, qint64 *pnEnd)
{
    if (nCount && (nEntrySize > static_cast<quint64>(nFileSize) / nCount)) return false;
    return checkedExtent(nOffset, nEntrySize * nCount, nFileSize, pnEnd);
}

bool getZpaqFranzSfxPayload(XBinary *pOuter, qint64 nOverlayOffset,
                            qint64 *pnPayloadOffset,
                            qint64 *pnPayloadSize,
                            XBinary::PDSTRUCT *pPdStruct)
{
    if (!pOuter || !pnPayloadOffset || !pnPayloadSize ||
        (nOverlayOffset < 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    const qint64 nFileSize = pOuter->getSize();
    const qint64 nMinimumFraming = SFX_ZPAQFRANZ_START_TAG.size() +
        SFX_ZPAQFRANZ_END_TAG.size() + 2;
    if ((nFileSize < 0) ||
        (nOverlayOffset > nFileSize - nMinimumFraming)) {
        return false;
    }

    const qint64 nReadSize = qMin(
        nFileSize - nOverlayOffset,
        SFX_ZPAQ_METADATA_SCAN_LIMIT);
    const QByteArray baFraming = pOuter->read_array_process(
        nOverlayOffset, nReadSize, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
        (baFraming.size() != nReadSize)) {
        return false;
    }

    // A certificate or another pre-existing unmapped trailer can precede the
    // zpaqfranz record. The paired 320-bit tags still identify it precisely
    // within this bounded metadata window.
    const int nStartTagOffset = baFraming.indexOf(
        SFX_ZPAQFRANZ_START_TAG);
    if (nStartTagOffset < 0) return false;
    const int nCommandOffset = nStartTagOffset +
        SFX_ZPAQFRANZ_START_TAG.size();
    const int nEndTagOffset = baFraming.indexOf(
        SFX_ZPAQFRANZ_END_TAG, nCommandOffset);
    if (nEndTagOffset <= nCommandOffset) return false;

    QByteArray baCommand = baFraming.mid(
        nCommandOffset, nEndTagOffset - nCommandOffset);
    for (char &c : baCommand) {
        c = static_cast<char>(static_cast<quint8>(c) ^ 0x21U);
        const quint8 nByte = static_cast<quint8>(c);
        if ((nByte < 0x20) || (nByte > 0x7E)) return false;
    }
    if (!baCommand.startsWith("x ") ||
        !baCommand.toLower().contains(".zpaq")) {
        return false;
    }

    const qint64 nRelativePayloadOffset =
        static_cast<qint64>(nEndTagOffset) +
        SFX_ZPAQFRANZ_END_TAG.size();
    if ((nRelativePayloadOffset < 0) ||
        (nRelativePayloadOffset > nFileSize - nOverlayOffset)) {
        return false;
    }
    const qint64 nPayloadOffset =
        nOverlayOffset + nRelativePayloadOffset;
    const qint64 nPayloadSize = nFileSize - nPayloadOffset;
    if (nPayloadSize <= 32) return false;

    *pnPayloadOffset = nPayloadOffset;
    *pnPayloadSize = nPayloadSize;
    return true;
}

bool resemblesPlainZpaqPrefix(const QByteArray &baPrefix)
{
    if (baPrefix.startsWith("zPQ")) return true;

    static const QByteArray baTaggedPrefix(
        "\x37\x6B\x53\x74\xA0\x31\x83\xD3"
        "\x8C\xB2\x28\xB0\xD3zPQ", 16);
    if (baPrefix.size() < baTaggedPrefix.size()) return false;

    qint32 nDifferences = 0;
    for (qint32 i = 0; i < baTaggedPrefix.size(); ++i) {
        if (baPrefix.at(i) != baTaggedPrefix.at(i)) ++nDifferences;
    }
    return nDifferences <= 1;
}

// XELF's normal raw-size calculation honors segment alignment. For an SFX that
// can consume a short unmapped trailer and hide the real archive. Derive the
// exact file-backed extent instead and reject malformed/out-of-range tables.
qint64 getExactELFExtent(XELF *pELF, qint64 nFileSize)
{
    if (!pELF || (nFileSize <= 0)) return -1;

    const XELF_DEF::Elf_Ehdr header = pELF->getHdr();
    const bool bIs64 = pELF->is64();
    const quint16 nExpectedHeaderSize = bIs64
        ? sizeof(XELF_DEF::Elf64_Ehdr)
        : sizeof(XELF_DEF::Elf32_Ehdr);
    const quint16 nExpectedProgramSize = bIs64
        ? sizeof(XELF_DEF::Elf64_Phdr)
        : sizeof(XELF_DEF::Elf32_Phdr);
    const quint16 nExpectedSectionSize = bIs64
        ? sizeof(XELF_DEF::Elf64_Shdr)
        : sizeof(XELF_DEF::Elf32_Shdr);

    // XELF's list readers advance by the native entry sizes. Accept only the
    // canonical layout they actually parse, and decline extended numbering
    // instead of deriving a potentially unsafe overlay boundary from it.
    if ((header.e_ehsize != nExpectedHeaderSize) ||
        (header.e_phnum && (header.e_phentsize != nExpectedProgramSize)) ||
        (header.e_shnum && (header.e_shentsize != nExpectedSectionSize)) ||
        ((!header.e_shnum) && header.e_shoff) ||
        (header.e_shstrndx == XELF_DEF::S_SHN_XINDEX)) {
        return -1;
    }
    if ((header.e_phnum > SFX_ELF_TABLE_LIMIT) ||
        (header.e_shnum > SFX_ELF_TABLE_LIMIT)) {
        return -1;
    }

    qint64 nResult = 0;
    qint64 nEnd = 0;
    if (!checkedExtent(0, header.e_ehsize, nFileSize, &nEnd)) return -1;
    nResult = qMax(nResult, nEnd);

    if (header.e_phnum) {
        if (!header.e_phentsize ||
            !checkedTableExtent(header.e_phoff, header.e_phentsize,
                                header.e_phnum, nFileSize, &nEnd)) {
            return -1;
        }
        nResult = qMax(nResult, nEnd);
    }
    if (header.e_shnum) {
        if (!header.e_shentsize ||
            !checkedTableExtent(header.e_shoff, header.e_shentsize,
                                header.e_shnum, nFileSize, &nEnd)) {
            return -1;
        }
        nResult = qMax(nResult, nEnd);
    }

    const QList<XELF_DEF::Elf_Phdr> programs =
        pELF->getElf_PhdrList(SFX_ELF_TABLE_LIMIT);
    if (programs.size() != header.e_phnum) return -1;
    for (const XELF_DEF::Elf_Phdr &program : programs) {
        if (!checkedExtent(program.p_offset, program.p_filesz, nFileSize, &nEnd)) return -1;
        nResult = qMax(nResult, nEnd);
    }

    const QList<XELF_DEF::Elf_Shdr> sections =
        pELF->getElf_ShdrList(SFX_ELF_TABLE_LIMIT);
    if (sections.size() != header.e_shnum) return -1;
    for (const XELF_DEF::Elf_Shdr &section : sections) {
        // SHT_NOBITS (8) occupies no bytes in the file.
        if (section.sh_type == 8) continue;
        if (!checkedExtent(section.sh_offset, section.sh_size, nFileSize, &nEnd)) return -1;
        nResult = qMax(nResult, nEnd);
    }

    return nResult;
}

bool hasFreeArcMethod(const QByteArray &baMethod)
{
    const int nEnd = baMethod.indexOf('\0');
    if (nEnd <= 0) return false;
    for (int i = 0; i < nEnd; i++) {
        const quint8 nByte = static_cast<quint8>(baMethod.at(i));
        if ((nByte < 0x20) || (nByte > 0x7E)) return false;
    }
    return true;
}

bool readFreeArcInteger(const QByteArray &baData, int *pnOffset,
                        quint64 *pnValue)
{
    if (!pnOffset || !pnValue || (*pnOffset < 0) ||
        (*pnOffset >= baData.size())) {
        return false;
    }

    const quint8 nFirst = static_cast<quint8>(baData.at(*pnOffset));
    int nEncodedSize = 0;
    if (!(nFirst & 1)) nEncodedSize = 1;
    else if ((nFirst & 3) == 1) nEncodedSize = 2;
    else if ((nFirst & 7) == 3) nEncodedSize = 3;
    else if ((nFirst & 15) == 7) nEncodedSize = 4;
    else if ((nFirst & 31) == 15) nEncodedSize = 5;
    else if ((nFirst & 63) == 31) nEncodedSize = 6;
    else if ((nFirst & 127) == 63) nEncodedSize = 7;
    else if (nFirst == 127) nEncodedSize = 8;
    else if (nFirst == 255) nEncodedSize = 9;
    else return false;

    if (nEncodedSize > baData.size() - *pnOffset) return false;

    quint64 nValue = 0;
    if (nEncodedSize == 9) {
        for (int i = 0; i < 8; i++) {
            nValue |= static_cast<quint64>(static_cast<quint8>(
                baData.at(*pnOffset + 1 + i))) << (i * 8);
        }
    } else {
        for (int i = 0; i < nEncodedSize; i++) {
            nValue |= static_cast<quint64>(static_cast<quint8>(
                baData.at(*pnOffset + i))) << (i * 8);
        }
        nValue >>= nEncodedSize;
    }

    *pnOffset += nEncodedSize;
    *pnValue = nValue;
    return true;
}

enum FREEARC_DATA_STATUS {
    FREEARC_DATA_CODEC_UNAVAILABLE = 0,
    FREEARC_DATA_RESOURCE_LIMIT,
    FREEARC_DATA_INVALID,
    FREEARC_DATA_AUTHENTICATED
};

enum FREEARC_LAYOUT_STATUS {
    FREEARC_LAYOUT_INVALID = 0,
    FREEARC_LAYOUT_RESOURCE_LIMIT,
    FREEARC_LAYOUT_PROVISIONAL,
    FREEARC_LAYOUT_AUTHENTICATED
};

struct FREEARC_DESCRIPTOR {
    qint64 nOffset = -1;
    qint64 nLength = 0;
    qint64 nDataOffset = -1;
    quint64 nType = 0;
    QByteArray baMethod;
    quint64 nOriginalSize = 0;
    quint64 nCompressedSize = 0;
    quint32 nDataCRC = 0;
};

quint32 readFreeArcLE32(const QByteArray &baData, int nOffset)
{
    if ((nOffset < 0) || (nOffset > baData.size() - 4)) return 0;
    return static_cast<quint32>(static_cast<quint8>(baData.at(nOffset))) |
           (static_cast<quint32>(static_cast<quint8>(baData.at(nOffset + 1))) << 8) |
           (static_cast<quint32>(static_cast<quint8>(baData.at(nOffset + 2))) << 16) |
           (static_cast<quint32>(static_cast<quint8>(baData.at(nOffset + 3))) << 24);
}

bool isFreeArcMethodText(const QByteArray &baMethod)
{
    if (baMethod.isEmpty()) return false;
    for (char c : baMethod) {
        const quint8 nByte = static_cast<quint8>(c);
        if ((nByte < 0x20) || (nByte > 0x7E)) return false;
    }
    return true;
}

bool readFreeArcCString(const QByteArray &baData, int *pnOffset,
                        QByteArray *pValue)
{
    if (!pnOffset || !pValue || (*pnOffset < 0) ||
        (*pnOffset >= baData.size())) {
        return false;
    }
    const int nEnd = baData.indexOf('\0', *pnOffset);
    if (nEnd < *pnOffset) return false;
    *pValue = baData.mid(*pnOffset, nEnd - *pnOffset);
    *pnOffset = nEnd + 1;
    return true;
}

bool parseFreeArcDescriptorData(const QByteArray &baDescriptor,
                                qint64 nOffset, qint64 nArchiveSize,
                                FREEARC_DESCRIPTOR *pDescriptor)
{
    if (!pDescriptor || (nOffset < 0) || (nArchiveSize < 0) ||
        (nOffset > nArchiveSize - 15) || (baDescriptor.size() < 15) ||
        (baDescriptor.left(4) != QByteArray("ArC\x01", 4))) {
        return false;
    }

    int nCursor = 4;
    quint64 nType = 0;
    QByteArray baMethod;
    quint64 nOriginalSize = 0;
    quint64 nCompressedSize = 0;
    if (!readFreeArcInteger(baDescriptor, &nCursor, &nType) ||
        !readFreeArcCString(baDescriptor, &nCursor, &baMethod) ||
        !isFreeArcMethodText(baMethod) ||
        !readFreeArcInteger(baDescriptor, &nCursor, &nOriginalSize) ||
        !readFreeArcInteger(baDescriptor, &nCursor, &nCompressedSize) ||
        !nOriginalSize || !nCompressedSize ||
        (nCursor > baDescriptor.size() - 8) ||
        (nCompressedSize > static_cast<quint64>(nOffset))) {
        return false;
    }

    const quint32 nStoredDescriptorCRC =
        readFreeArcLE32(baDescriptor, nCursor + 4);
    const quint32 nCalculatedDescriptorCRC = XBinary::_getCRC32(
        baDescriptor.constData(), nCursor + 4, 0xFFFFFFFFU,
        XBinary::_getCRC32Table_EDB88320()) ^ 0xFFFFFFFFU;
    if (nStoredDescriptorCRC != nCalculatedDescriptorCRC) return false;

    FREEARC_DESCRIPTOR descriptor;
    descriptor.nOffset = nOffset;
    descriptor.nLength = nCursor + 8;
    descriptor.nDataOffset =
        nOffset - static_cast<qint64>(nCompressedSize);
    descriptor.nType = nType;
    descriptor.baMethod = baMethod;
    descriptor.nOriginalSize = nOriginalSize;
    descriptor.nCompressedSize = nCompressedSize;
    descriptor.nDataCRC = readFreeArcLE32(baDescriptor, nCursor);
    *pDescriptor = descriptor;
    return true;
}

bool parseFreeArcDescriptorAt(XFREEARC *pArchive, qint64 nOffset,
                              FREEARC_DESCRIPTOR *pDescriptor,
                              XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pDescriptor || (nOffset < 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }
    const qint64 nArchiveSize = pArchive->getSize();
    if ((nArchiveSize < 0) || (nOffset > nArchiveSize - 15)) return false;

    const qint64 nReadSize = qMin(
        nArchiveSize - nOffset, SFX_FREEARC_DESCRIPTOR_SCAN_LIMIT);
    const QByteArray baDescriptor = pArchive->read_array_process(
        nOffset, nReadSize, pPdStruct);
    return XBinary::isPdStructNotCanceled(pPdStruct) &&
           (baDescriptor.size() == nReadSize) &&
           parseFreeArcDescriptorData(
               baDescriptor, nOffset, nArchiveSize, pDescriptor);
}

bool isAuthenticatedFreeArcHeaderDescriptor(
    XFREEARC *pArchive, const FREEARC_DESCRIPTOR &descriptor,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || (descriptor.nDataOffset < 0) ||
        (descriptor.nOffset !=
         descriptor.nDataOffset + SFX_FREEARC_HEADER_SIZE) ||
        (descriptor.nType != 1) || (descriptor.baMethod != "storing") ||
        (descriptor.nOriginalSize != SFX_FREEARC_HEADER_SIZE) ||
        (descriptor.nCompressedSize != SFX_FREEARC_HEADER_SIZE) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    const QByteArray baHeader = pArchive->read_array_process(
        descriptor.nDataOffset, SFX_FREEARC_HEADER_SIZE, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
        (baHeader.size() != SFX_FREEARC_HEADER_SIZE) ||
        (baHeader.left(4) != QByteArray("ArC\x01", 4))) {
        return false;
    }

    const quint32 nCalculatedCRC = pArchive->_getCRC32(
        descriptor.nDataOffset, SFX_FREEARC_HEADER_SIZE, 0xFFFFFFFFU,
        XBinary::_getCRC32Table_EDB88320(), pPdStruct);
    return XBinary::isPdStructNotCanceled(pPdStruct) &&
           (nCalculatedCRC == descriptor.nDataCRC);
}

bool hasAuthenticatedFreeArcHeader(XFREEARC *pArchive,
                                   XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive ||
        (pArchive->getSize() < SFX_FREEARC_HEADER_SIZE + 15) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    FREEARC_DESCRIPTOR descriptor;
    return parseFreeArcDescriptorAt(
               pArchive, SFX_FREEARC_HEADER_SIZE, &descriptor, pPdStruct) &&
           (descriptor.nDataOffset == 0) &&
           isAuthenticatedFreeArcHeaderDescriptor(
               pArchive, descriptor, pPdStruct);
}

bool parseFreeArcDecimal(const QByteArray &baValue, qint32 *pnResult)
{
    if (!pnResult || baValue.isEmpty()) return false;
    for (char c : baValue) {
        if ((c < '0') || (c > '9')) return false;
    }
    bool bOK = false;
    const qlonglong nValue = baValue.toLongLong(&bOK);
    if (!bOK || (nValue > (std::numeric_limits<qint32>::max)())) return false;
    *pnResult = static_cast<qint32>(nValue);
    return true;
}

bool parseFreeArcMemory(const QByteArray &baValue, quint64 *pnResult)
{
    if (!pnResult || baValue.isEmpty()) return false;
    QByteArray baNumber = baValue;
    quint64 nMultiplier = 1;
    bool bPowerOfTwo = false;
    if (baNumber.startsWith('=')) baNumber.remove(0, 1);
    if (baNumber.endsWith("gb")) {
        nMultiplier = 1024ULL * 1024 * 1024;
        baNumber.chop(2);
    } else if (baNumber.endsWith('g')) {
        nMultiplier = 1024ULL * 1024 * 1024;
        baNumber.chop(1);
    } else if (baNumber.endsWith("mb")) {
        nMultiplier = 1024ULL * 1024;
        baNumber.chop(2);
    } else if (baNumber.endsWith('m')) {
        nMultiplier = 1024ULL * 1024;
        baNumber.chop(1);
    } else if (baNumber.endsWith("kb")) {
        nMultiplier = 1024;
        baNumber.chop(2);
    } else if (baNumber.endsWith('k')) {
        nMultiplier = 1024;
        baNumber.chop(1);
    } else if (baNumber.endsWith('b')) {
        baNumber.chop(1);
    } else if (baNumber.endsWith('^')) {
        baNumber.chop(1);
        bPowerOfTwo = true;
    } else {
        // FreeArc's C parseMem() defaults a suffixless d/h value to 2^N.
        bPowerOfTwo = true;
    }

    if (baNumber.isEmpty()) return false;
    for (char c : baNumber) {
        if ((c < '0') || (c > '9')) return false;
    }

    bool bOK = false;
    const quint64 nValue = baNumber.toULongLong(&bOK);
    if (!bOK) {
        return false;
    }
    if (bPowerOfTwo) {
        if (nValue >= 64) return false;
        *pnResult = Q_UINT64_C(1) << nValue;
    } else {
        if (nValue >
            (std::numeric_limits<quint64>::max)() / nMultiplier) {
            return false;
        }
        *pnResult = nValue * nMultiplier;
    }
    return true;
}

enum FREEARC_LZMA_PROPERTIES_STATUS {
    FREEARC_LZMA_PROPERTIES_CODEC_UNAVAILABLE = 0,
    FREEARC_LZMA_PROPERTIES_RESOURCE_LIMIT,
    FREEARC_LZMA_PROPERTIES_INVALID,
    FREEARC_LZMA_PROPERTIES_VALID
};

FREEARC_LZMA_PROPERTIES_STATUS parseFreeArcLzmaProperties(
    const QByteArray &baMethod, QByteArray *pProperties,
    quint64 *pnDictionarySize)
{
    if (!pProperties || !pnDictionarySize) {
        return FREEARC_LZMA_PROPERTIES_INVALID;
    }
    if (baMethod.contains('+')) {
        const QList<QByteArray> chain = baMethod.split('+');
        for (const QByteArray &component : chain) {
            if (component.isEmpty()) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
        }
        return FREEARC_LZMA_PROPERTIES_CODEC_UNAVAILABLE;
    }

    const QList<QByteArray> parts = baMethod.split(':');
    if (parts.isEmpty() || (parts.first() != "lzma")) {
        return FREEARC_LZMA_PROPERTIES_CODEC_UNAVAILABLE;
    }

    quint64 nDictionarySize = 64ULL * 1024 * 1024;
    qint32 nPosStateBits = 2;
    qint32 nLiteralContextBits = 3;
    qint32 nLiteralPosBits = 0;

    for (qint32 i = 1; i < parts.size(); i++) {
        QByteArray baPart = parts.at(i);
        const bool bOptional = baPart.startsWith('*');
        if (bOptional) baPart.remove(0, 1);
        if (baPart.isEmpty()) return FREEARC_LZMA_PROPERTIES_INVALID;

        qint32 nInteger = 0;
        quint64 nMemory = 0;
        if ((baPart == "fastest") || (baPart == "fast") ||
                   (baPart == "normal") || (baPart == "max") ||
                   (baPart == "ultra") || (baPart == "ht4") ||
                   (baPart == "hc4") || (baPart == "bt2") ||
                   (baPart == "bt3") || (baPart == "bt4")) {
            // Encoder-only choices do not alter the raw LZMA properties.
        } else if (baPart.startsWith('d')) {
            QByteArray baValue = baPart.mid(1);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcMemory(baValue, &nMemory)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
            nDictionarySize = nMemory;
        } else if (baPart.startsWith("pb")) {
            QByteArray baValue = baPart.mid(2);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcDecimal(baValue, &nInteger)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
            nPosStateBits = nInteger;
        } else if (baPart.startsWith("lc")) {
            QByteArray baValue = baPart.mid(2);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcDecimal(baValue, &nInteger)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
            nLiteralContextBits = nInteger;
        } else if (baPart.startsWith("lp")) {
            QByteArray baValue = baPart.mid(2);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcDecimal(baValue, &nInteger)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
            nLiteralPosBits = nInteger;
        } else if (baPart.startsWith('h')) {
            QByteArray baValue = baPart.mid(1);
            if (!parseFreeArcMemory(baValue, &nMemory)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
        } else if (baPart.startsWith('a')) {
            QByteArray baValue = baPart.mid(1);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcDecimal(baValue, &nInteger)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
        } else if (baPart.startsWith("fb") || baPart.startsWith("mc")) {
            QByteArray baValue = baPart.mid(2);
            if (baValue.startsWith('=')) baValue.remove(0, 1);
            if (!parseFreeArcDecimal(baValue, &nInteger)) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
        } else if (baPart.startsWith("mf")) {
            QByteArray baMatchFinder = baPart.mid(2);
            if (baMatchFinder.startsWith('=')) baMatchFinder.remove(0, 1);
            if ((baMatchFinder != "ht4") && (baMatchFinder != "hc4") &&
                (baMatchFinder != "bt2") && (baMatchFinder != "bt3") &&
                (baMatchFinder != "bt4")) {
                return FREEARC_LZMA_PROPERTIES_INVALID;
            }
        } else if (parseFreeArcDecimal(baPart, &nInteger)) {
            // Unnamed decimal is numFastBytes, an encoder-only setting.
        } else if (parseFreeArcMemory(baPart, &nMemory)) {
            nDictionarySize = nMemory;
        } else if (!bOptional) {
            // FreeArc has encoder-only option spellings which do not affect
            // raw decoder properties. Unknown options are indeterminate, not
            // proof that the archive itself is corrupt.
            return FREEARC_LZMA_PROPERTIES_CODEC_UNAVAILABLE;
        }
    }

    if (!nDictionarySize || (nPosStateBits < 0) || (nPosStateBits > 4) ||
        (nLiteralContextBits < 0) || (nLiteralContextBits > 8) ||
        (nLiteralPosBits < 0) || (nLiteralPosBits > 4) ||
        (nLiteralContextBits + nLiteralPosBits > 12)) {
        return FREEARC_LZMA_PROPERTIES_INVALID;
    }
    if ((nDictionarySize > SFX_FREEARC_LZMA_DICTIONARY_LIMIT) ||
        (nDictionarySize > (std::numeric_limits<quint32>::max)())) {
        return FREEARC_LZMA_PROPERTIES_RESOURCE_LIMIT;
    }

    const quint32 nDictionary32 = static_cast<quint32>(nDictionarySize);
    QByteArray properties(5, 0);
    properties[0] = static_cast<char>(
        (nPosStateBits * 5 + nLiteralPosBits) * 9 +
        nLiteralContextBits);
    for (qint32 i = 0; i < 4; i++) {
        properties[1 + i] = static_cast<char>(nDictionary32 >> (8 * i));
    }
    *pProperties = properties;
    *pnDictionarySize = nDictionarySize;
    return FREEARC_LZMA_PROPERTIES_VALID;
}

FREEARC_DATA_STATUS validateFreeArcFooterData(
    XFREEARC *pArchive, const QByteArray &baData, qint64 nFooterDataOffset,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || baData.isEmpty() || (nFooterDataOffset < 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return FREEARC_DATA_INVALID;
    }

    int nCursor = 0;
    quint64 nBlockCount = 0;
    if (!readFreeArcInteger(baData, &nCursor, &nBlockCount) ||
        !nBlockCount) {
        return FREEARC_DATA_INVALID;
    }
    if (nBlockCount > SFX_FREEARC_CONTROL_BLOCK_LIMIT) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }

    qint64 nPreviousControlEnd = 0;
    for (quint64 i = 0; i < nBlockCount; i++) {
        quint64 nType = 0;
        QByteArray baMethod;
        quint64 nRelativePosition = 0;
        quint64 nOriginalSize = 0;
        quint64 nCompressedSize = 0;
        if (!readFreeArcInteger(baData, &nCursor, &nType) ||
            !readFreeArcCString(baData, &nCursor, &baMethod) ||
            !isFreeArcMethodText(baMethod) ||
            !readFreeArcInteger(baData, &nCursor, &nRelativePosition) ||
            !readFreeArcInteger(baData, &nCursor, &nOriginalSize) ||
            !readFreeArcInteger(baData, &nCursor, &nCompressedSize) ||
            !nOriginalSize || !nCompressedSize ||
            (nCursor > baData.size() - 4) ||
            (nRelativePosition > static_cast<quint64>(nFooterDataOffset))) {
            return FREEARC_DATA_INVALID;
        }
        const quint32 nDataCRC = readFreeArcLE32(baData, nCursor);
        nCursor += 4;

        if (((i == 0) && (nType != 1)) ||
            ((i != 0) && (nType == 1)) ||
            ((nType != 1) && (nType != 3) &&
             (nType != 4) && (nType != 5))) {
            return FREEARC_DATA_INVALID;
        }
        const qint64 nBlockOffset = nFooterDataOffset -
            static_cast<qint64>(nRelativePosition);
        if ((nBlockOffset < nPreviousControlEnd) ||
            (nCompressedSize > static_cast<quint64>(
                nFooterDataOffset - nBlockOffset))) {
            return FREEARC_DATA_INVALID;
        }
        const qint64 nDescriptorOffset = nBlockOffset +
            static_cast<qint64>(nCompressedSize);
        FREEARC_DESCRIPTOR descriptor;
        if (!parseFreeArcDescriptorAt(
                pArchive, nDescriptorOffset, &descriptor, pPdStruct) ||
            (descriptor.nType != nType) ||
            (descriptor.baMethod != baMethod) ||
            (descriptor.nOriginalSize != nOriginalSize) ||
            (descriptor.nCompressedSize != nCompressedSize) ||
            (descriptor.nDataCRC != nDataCRC) ||
            (descriptor.nDataOffset != nBlockOffset) ||
            (descriptor.nLength > nFooterDataOffset - nDescriptorOffset)) {
            return FREEARC_DATA_INVALID;
        }
        nPreviousControlEnd = nDescriptorOffset + descriptor.nLength;

        if (i == 0) {
            if ((nBlockOffset != 0) || (baMethod != "storing") ||
                (nOriginalSize != 8) || (nCompressedSize != 8)) {
                return FREEARC_DATA_INVALID;
            }
            const quint32 nCalculatedHeaderCRC = pArchive->_getCRC32(
                0, 8, 0xFFFFFFFFU,
                XBinary::_getCRC32Table_EDB88320(), pPdStruct);
            if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
                (nCalculatedHeaderCRC != nDataCRC)) {
                return FREEARC_DATA_INVALID;
            }
        }
    }
    if (nCursor >= baData.size()) {
        return FREEARC_DATA_INVALID;
    }

    const quint8 nLocked = static_cast<quint8>(baData.at(nCursor++));
    if (nLocked > 1) return FREEARC_DATA_INVALID;

    quint64 nOldCommentLength = 0;
    if (!readFreeArcInteger(baData, &nCursor, &nOldCommentLength) ||
        (nOldCommentLength > static_cast<quint64>(
            (baData.size() - nCursor) / 4))) {
        return FREEARC_DATA_INVALID;
    }
    nCursor += static_cast<int>(nOldCommentLength * 4);
    if (nCursor == baData.size()) return FREEARC_DATA_AUTHENTICATED;

    QByteArray baRecovery;
    if (!readFreeArcCString(baData, &nCursor, &baRecovery)) {
        return FREEARC_DATA_INVALID;
    }
    if (nCursor == baData.size()) return FREEARC_DATA_AUTHENTICATED;

    quint64 nCommentLength = 0;
    if (!readFreeArcInteger(baData, &nCursor, &nCommentLength) ||
        (nCommentLength != static_cast<quint64>(baData.size() - nCursor))) {
        return FREEARC_DATA_INVALID;
    }
    return FREEARC_DATA_AUTHENTICATED;
}

QString freeArcAuthenticationKey(qint64 nAbsoluteDataOffset,
                                 const QByteArray &baMethod,
                                 quint64 nOriginalSize,
                                 quint64 nCompressedSize,
                                 quint32 nStoredCRC)
{
    return QString::number(nAbsoluteDataOffset) + QLatin1Char(':') +
           QString::number(nOriginalSize) + QLatin1Char(':') +
           QString::number(nCompressedSize) + QLatin1Char(':') +
           QString::number(nStoredCRC) + QLatin1Char(':') +
           QString::fromLatin1(baMethod.toHex());
}

bool getExpectedFreeArcCandidateOffset(
    const QByteArray &baFooterData, qint64 nAbsoluteFooterDataOffset,
    qint64 *pnExpectedCandidateOffset)
{
    if (!pnExpectedCandidateOffset || baFooterData.isEmpty() ||
        (nAbsoluteFooterDataOffset < 0)) {
        return false;
    }

    int nCursor = 0;
    quint64 nBlockCount = 0;
    quint64 nType = 0;
    QByteArray baMethod;
    quint64 nRelativePosition = 0;
    quint64 nOriginalSize = 0;
    quint64 nCompressedSize = 0;
    if (!readFreeArcInteger(baFooterData, &nCursor, &nBlockCount) ||
        !nBlockCount ||
        !readFreeArcInteger(baFooterData, &nCursor, &nType) ||
        !readFreeArcCString(baFooterData, &nCursor, &baMethod) ||
        !readFreeArcInteger(
            baFooterData, &nCursor, &nRelativePosition) ||
        !readFreeArcInteger(baFooterData, &nCursor, &nOriginalSize) ||
        !readFreeArcInteger(baFooterData, &nCursor, &nCompressedSize) ||
        (nCursor > baFooterData.size() - 4) || (nType != 1) ||
        (baMethod != "storing") || (nOriginalSize != 8) ||
        (nCompressedSize != 8) ||
        (nRelativePosition >
            static_cast<quint64>(nAbsoluteFooterDataOffset))) {
        return false;
    }

    *pnExpectedCandidateOffset = nAbsoluteFooterDataOffset -
        static_cast<qint64>(nRelativePosition);
    return true;
}

FREEARC_DATA_STATUS authenticateFreeArcStoredData(
    XFREEARC *pArchive, qint64 nCandidateOffset, qint64 nDataOffset,
    quint64 nOriginalSize, quint64 nCompressedSize, quint32 nStoredCRC,
    XSFX_FREEARC_SCAN_CACHE *pScanCache,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pScanCache || (nCandidateOffset < 0) ||
        (nDataOffset < 0) || !nOriginalSize ||
        (nOriginalSize != nCompressedSize) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return FREEARC_DATA_INVALID;
    }
    if ((nOriginalSize > static_cast<quint64>(
            SFX_FREEARC_CONTROL_OUTPUT_LIMIT)) ||
        (nCompressedSize > static_cast<quint64>(
            SFX_FREEARC_CONTROL_OUTPUT_LIMIT))) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if (nCandidateOffset > (std::numeric_limits<qint64>::max)() -
            nDataOffset) {
        return FREEARC_DATA_INVALID;
    }

    const qint64 nAbsoluteDataOffset = nCandidateOffset + nDataOffset;
    const QString sKey = freeArcAuthenticationKey(
        nAbsoluteDataOffset, QByteArray("storing"), nOriginalSize,
        nCompressedSize, nStoredCRC);
    qint64 nExpectedCandidateOffset = -1;
    if (pScanCache->lookupExpectedCandidate(
            sKey, &nExpectedCandidateOffset) &&
        (nCandidateOffset != nExpectedCandidateOffset)) {
        return FREEARC_DATA_INVALID;
    }
    qint32 nCachedStatus = 0;
    if (pScanCache->lookup(sKey, &nCachedStatus)) {
        return static_cast<FREEARC_DATA_STATUS>(nCachedStatus);
    }
    QMap<XBinary::UNPACK_PROP, QVariant> mapMemoryProperties;
    mapMemoryProperties.insert(
        XBinary::UNPACK_PROP_MAX_OUTPUT_SIZE, SFX_FREEARC_MEMORY_LIMIT);
    XBinary::UNPACK_MEMORY_RESERVATION outputReservation;
    if (!outputReservation.acquire(
            mapMemoryProperties, static_cast<qint64>(nOriginalSize))) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if (!pScanCache->charge(static_cast<qint64>(nOriginalSize))) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }

    const QByteArray baData = pArchive->read_array_process(
        nDataOffset, static_cast<qint64>(nCompressedSize), pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
        (baData.size() != static_cast<qint64>(nCompressedSize))) {
        return FREEARC_DATA_INVALID;
    }
    const quint32 nCalculatedCRC = XBinary::_getCRC32(
        baData.constData(), baData.size(), 0xFFFFFFFFU,
        XBinary::_getCRC32Table_EDB88320()) ^ 0xFFFFFFFFU;
    if (nCalculatedCRC != nStoredCRC) {
        pScanCache->remember(sKey, FREEARC_DATA_INVALID);
        return FREEARC_DATA_INVALID;
    }
    if (!getExpectedFreeArcCandidateOffset(
            baData, nAbsoluteDataOffset, &nExpectedCandidateOffset)) {
        pScanCache->remember(sKey, FREEARC_DATA_INVALID);
        return FREEARC_DATA_INVALID;
    }
    pScanCache->rememberExpectedCandidate(
        sKey, nExpectedCandidateOffset);
    if (nCandidateOffset != nExpectedCandidateOffset) {
        return FREEARC_DATA_INVALID;
    }
    const FREEARC_DATA_STATUS status = validateFreeArcFooterData(
        pArchive, baData, nDataOffset, pPdStruct);
    pScanCache->remember(sKey, status);
    return status;
}

FREEARC_DATA_STATUS authenticateFreeArcLzmaData(
    XFREEARC *pArchive, qint64 nCandidateOffset,
    const QByteArray &baMethod, qint64 nDataOffset,
    quint64 nOriginalSize, quint64 nCompressedSize, quint32 nStoredCRC,
    XSFX_FREEARC_SCAN_CACHE *pScanCache,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pScanCache || (nCandidateOffset < 0) ||
        (nDataOffset < 0) || !nOriginalSize || !nCompressedSize ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return FREEARC_DATA_INVALID;
    }
    if ((nOriginalSize > static_cast<quint64>(
            SFX_FREEARC_CONTROL_OUTPUT_LIMIT)) ||
        (nCompressedSize > static_cast<quint64>(
            SFX_FREEARC_CONTROL_OUTPUT_LIMIT))) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if (nCandidateOffset > (std::numeric_limits<qint64>::max)() -
            nDataOffset) {
        return FREEARC_DATA_INVALID;
    }

    // Composed codecs are delegated to the FreeArc backend, but recognizable
    // LZMA stages still have to satisfy the same local dictionary cap. Adding
    // an unsupported filter or encryption stage must not bypass that limit.
    if (baMethod.contains('+')) {
        const QList<QByteArray> chain = baMethod.split('+');
        for (const QByteArray &component : chain) {
            if (component.isEmpty()) return FREEARC_DATA_INVALID;
            if ((component == "lzma") || component.startsWith("lzma:")) {
                QByteArray baComponentProperties;
                quint64 nComponentDictionarySize = 0;
                const FREEARC_LZMA_PROPERTIES_STATUS componentStatus =
                    parseFreeArcLzmaProperties(
                        component, &baComponentProperties,
                        &nComponentDictionarySize);
                if (componentStatus ==
                        FREEARC_LZMA_PROPERTIES_RESOURCE_LIMIT) {
                    return FREEARC_DATA_RESOURCE_LIMIT;
                }
                if (componentStatus == FREEARC_LZMA_PROPERTIES_INVALID) {
                    return FREEARC_DATA_INVALID;
                }
            }
        }
        return FREEARC_DATA_CODEC_UNAVAILABLE;
    }

    QByteArray baProperties;
    quint64 nDictionarySize = 0;
    const FREEARC_LZMA_PROPERTIES_STATUS propertiesStatus =
        parseFreeArcLzmaProperties(
            baMethod, &baProperties, &nDictionarySize);
    if (propertiesStatus == FREEARC_LZMA_PROPERTIES_CODEC_UNAVAILABLE) {
        return FREEARC_DATA_CODEC_UNAVAILABLE;
    }
    if (propertiesStatus == FREEARC_LZMA_PROPERTIES_RESOURCE_LIMIT) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if (propertiesStatus != FREEARC_LZMA_PROPERTIES_VALID) {
        return FREEARC_DATA_INVALID;
    }
    Q_UNUSED(nDictionarySize)

    const qint64 nAbsoluteDataOffset = nCandidateOffset + nDataOffset;
    const QString sKey = freeArcAuthenticationKey(
        nAbsoluteDataOffset, baMethod, nOriginalSize, nCompressedSize,
        nStoredCRC);
    qint64 nExpectedCandidateOffset = -1;
    if (pScanCache->lookupExpectedCandidate(
            sKey, &nExpectedCandidateOffset) &&
        (nCandidateOffset != nExpectedCandidateOffset)) {
        return FREEARC_DATA_INVALID;
    }
    qint32 nCachedStatus = 0;
    if (pScanCache->lookup(sKey, &nCachedStatus)) {
        return static_cast<FREEARC_DATA_STATUS>(nCachedStatus);
    }
    QMap<XBinary::UNPACK_PROP, QVariant> mapMemoryProperties;
    mapMemoryProperties.insert(
        XBinary::UNPACK_PROP_MAX_OUTPUT_SIZE, SFX_FREEARC_MEMORY_LIMIT);
    qint64 nDecoderMemory = 0;
    if (!XLZMADecoder::getMemoryRequirement(
            baProperties, &nDecoderMemory, pPdStruct)) {
        return FREEARC_DATA_INVALID;
    }
    if (nOriginalSize > static_cast<quint64>(
            (std::numeric_limits<qint64>::max)() - nDecoderMemory)) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    const qint64 nCombinedMemory =
        static_cast<qint64>(nOriginalSize) + nDecoderMemory;
    XBinary::UNPACK_MEMORY_RESERVATION combinedReservation;
    if (!combinedReservation.acquire(mapMemoryProperties,
                                     nCombinedMemory)) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if (!pScanCache->charge(static_cast<qint64>(nOriginalSize))) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }

    SubDevice input(pArchive->getDevice(), nDataOffset,
                    static_cast<qint64>(nCompressedSize));
    QBuffer output;
    output.buffer().reserve(static_cast<qsizetype>(nOriginalSize));
    if (!input.open(QIODevice::ReadOnly) ||
        !output.open(QIODevice::ReadWrite)) {
        return FREEARC_DATA_INVALID;
    }

    XBinary::DATAPROCESS_STATE state = {};
    state.pDeviceInput = &input;
    state.pDeviceOutput = &output;
    state.nInputOffset = 0;
    state.nInputLimit = static_cast<qint64>(nCompressedSize);
    state.nProcessedOffset = 0;
    state.nProcessedLimit = static_cast<qint64>(nOriginalSize);
    state.mapProperties.insert(
        XBinary::FPART_PROP_UNCOMPRESSEDSIZE,
        static_cast<qint64>(nOriginalSize));
    state.mapUnpackProperties = mapMemoryProperties;

    const XLZMADecoder::DECOMPRESS_RESULT decodeResult =
        XLZMADecoder::decompressWithResult(
            &state, baProperties, pPdStruct, &combinedReservation);
    input.close();
    output.close();
    if (decodeResult == XLZMADecoder::DECOMPRESS_RESULT_RESOURCE_LIMIT) {
        return FREEARC_DATA_RESOURCE_LIMIT;
    }
    if ((decodeResult != XLZMADecoder::DECOMPRESS_RESULT_SUCCESS) ||
        !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (state.nCountInput != static_cast<qint64>(nCompressedSize)) ||
        (state.nCountOutput != static_cast<qint64>(nOriginalSize)) ||
        (output.data().size() != static_cast<qint64>(nOriginalSize))) {
        pScanCache->remember(sKey, FREEARC_DATA_INVALID);
        return FREEARC_DATA_INVALID;
    }

    const quint32 nCalculatedCRC = XBinary::_getCRC32(
        output.data().constData(), output.data().size(), 0xFFFFFFFFU,
        XBinary::_getCRC32Table_EDB88320()) ^ 0xFFFFFFFFU;
    if (nCalculatedCRC != nStoredCRC) {
        pScanCache->remember(sKey, FREEARC_DATA_INVALID);
        return FREEARC_DATA_INVALID;
    }
    if (!getExpectedFreeArcCandidateOffset(
            output.data(), nAbsoluteDataOffset,
            &nExpectedCandidateOffset)) {
        pScanCache->remember(sKey, FREEARC_DATA_INVALID);
        return FREEARC_DATA_INVALID;
    }
    pScanCache->rememberExpectedCandidate(
        sKey, nExpectedCandidateOffset);
    if (nCandidateOffset != nExpectedCandidateOffset) {
        return FREEARC_DATA_INVALID;
    }
    const FREEARC_DATA_STATUS status = validateFreeArcFooterData(
        pArchive, output.data(), nDataOffset, pPdStruct);
    pScanCache->remember(sKey, status);
    return status;
}

FREEARC_DATA_STATUS getFreeArcFinalFooterStatus(
    XFREEARC *pArchive, qint64 nCandidateOffset,
    const FREEARC_DESCRIPTOR &descriptor,
    XSFX_FREEARC_SCAN_CACHE *pScanCache,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pScanCache || (nCandidateOffset < 0) ||
        (descriptor.nType != 4) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return FREEARC_DATA_INVALID;
    }

    const qint64 nArchiveSize = pArchive->getSize();
    if ((descriptor.nOffset < 0) ||
        (descriptor.nLength != nArchiveSize - descriptor.nOffset) ||
        (descriptor.nDataOffset < 0)) {
        return FREEARC_DATA_INVALID;
    }

    FREEARC_DATA_STATUS status = FREEARC_DATA_CODEC_UNAVAILABLE;
    if (descriptor.baMethod == "storing") {
        status = authenticateFreeArcStoredData(
            pArchive, nCandidateOffset, descriptor.nDataOffset,
            descriptor.nOriginalSize, descriptor.nCompressedSize,
            descriptor.nDataCRC, pScanCache, pPdStruct);
    } else {
        status = authenticateFreeArcLzmaData(
            pArchive, nCandidateOffset, descriptor.baMethod,
            descriptor.nDataOffset, descriptor.nOriginalSize,
            descriptor.nCompressedSize, descriptor.nDataCRC,
            pScanCache, pPdStruct);
    }
    return status;
}

FREEARC_LAYOUT_STATUS getFreeArcBlockLayoutStatus(
    XFREEARC *pArchive, qint64 nCandidateOffset,
    XSFX_FREEARC_SCAN_CACHE *pScanCache,
    XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pScanCache || (nCandidateOffset < 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return FREEARC_LAYOUT_INVALID;
    }

    const qint64 nArchiveSize = pArchive->getSize();
    if ((nArchiveSize < 23) ||
        !hasAuthenticatedFreeArcHeader(pArchive, pPdStruct)) {
        return FREEARC_LAYOUT_INVALID;
    }
    const qint64 nScanSize = qMin(
        nArchiveSize, SFX_FREEARC_DESCRIPTOR_SCAN_LIMIT);
    const qint64 nScanOffset = nArchiveSize - nScanSize;
    const QByteArray baTail = pArchive->read_array_process(
        nScanOffset, nScanSize, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
        (baTail.size() != nScanSize)) {
        return FREEARC_LAYOUT_INVALID;
    }

    bool bResourceLimited = false;
    const QByteArray baSignature("ArC\x01", 4);
    int nSearchFrom = baTail.size() - baSignature.size();
    while ((nSearchFrom >= 0) &&
           XBinary::isPdStructNotCanceled(pPdStruct)) {
        const int nRelativeOffset = baTail.lastIndexOf(
            baSignature, nSearchFrom);
        if (nRelativeOffset < 0) break;

        const qint64 nDescriptorOffset = nScanOffset + nRelativeOffset;
        FREEARC_DESCRIPTOR descriptor;
        if (parseFreeArcDescriptorAt(
                pArchive, nDescriptorOffset, &descriptor, pPdStruct) &&
            (descriptor.nType == 4) &&
            (descriptor.nLength == nArchiveSize - nDescriptorOffset)) {
            const FREEARC_DATA_STATUS status =
                getFreeArcFinalFooterStatus(
                    pArchive, nCandidateOffset, descriptor, pScanCache,
                    pPdStruct);
            if (status == FREEARC_DATA_AUTHENTICATED) {
                return FREEARC_LAYOUT_AUTHENTICATED;
            }
            if (status == FREEARC_DATA_CODEC_UNAVAILABLE) {
                // Encrypted/composed control streams require backend validation
                // with the caller's password before this offset is committed.
                return FREEARC_LAYOUT_PROVISIONAL;
            }
            if (status == FREEARC_DATA_RESOURCE_LIMIT) {
                bResourceLimited = true;
            }
        }
        nSearchFrom = nRelativeOffset - 1;
    }
    return bResourceLimited ? FREEARC_LAYOUT_RESOURCE_LIMIT
                            : FREEARC_LAYOUT_INVALID;
}

bool hasZpaqBlockLayout(XZPAQ *pArchive, XBinary *pOuter,
                        qint64 nCandidateOffset,
                        XSFX_ZPAQ_SCAN_CACHE *pZpaqScanCache,
                        XBinary::PDSTRUCT *pPdStruct)
{
    if (!pArchive || !pOuter || (nCandidateOffset < 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    const qint64 nArchiveSize = pArchive->getSize();
    const qint64 nOuterSize = pOuter->getSize();
    if ((nOuterSize < 0) || (nCandidateOffset > nOuterSize) ||
        (nArchiveSize != nOuterSize - nCandidateOffset)) {
        return false;
    }
    const qint64 nBlockOffset = pArchive->getFirstBlockOffset();
    const quint16 nHeaderSize = pArchive->getHeaderSize();
    const qint64 nHeaderStart = nBlockOffset + 7;
    if ((nBlockOffset < 0) || (nHeaderSize < 7) ||
        (nHeaderStart < nBlockOffset) ||
        (nHeaderStart > nArchiveSize) ||
        (nHeaderSize > nArchiveSize - nHeaderStart)) {
        return false;
    }

    const qint64 nHeaderEnd = nHeaderStart + nHeaderSize;
    const QByteArray baPrefix = pArchive->read_array_process(
        0, nHeaderEnd, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
        (baPrefix.size() != nHeaderEnd)) {
        return false;
    }

    // Validate the COMP layout, not just the final zero byte. The first five
    // bytes are hh, hm, ph, pm, and the component count. Each component has a
    // fixed record size defined by the ZPAQ specification.
    static const quint8 anComponentSizes[] = {0, 2, 3, 2, 3, 4, 6, 6, 3, 5};
    const int nBodyStart = static_cast<int>(nHeaderStart);
    const int nBodyEnd = static_cast<int>(nHeaderEnd);
    const quint8 nLevel = static_cast<quint8>(baPrefix.at(
        static_cast<int>(nBlockOffset + 3)));
    const quint8 nComponents = static_cast<quint8>(baPrefix.at(nBodyStart + 4));
    if ((nLevel == 1) && !nComponents) return false;

    int nCursor = nBodyStart + 5;
    for (quint16 i = 0; i < nComponents; i++) {
        if (nCursor >= nBodyEnd) return false;
        const quint8 nType = static_cast<quint8>(baPrefix.at(nCursor));
        if ((nType == 0) ||
            (nType >= sizeof(anComponentSizes) / sizeof(anComponentSizes[0]))) {
            return false;
        }
        const int nComponentSize = anComponentSizes[nType];
        if ((nComponentSize <= 0) || (nComponentSize > nBodyEnd - nCursor)) {
            return false;
        }
        nCursor += nComponentSize;
    }

    // COMP and HCOMP are independently zero-terminated.
    if ((nCursor >= nBodyEnd) || (baPrefix.at(nCursor) != 0) ||
        (nCursor + 1 > nBodyEnd - 1) || (baPrefix.at(nBodyEnd - 1) != 0) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    // Parse through the end of the first block. For modeled data, four zero
    // bytes are an unambiguous arithmetic-stream terminator. Level-2 blocks
    // without components store a sequence of big-endian sized chunks ending
    // in a zero length. Requiring the segment checksum marker and final EOB
    // keeps a planted header/segment prefix from masking the real payload.
    const qint64 nScanEnd = nArchiveSize;
    qint64 nSegmentOffset = nHeaderEnd;
    bool bSeenSegment = false;
    while ((nSegmentOffset < nScanEnd) &&
           XBinary::isPdStructNotCanceled(pPdStruct)) {
        if (pArchive->read_uint8(nSegmentOffset) == 255) {
            // A block with no segments is valid (for example, an empty
            // journal), but only when that complete empty block reaches EOF.
            // Otherwise a planted 28-byte block could mask a real payload
            // beginning later in the executable overlay.
            return bSeenSegment || (nSegmentOffset + 1 == nScanEnd);
        }
        if (pArchive->read_uint8(nSegmentOffset) != 1) return false;
        bSeenSegment = true;

        const qint64 nFilenameStart = nSegmentOffset + 1;
        const qint64 nFilenameScanSize = qMin(
            nScanEnd - nFilenameStart, SFX_ZPAQ_METADATA_SCAN_LIMIT);
        const qint64 nFilenameEnd = pArchive->find_signature(
            nFilenameStart, nFilenameScanSize,
            "00", nullptr, pPdStruct);
        if ((nFilenameEnd < 0) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }
        const qint64 nCommentStart = nFilenameEnd + 1;
        const qint64 nCommentScanSize = qMin(
            nScanEnd - nCommentStart, SFX_ZPAQ_METADATA_SCAN_LIMIT);
        const qint64 nCommentEnd = pArchive->find_signature(
            nCommentStart, nCommentScanSize,
            "00", nullptr, pPdStruct);
        if ((nCommentEnd < 0) || (nCommentEnd + 1 >= nScanEnd) ||
            (pArchive->read_uint8(nCommentEnd + 1) != 0) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return false;
        }

        qint64 nDataOffset = nCommentEnd + 2;
        if (nComponents) {
            qint64 nTerminator = -1;
            if (pZpaqScanCache) {
                const qint64 nAbsoluteStart = nCandidateOffset + nDataOffset;
                const qint64 nAbsoluteEnd = nCandidateOffset + nScanEnd;
                const qint64 nAbsoluteTerminator =
                    pZpaqScanCache->findTerminator(
                        pOuter, nAbsoluteStart, nAbsoluteEnd, pPdStruct);
                if (nAbsoluteTerminator >= nCandidateOffset) {
                    nTerminator = nAbsoluteTerminator - nCandidateOffset;
                }
            } else {
                nTerminator = pArchive->find_signature(
                    nDataOffset, nScanEnd - nDataOffset,
                    "00000000", nullptr, pPdStruct);
            }
            if ((nTerminator < 0) ||
                !XBinary::isPdStructNotCanceled(pPdStruct)) {
                return false;
            }
            nDataOffset = nTerminator + 4;
        } else {
            bool bEndOfData = false;
            while ((nDataOffset <= nScanEnd - 4) &&
                   XBinary::isPdStructNotCanceled(pPdStruct)) {
                const quint32 nChunkSize = pArchive->read_uint32(
                    nDataOffset, true);
                nDataOffset += 4;
                if (!nChunkSize) {
                    bEndOfData = true;
                    break;
                }
                if (nChunkSize > static_cast<quint64>(nScanEnd - nDataOffset)) {
                    return false;
                }
                nDataOffset += nChunkSize;
            }
            if (!bEndOfData || !XBinary::isPdStructNotCanceled(pPdStruct)) {
                return false;
            }
        }

        if (nDataOffset >= nScanEnd) return false;
        const quint8 nEndMarker = pArchive->read_uint8(nDataOffset++);
        if (nEndMarker == 253) {
            if (nDataOffset > nScanEnd - 20) return false;
            nDataOffset += 20;
        } else if (nEndMarker != 254) {
            return false;
        }
        nSegmentOffset = nDataOffset;
    }

    return false;
}

bool isExternalSfxType(XSFX::ARCTYPE arcType)
{
    return (arcType == XSFX::ARC_FREEARC) ||
           (arcType == XSFX::ARC_ZPAQ);
}

XExternalArchive *externalArchiveFor(XArchive *pArchive,
                                     XSFX::ARCTYPE arcType)
{
    if (!pArchive || !isExternalSfxType(arcType)) return nullptr;
    return static_cast<XExternalArchive *>(pArchive);
}

void clearPrivateUnpackCredential(XSFX::UNPACK_CONTEXT *pContext)
{
    if (!pContext) return;
    pContext->mapPrivateUnpackProperties.remove(
        XBinary::UNPACK_PROP_PASSWORD);
    pContext->mapPrivateUnpackProperties.remove(
        XBinary::UNPACK_PROP_PASSWORD_BYTES);
    if (!pContext->sPrivatePassword.isEmpty()) {
        pContext->sPrivatePassword.detach();
        pContext->sPrivatePassword.fill(QChar::Null);
        pContext->sPrivatePassword.clear();
        pContext->sPrivatePassword.squeeze();
    }
    if (!pContext->baPrivatePassword.isEmpty()) {
        pContext->baPrivatePassword.detach();
        pContext->baPrivatePassword.fill('\0');
        pContext->baPrivatePassword.clear();
        pContext->baPrivatePassword.squeeze();
    }
}

void initializePrivateUnpackProperties(
    XSFX::UNPACK_CONTEXT *pContext,
    const QMap<XBinary::UNPACK_PROP, QVariant> &mapProperties,
    bool bKeepCredential)
{
    if (!pContext) return;
    clearPrivateUnpackCredential(pContext);
    pContext->mapPrivateUnpackProperties = mapProperties;
    pContext->mapPrivateUnpackProperties.remove(
        XBinary::UNPACK_PROP_PASSWORD);
    pContext->mapPrivateUnpackProperties.remove(
        XBinary::UNPACK_PROP_PASSWORD_BYTES);
    if (!bKeepCredential) return;

    pContext->sPrivatePassword =
        mapProperties.value(XBinary::UNPACK_PROP_PASSWORD).toString();
    pContext->sPrivatePassword.detach();
    pContext->baPrivatePassword =
        mapProperties.value(XBinary::UNPACK_PROP_PASSWORD_BYTES).toByteArray();
    pContext->baPrivatePassword.detach();
}

QMap<XBinary::UNPACK_PROP, QVariant> privateUnpackProperties(
    const XSFX::UNPACK_CONTEXT *pContext)
{
    QMap<XBinary::UNPACK_PROP, QVariant> result;
    if (!pContext) return result;
    result = pContext->mapPrivateUnpackProperties;
    if (!pContext->baPrivatePassword.isEmpty()) {
        result.insert(XBinary::UNPACK_PROP_PASSWORD_BYTES,
                      pContext->baPrivatePassword);
    } else if (!pContext->sPrivatePassword.isEmpty()) {
        result.insert(XBinary::UNPACK_PROP_PASSWORD,
                      pContext->sPrivatePassword);
    }
    return result;
}

void scrubPublicUnpackProperties(
    QMap<XBinary::UNPACK_PROP, QVariant> *pProperties)
{
    if (!pProperties) return;
    pProperties->remove(XBinary::UNPACK_PROP_PASSWORD);
    pProperties->remove(XBinary::UNPACK_PROP_PASSWORD_BYTES);
}

}  // namespace

XSFX::UNPACK_DEFERRED_CLEANUP::~UNPACK_DEFERRED_CLEANUP()
{
    const QSet<UNPACK_CONTEXT *> contexts = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : contexts) {
        clearPrivateUnpackCredential(pContext);
        if (pContext->pArchive) {
            pContext->pArchive->finishUnpack(&pContext->innerState, nullptr);
            delete pContext->pArchive;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
        }
        delete pContext;
    }
}

XSFX::XSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress)
    : XSFX(pDevice, bIsImage, nModuleAddress, ARC_UNKNOWN)
{
}

XSFX::XSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress,
           ARCTYPE requiredArcType)
    : XBinary(pDevice, bIsImage, nModuleAddress),
      m_requiredArcType(requiredArcType)
{
    m_pUnpackDeferredCleanup = QSharedPointer<UNPACK_DEFERRED_CLEANUP>::create();
    const QSharedPointer<UNPACK_DEFERRED_CLEANUP> pDeferredCleanup = m_pUnpackDeferredCleanup;
    m_pUnpackOperationState = QSharedPointer<bool>(new bool(false), [pDeferredCleanup](bool *pValue) { delete pValue; });
    m_internalInfo = INTERNAL_INFO();
    setIsArchive(true);
}

XSFX::~XSFX()
{
    if (m_pUnpackOperationState) *m_pUnpackOperationState = true;
    if (m_pUnpackDeferredCleanup) {
        m_pUnpackDeferredCleanup->setContexts.unite(m_setUnpackContexts);
        m_setUnpackContexts.clear();
    }
    m_pUnpackDeferredCleanup.clear();
    m_pUnpackOperationState.clear();
}

bool XSFX::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XSFX> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XSFX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSFX sfx(pDevice);
    return sfx.isValid(pPdStruct);
}

XSFX::INTERNAL_INFO XSFX::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XSFX::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XSFX> guardedThis(this);
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
        if (info.bResourceIndeterminate) {
            // Resource reservations are transient. Leave the internal-info
            // transaction uncommitted so a later caller can retry detection.
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

void *XSFX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XSFX> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XSFX::setInternalInfo(void *pInternalInfo)
{
    if (pInternalInfo) {
        const INTERNAL_INFO info =
            *static_cast<INTERNAL_INFO *>(pInternalInfo);
        if ((m_requiredArcType != ARC_UNKNOWN) && info.bIsValid &&
            (info.arcType != m_requiredArcType)) {
            m_internalInfo = INTERNAL_INFO();
            setIsInternalInfoHandled(false);
            XBinary::setInternalInfo(nullptr);
            return;
        }
        m_internalInfo = info;
        setIsInternalInfoHandled(true);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    } else {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(false);
        XBinary::setInternalInfo(nullptr);
    }
}

XBinary::FT XSFX::getFileType()
{
    ARCTYPE arcType = m_requiredArcType;
    if ((arcType == ARC_UNKNOWN) && m_internalInfo.bIsValid) {
        arcType = m_internalInfo.arcType;
    }

    XPE pe(getDevice());

    if (pe.isValid()) {
        const bool b64 = pe.is64();
        switch (arcType) {
            case ARC_ZIP: return b64 ? FT_PE64_ZIPSFX : FT_PE32_ZIPSFX;
            case ARC_RAR: return b64 ? FT_PE64_RARSFX : FT_PE32_RARSFX;
            case ARC_CAB: return b64 ? FT_PE64_CABSFX : FT_PE32_CABSFX;
            case ARC_FREEARC: return b64 ? FT_PE64_FREEARCSFX : FT_PE32_FREEARCSFX;
            case ARC_ZPAQ: return b64 ? FT_PE64_ZPAQSFX : FT_PE32_ZPAQSFX;
            default: return b64 ? FT_PE64_SFX : FT_PE32_SFX;
        }
    }

    XELF elf(getDevice(), isImage(), getModuleAddress());
    if (elf.isValid()) {
        const bool b64 = elf.is64();
        switch (arcType) {
            case ARC_ZIP: return b64 ? FT_ELF64_ZIPSFX : FT_ELF32_ZIPSFX;
            case ARC_RAR: return b64 ? FT_ELF64_RARSFX : FT_ELF32_RARSFX;
            case ARC_CAB: return b64 ? FT_ELF64_CABSFX : FT_ELF32_CABSFX;
            case ARC_FREEARC: return b64 ? FT_ELF64_FREEARCSFX : FT_ELF32_FREEARCSFX;
            case ARC_ZPAQ: return b64 ? FT_ELF64_ZPAQSFX : FT_ELF32_ZPAQSFX;
            default: return b64 ? FT_ELF64_SFX : FT_ELF32_SFX;
        }
    }

    switch (arcType) {
        case ARC_ZIP: return FT_PE32_ZIPSFX;
        case ARC_RAR: return FT_PE32_RARSFX;
        case ARC_CAB: return FT_PE32_CABSFX;
        case ARC_FREEARC: return FT_PE32_FREEARCSFX;
        case ARC_ZPAQ: return FT_PE32_ZPAQSFX;
        default: break;
    }

    return FT_PE32_SFX;
}

QString XSFX::getArch()
{
    XMSDOS msdos(getDevice(), isImage(), getModuleAddress());
    if (msdos.isValid()) {
        return msdos.getArch();
    }
    XELF elf(getDevice(), isImage(), getModuleAddress());
    if (elf.isValid()) return elf.getArch();
    return QString();
}

XBinary::MODE XSFX::getMode()
{
    return MODE_DATA;
}

QString XSFX::getMIMEString()
{
    return "application/x-sfx";
}

bool XSFX::_matchArchiveAt(qint64 nOffset, qint64 nSize, ARCTYPE *pType,
                           qint64 *pArchiveSize, PDSTRUCT *pPdStruct,
                           XSFX_ZPAQ_SCAN_CACHE *pZpaqScanCache,
                           XSFX_FREEARC_SCAN_CACHE *pFreeArcScanCache,
                           bool *pbProvisional,
                           bool *pbResourceIndeterminate,
                           bool *pbUseOuterDevice)
{
    if (pbProvisional) *pbProvisional = false;
    if (pbResourceIndeterminate) *pbResourceIndeterminate = false;
    if (pbUseOuterDevice) *pbUseOuterDevice = false;
    const qint64 nTotalSize = getSize();
    if (!pType || !pArchiveSize || !pFreeArcScanCache ||
        !pbProvisional || !pbResourceIndeterminate || !pbUseOuterDevice ||
        (nOffset < 0) || (nSize < 8) || (nOffset > nTotalSize) ||
        (nSize > nTotalSize - nOffset) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    QByteArray baMagic = read_array_process(nOffset, qMin(nSize, (qint64)16), pPdStruct);
    if (baMagic.size() < 6) {
        return false;
    }
    const quint8 *p = (const quint8 *)baMagic.constData();

    ARCTYPE candidate = ARC_UNKNOWN;

    if ((p[0] == 0x37) && (p[1] == 0x7A) && (p[2] == 0xBC) && (p[3] == 0xAF) && (p[4] == 0x27) && (p[5] == 0x1C)) {
        candidate = ARC_7Z;  // '7z' BC AF 27 1C
    } else if ((p[0] == 0x50) && (p[1] == 0x4B) &&
               (((p[2] == 0x03) && (p[3] == 0x04)) ||
                ((p[2] == 0x05) && (p[3] == 0x06)))) {
        candidate = ARC_ZIP;  // local header or empty archive EOCD
    } else if ((p[0] == 0x52) && (p[1] == 0x61) && (p[2] == 0x72) && (p[3] == 0x21) && (p[4] == 0x1A) && (p[5] == 0x07)) {
        candidate = ARC_RAR;  // 'Rar!' 1A 07 (RAR4/RAR5)
    } else if ((p[0] == 0x52) && (p[1] == 0x45) && (p[2] == 0x7E) && (p[3] == 0x5E)) {
        candidate = ARC_RAR;  // 'RE~^' (RAR1.4)
    } else if ((p[0] == 0x4D) && (p[1] == 0x53) && (p[2] == 0x43) && (p[3] == 0x46)) {
        candidate = ARC_CAB;  // 'MSCF'
    } else if ((baMagic.size() >= 13) &&
               (p[0] == 0x41) && (p[1] == 0x72) && (p[2] == 0x43) && (p[3] == 0x01) &&
               (p[8] == 0x41) && (p[9] == 0x72) && (p[10] == 0x43) && (p[11] == 0x01) &&
               (p[12] == 0x02)) {
        // Header followed by the first data block. A single ArC\x01 is common
        // inside the executable stubs and is deliberately not enough.
        candidate = ARC_FREEARC;
    } else if ((baMagic.size() >= 16) &&
               (p[0] == 0x37) && (p[1] == 0x6B) && (p[2] == 0x53) && (p[3] == 0x74) &&
               (p[4] == 0xA0) && (p[5] == 0x31) && (p[6] == 0x83) && (p[7] == 0xD3) &&
               (p[8] == 0x8C) && (p[9] == 0xB2) && (p[10] == 0x28) && (p[11] == 0xB0) &&
               (p[12] == 0xD3) && (p[13] == 0x7A) && (p[14] == 0x50) && (p[15] == 0x51)) {
        candidate = ARC_ZPAQ;  // 13-byte locator tag followed by 'zPQ'
    } else if ((p[0] == 0x7A) && (p[1] == 0x50) && (p[2] == 0x51)) {
        // Untagged zPQ is accepted only when the caller checks the exact
        // executable boundary. It is never one of the fallback scan patterns.
        candidate = ARC_ZPAQ;
    } else {
        return false;
    }

    if ((m_requiredArcType != ARC_UNKNOWN) &&
        (candidate != m_requiredArcType)) {
        return false;
    }

    if (candidate == ARC_FREEARC) {
        const qint64 nMethodSize = qMin(nSize - 13, (qint64)256);
        if ((nMethodSize <= 0) ||
            !hasFreeArcMethod(read_array_process(nOffset + 13, nMethodSize, pPdStruct))) {
            return false;
        }
    }

    // Confirm the candidate really is a valid archive at that offset.
    SubDevice sub(getDevice(), nOffset, nSize);
    if (!sub.open(QIODevice::ReadOnly)) {
        return false;
    }

    bool bValid = false;
    qint64 nLogicalSize = 0;
    XArchive *pArc = _createArchive(candidate, &sub);
    if (pArc) {
        if (candidate == ARC_FREEARC) {
            // Format probing must remain structural: archive initialization now
            // publishes only helper metadata, while the first member extraction
            // authenticates and stages the payload through the external adapter.
            XFREEARC *pFreeArc = static_cast<XFREEARC *>(pArc);
            FREEARC_LAYOUT_STATUS layoutStatus = FREEARC_LAYOUT_INVALID;
            if (pFreeArc->isValid(pPdStruct)) {
                layoutStatus = getFreeArcBlockLayoutStatus(
                    pFreeArc, nOffset, pFreeArcScanCache, pPdStruct);
            }
            bValid = (layoutStatus == FREEARC_LAYOUT_AUTHENTICATED) ||
                     (layoutStatus == FREEARC_LAYOUT_PROVISIONAL);
            *pbProvisional =
                (layoutStatus == FREEARC_LAYOUT_PROVISIONAL);
            *pbResourceIndeterminate =
                (layoutStatus == FREEARC_LAYOUT_RESOURCE_LIMIT);
            nLogicalSize = bValid ? nSize : 0;
        } else if (candidate == ARC_ZPAQ) {
            XZPAQ *pZpaq = static_cast<XZPAQ *>(pArc);
            bValid = pZpaq->isValid(pPdStruct) &&
                       hasZpaqBlockLayout(pZpaq, this, nOffset,
                                          pZpaqScanCache, pPdStruct);
            // Local parsing proves the first block's framing but deliberately
            // does not decompress/authenticate its data. If first extraction
            // rejects it, unpackCurrent may select a later manifest-equivalent
            // same-family candidate without exposing partial caller output.
            *pbProvisional = bValid;
            nLogicalSize = bValid ? nSize : 0;
        } else {
            UNPACK_STATE state = {};
            QMap<UNPACK_PROP, QVariant> properties;
            bValid = pArc->initUnpack(&state, properties, pPdStruct);
            if (bValid) {
                bValid = pArc->finishUnpack(&state, pPdStruct);
            } else if ((candidate == ARC_7Z) && XBinary::isPdStructNotCanceled(pPdStruct)) {
                // Preserve detection of password-protected encoded headers while
                // still requiring a structurally parsed encrypted stream map.
                XSevenZip *pSevenZip = static_cast<XSevenZip *>(pArc);
                bValid = pSevenZip->isValid(pPdStruct) && pSevenZip->isEncrypted();
            }
            if (bValid) nLogicalSize = pArc->getFileFormatSize(pPdStruct);
        }
        delete pArc;
    }
    sub.close();

    // Some ZIP SFX writers store central-directory and local-header offsets
    // as absolute offsets in the outer executable. Such archives cannot be
    // parsed through a rebased SubDevice. Validate them on the complete input,
    // then require the first authenticated local record (or an empty EOCD) to
    // begin at this exact overlay candidate before delegating extraction to the
    // same whole-device XZip view.
    if (!bValid && (candidate == ARC_ZIP) &&
        XBinary::isPdStructNotCanceled(pPdStruct)) {
        XZip outerZip(getDevice());
        const qint64 nECDOffset = outerZip.findECDOffset(pPdStruct);
        bool bStartsAtCandidate = false;
        if (nECDOffset >= 0) {
            const quint16 nRecords = outerZip.read_uint16(
                nECDOffset + offsetof(
                    XZip::ENDOFCENTRALDIRECTORYRECORD,
                    nTotalNumberOfRecords));
            if (nRecords == 0) {
                bStartsAtCandidate = (nECDOffset == nOffset);
            } else {
                qint64 nCentralOffset = outerZip.read_uint32(
                    nECDOffset + offsetof(
                        XZip::ENDOFCENTRALDIRECTORYRECORD,
                        nOffsetToCentralDirectory));
                qint64 nFirstLocalOffset =
                    (std::numeric_limits<qint64>::max)();
                bool bCentralValid = true;
                for (quint32 i = 0; i < nRecords; ++i) {
                    if ((nCentralOffset < 0) ||
                        ((nECDOffset - nCentralOffset) <
                         (qint64)sizeof(XZip::CENTRALDIRECTORYFILEHEADER))) {
                        bCentralValid = false;
                        break;
                    }
                    const XZip::CENTRALDIRECTORYFILEHEADER header =
                        outerZip.read_CENTRALDIRECTORYFILEHEADER(
                            nCentralOffset, pPdStruct);
                    if (header.nSignature != XZip::SIGNATURE_CFD) {
                        bCentralValid = false;
                        break;
                    }
                    nFirstLocalOffset = qMin(
                        nFirstLocalOffset,
                        (qint64)header.nOffsetToLocalFileHeader);
                    const qint64 nRecordSize =
                        sizeof(XZip::CENTRALDIRECTORYFILEHEADER) +
                        (qint64)header.nFileNameLength +
                        (qint64)header.nExtraFieldLength +
                        (qint64)header.nFileCommentLength;
                    if ((nRecordSize <= 0) ||
                        (nRecordSize > nECDOffset - nCentralOffset)) {
                        bCentralValid = false;
                        break;
                    }
                    nCentralOffset += nRecordSize;
                }
                bStartsAtCandidate = bCentralValid &&
                    (nFirstLocalOffset == nOffset);
            }
        }

        if (bStartsAtCandidate) {
            UNPACK_STATE state = {};
            QMap<UNPACK_PROP, QVariant> properties;
            bValid = outerZip.initUnpack(&state, properties, pPdStruct);
            if (bValid) {
                bValid = outerZip.finishUnpack(&state, pPdStruct);
            }
            const qint64 nOuterLogicalSize = bValid
                ? outerZip.getFileFormatSize(pPdStruct) : 0;
            if (bValid && (nOuterLogicalSize > nOffset) &&
                (nOuterLogicalSize <= nTotalSize)) {
                nLogicalSize = nOuterLogicalSize - nOffset;
                *pbUseOuterDevice = true;
            } else {
                bValid = false;
            }
        }
    }

    if (bValid && (nLogicalSize > 0) && (nLogicalSize <= nSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        *pType = candidate;
        *pArchiveSize = nLogicalSize;
        return true;
    }

    return false;
}

XSFX::INTERNAL_INFO XSFX::_detect(PDSTRUCT *pPdStruct,
                                  XSFX_ZPAQ_SCAN_CACHE *pZpaqScanCache,
                                  XSFX_FREEARC_SCAN_CACHE *pFreeArcScanCache,
                                  qint64 nMinimumArchiveOffset)
{
    INTERNAL_INFO result = {};
    result.arcType = ARC_UNKNOWN;

    const qint64 nTotalSize = getSize();
    if (nTotalSize < 0x40) {
        return result;
    }

    XSFX_ZPAQ_SCAN_CACHE localZpaqScanCache;
    if (!pZpaqScanCache) pZpaqScanCache = &localZpaqScanCache;
    pZpaqScanCache->bind(getDevice(), nTotalSize);
    XSFX_FREEARC_SCAN_CACHE localFreeArcScanCache;
    if (!pFreeArcScanCache) pFreeArcScanCache = &localFreeArcScanCache;
    pFreeArcScanCache->bind(getDevice(), nTotalSize);

    // Must be an executable stub. A bare archive is handled by its own class.
    XMSDOS msdos(getDevice(), isImage(), getModuleAddress());
    const bool bMSDOS = msdos.isValid(pPdStruct);
    XELF elf(getDevice(), isImage(), getModuleAddress());
    const bool bELF = elf.isValid(pPdStruct);
    if (!bMSDOS && !bELF) {
        return result;
    }

    // 1) Preferred: the archive sits in the executable overlay.  XSFX itself
    // has XBinary's flat memory map, whose raw extent is the whole input, so
    // asking `this` for the overlay always returned EOF.  Use the parsed stub
    // map instead.
    qint64 nOverlayOffset = -1;
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (pe.isValid(pPdStruct)) {
        nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    } else if (bELF) {
        nOverlayOffset = getExactELFExtent(&elf, nTotalSize);
    } else if (bMSDOS) {
        nOverlayOffset = msdos.getOverlayOffset(pPdStruct);
    }

    // Current zpaqfranz SFX files place an encoded extraction command between
    // two fixed tags at the PE overlay boundary. Derive the authoritative
    // payload boundary from that framing before signature scanning: encrypted
    // payloads are intentionally opaque, while untagged plaintext archives
    // begin with raw zPQ and otherwise risk being carved from a later block.
    qint64 nFramedZpaqOffset = -1;
    qint64 nFramedZpaqSize = 0;
    if (((m_requiredArcType == ARC_UNKNOWN) ||
         (m_requiredArcType == ARC_ZPAQ)) &&
        getZpaqFranzSfxPayload(
            this, nOverlayOffset, &nFramedZpaqOffset,
            &nFramedZpaqSize, pPdStruct) &&
        ((nMinimumArchiveOffset < 0) ||
         (nFramedZpaqOffset >= nMinimumArchiveOffset))) {
        ARCTYPE type = ARC_UNKNOWN;
        qint64 nArchiveSize = 0;
        bool bProvisional = false;
        bool bResourceIndeterminate = false;
        bool bUseOuterDevice = false;
        if (_matchArchiveAt(
                nFramedZpaqOffset, nFramedZpaqSize, &type,
                &nArchiveSize, pPdStruct, pZpaqScanCache,
                pFreeArcScanCache, &bProvisional,
                &bResourceIndeterminate, &bUseOuterDevice)) {
            if (type != ARC_ZPAQ) return result;
            result.bIsValid = true;
            result.bProvisional = bProvisional;
            result.arcType = type;
            result.bUseOuterDevice = bUseOuterDevice;
            result.nArchiveOffset = nFramedZpaqOffset;
            result.nArchiveSize = nArchiveSize;
            return result;
        }
        if (bResourceIndeterminate) {
            result.bResourceIndeterminate = true;
            return result;
        }
        if (!isPdStructNotCanceled(pPdStruct)) return result;

        const QByteArray baPrefix = read_array_process(
            nFramedZpaqOffset, qMin<qint64>(nFramedZpaqSize, 16),
            pPdStruct);
        if (!isPdStructNotCanceled(pPdStruct) ||
            resemblesPlainZpaqPrefix(baPrefix)) {
            // Do not reinterpret a damaged plaintext stream as encryption.
            return result;
        }

        result.bIsValid = true;
        result.bProvisional = true;
        result.bAllowOpaqueZpaq = true;
        result.arcType = ARC_ZPAQ;
        result.bUseOuterDevice = false;
        result.nArchiveOffset = nFramedZpaqOffset;
        result.nArchiveSize = nFramedZpaqSize;
        return result;
    }

    qint64 nTestedOverlayOffset = -1;
    if ((nOverlayOffset > 0) && (nOverlayOffset < nTotalSize) &&
        ((nMinimumArchiveOffset < 0) ||
         (nOverlayOffset >= nMinimumArchiveOffset))) {
        nTestedOverlayOffset = nOverlayOffset;
        ARCTYPE type = ARC_UNKNOWN;
        qint64 nArchiveSize = 0;
        bool bProvisional = false;
        bool bResourceIndeterminate = false;
        bool bUseOuterDevice = false;
        if (_matchArchiveAt(nOverlayOffset, nTotalSize - nOverlayOffset,
                            &type, &nArchiveSize, pPdStruct,
                            pZpaqScanCache, pFreeArcScanCache,
                            &bProvisional,
                            &bResourceIndeterminate,
                            &bUseOuterDevice)) {
            result.bIsValid = true;
            result.bProvisional = bProvisional;
            result.arcType = type;
            result.bUseOuterDevice = bUseOuterDevice;
            result.nArchiveOffset = nOverlayOffset;
            result.nArchiveSize = nArchiveSize;
            return result;
        }
        if (bResourceIndeterminate) {
            result.bResourceIndeterminate = true;
            return result;
        }
    }

    // 2) Fallback: scan only the executable overlay. Searching mapped PE
    // sections classified ordinary programs containing CAB resources as SFXs.
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nTotalSize)) return result;

    const char *apszSignatures[] = {
        "377ABCAF271C", "504B0304", "504B0506", "52617221",
        "52457E5E", "4D534346",
        "41724301........4172430102",  // FreeArc header + first data block
        "376B5374A03183D38CB228B0D37A5051"};  // full ZPAQ locator
    const qint64 nScanEnd = nOverlayOffset +
        qMin(nTotalSize - nOverlayOffset, SFX_OVERLAY_SCAN_LIMIT);
    const qint64 nScanStart = qMax(
        nOverlayOffset,
        (nMinimumArchiveOffset < 0)
            ? nOverlayOffset : nMinimumArchiveOffset);
    if (nScanStart >= nScanEnd) return result;
    const qint64 nScanSize = nScanEnd - nScanStart;
    const int nSignatureCount = sizeof(apszSignatures) / sizeof(apszSignatures[0]);
    qint64 anNextCandidate[nSignatureCount];
    qint32 anCandidateCounts[nSignatureCount] = {};
    for (int i = 0; i < nSignatureCount; i++) {
        anNextCandidate[i] = find_signature(nScanStart, nScanSize,
                                            apszSignatures[i], nullptr,
                                            pPdStruct);
    }

    // Examine signatures by file offset, not by format family. Otherwise a
    // later embedded archive or a run of one-family decoys can hide the real,
    // earlier payload of another type.
    while (isPdStructNotCanceled(pPdStruct)) {
        qint64 nPos = -1;
        for (int i = 0; i < nSignatureCount; i++) {
            if ((anNextCandidate[i] >= 0) &&
                ((nPos == -1) || (anNextCandidate[i] < nPos))) {
                nPos = anNextCandidate[i];
            }
        }
        if ((nPos < nScanStart) || (nPos >= nScanEnd)) break;

        ARCTYPE type = ARC_UNKNOWN;
        qint64 nArchiveSize = 0;
        bool bProvisional = false;
        bool bResourceIndeterminate = false;
        bool bUseOuterDevice = false;
        if ((nPos != nTestedOverlayOffset) &&
            _matchArchiveAt(nPos, nTotalSize - nPos, &type, &nArchiveSize,
                            pPdStruct, pZpaqScanCache,
                            pFreeArcScanCache, &bProvisional,
                            &bResourceIndeterminate,
                            &bUseOuterDevice)) {
            result.bIsValid = true;
            result.bProvisional = bProvisional;
            result.arcType = type;
            result.bUseOuterDevice = bUseOuterDevice;
            result.nArchiveOffset = nPos;
            result.nArchiveSize = nArchiveSize;
            return result;
        }
        if (bResourceIndeterminate) {
            result.bResourceIndeterminate = true;
            return result;
        }

        const qint64 nNextStart = nPos + 1;
        for (int i = 0; i < nSignatureCount; i++) {
            if (anNextCandidate[i] == nPos) {
                anCandidateCounts[i]++;
                anNextCandidate[i] =
                    ((anCandidateCounts[i] < SFX_SIGNATURE_CANDIDATE_LIMIT) &&
                     (nNextStart < nScanEnd))
                    ? find_signature(nNextStart, nScanEnd - nNextStart,
                                     apszSignatures[i], nullptr, pPdStruct)
                    : -1;
            }
        }
    }

    if (!isPdStructNotCanceled(pPdStruct)) {
        INTERNAL_INFO canceledResult = {};
        canceledResult.arcType = ARC_UNKNOWN;
        return canceledResult;
    }
    return result;
}

XArchive *XSFX::_createArchive(ARCTYPE arcType, QIODevice *pDevice,
                               bool bAllowOpaqueZpaq)
{
    switch (arcType) {
        case ARC_7Z: return new XSevenZip(pDevice);
        case ARC_ZIP: return new XZip(pDevice);
        case ARC_RAR: return new XRar(pDevice);
        case ARC_CAB: return new XCab(pDevice);
        case ARC_FREEARC: return new XFREEARC(pDevice);
        case ARC_ZPAQ: {
            XZPAQ *pZpaq = new XZPAQ(pDevice);
            pZpaq->setAllowOpaqueEncrypted(bAllowOpaqueZpaq);
            return pZpaq;
        }
        default: return nullptr;
    }
}

QMap<XBinary::UNPACK_PROP, QVariant> XSFX::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    QIODevice *pDevice = getDevice();

    if (pDevice) {
        INTERNAL_INFO info = _detect(nullptr);

        if (info.bIsValid && (info.nArchiveOffset >= 0) && (info.nArchiveSize > 0)) {
            SubDevice subDevice(pDevice, info.nArchiveOffset, info.nArchiveSize);
            QIODevice *pArchiveDevice = info.bUseOuterDevice
                ? pDevice : static_cast<QIODevice *>(&subDevice);
            const bool bDeviceReady = info.bUseOuterDevice
                ? (pDevice->isOpen() && pDevice->isReadable())
                : subDevice.open(QIODevice::ReadOnly);

            if (bDeviceReady) {
                XArchive *pArchive = _createArchive(
                    info.arcType, pArchiveDevice, info.bAllowOpaqueZpaq);

                if (pArchive) {
                    QMap<UNPACK_PROP, QVariant> mapInnerProperties = pArchive->getDefaultUnpackProperties();

                    if (mapInnerProperties.contains(UNPACK_PROP_PASSWORD)) {
                        result.insert(UNPACK_PROP_PASSWORD, mapInnerProperties.value(UNPACK_PROP_PASSWORD));
                    }

                    for (QMap<UNPACK_PROP, QVariant>::const_iterator it = mapInnerProperties.constBegin(); it != mapInnerProperties.constEnd(); ++it) {
                        if (XBinary::isUnpackCRCProperty(it.key())) {
                            result.insert(it.key(), it.value());
                        }
                    }

                    delete pArchive;
                }

                if (!info.bUseOuterDevice) subDevice.close();
            }
        }
    }

    return result;
}

bool XSFX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) pPdStruct = &pdStructEmpty;
    qint64 nOutputLimit = -1;
    if (!getUnpackOutputLimit(mapProperties, &nOutputLimit)) return false;
    Q_UNUSED(nOutputLimit)
    // Register the caller's operation budget before structural probing. The
    // FreeArc probes use a stricter internal ceiling, and the shared reservation
    // tracker clamps those nested allocations to this active caller limit too.
    UNPACK_MEMORY_RESERVATION operationMemoryBudget;
    if (!operationMemoryBudget.acquire(mapProperties, 0)) return false;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    if (!pState->baUnpackSourceToken.isEmpty()) return false;
    if (pState->pContext) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!m_setUnpackContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState)) return false;
        m_setUnpackContexts.remove(pOldContext);
        pState->pContext = nullptr;
        bool bFinishOK = true;
        clearPrivateUnpackCredential(pOldContext);
        if (pOldContext->pArchive) {
            bFinishOK = pOldContext->pArchive->finishUnpack(&pOldContext->innerState, nullptr);
            delete pOldContext->pArchive;
        }
        if (pOldContext->pSubDevice) {
            pOldContext->pSubDevice->close();
            delete pOldContext->pSubDevice;
        }
        delete pOldContext;
        *pState = UNPACK_STATE();
        if (!guardedThis || !bFinishOK) return false;
    }
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
    pState->mapUnpackProperties = mapProperties;
    scrubPublicUnpackProperties(&pState->mapUnpackProperties);

    QPointer<QIODevice> guardedSource(getDevice());
    if (!guardedSource) return false;
    const qint64 nTotalSize = guardedSource->size();
    if (!guardedThis || !guardedSource || (nTotalSize < 0)) return false;

    XSFX detector(guardedSource.data(), isImage(), getModuleAddress(),
                  m_requiredArcType);
    const QString sInitialError =
        XBinary::getPdStructErrorString(pPdStruct);
    QString sLastCandidateError;
    qint64 nMinimumArchiveOffset = -1;
    ARCTYPE retryType = ARC_UNKNOWN;
    UNPACK_CONTEXT *pContext = nullptr;
    XSFX_ZPAQ_SCAN_CACHE zpaqScanCache;
    XSFX_FREEARC_SCAN_CACHE freeArcScanCache;
    const QDeadlineTimer helperDeadline =
        XExternalArchive::createHelperDeadline();

    for (qint32 nAttempt = 0;
         (nAttempt < SFX_SIGNATURE_CANDIDATE_LIMIT) &&
         XBinary::isPdStructNotCanceled(pPdStruct);
         nAttempt++) {
        const INTERNAL_INFO info = detector._detect(
            pPdStruct, &zpaqScanCache, &freeArcScanCache,
            nMinimumArchiveOffset);
        if (!guardedThis || !guardedSource || !info.bIsValid) break;

        if ((retryType != ARC_UNKNOWN) && (info.arcType != retryType)) {
            if (info.nArchiveOffset >=
                (std::numeric_limits<qint64>::max)()) break;
            nMinimumArchiveOffset = info.nArchiveOffset + 1;
            continue;
        }

        pContext = new UNPACK_CONTEXT;
        pContext->pOuterSourceDevice = guardedSource;
        pContext->nOwnerDeviceGeneration = getDeviceGeneration();
        pContext->info = info;
        pContext->pSubDevice = nullptr;
        pContext->pArchive = nullptr;
        pContext->innerState = UNPACK_STATE();
        if (info.bProvisional && isExternalSfxType(info.arcType)) {
            initializePrivateUnpackProperties(
                pContext, mapProperties, true);
        }

        bool bInitialized = guardedThis && guardedSource;
        QIODevice *pArchiveDevice = guardedSource.data();
        if (!info.bUseOuterDevice) {
            pContext->pSubDevice = new SubDevice(
                guardedSource.data(), info.nArchiveOffset,
                info.nArchiveSize);
            bInitialized = pContext->pSubDevice->open(QIODevice::ReadOnly) &&
                           guardedThis && guardedSource;
            pArchiveDevice = pContext->pSubDevice;
        }
        XExternalArchive *pExternalArchive = nullptr;
        if (bInitialized) {
            pContext->pArchive = _createArchive(
                info.arcType, pArchiveDevice,
                info.bAllowOpaqueZpaq);
            pExternalArchive = externalArchiveFor(
                pContext->pArchive, info.arcType);
            if (pExternalArchive)
                pExternalArchive->setHelperDeadline(helperDeadline);
            bInitialized = pContext->pArchive &&
                pContext->pArchive->initUnpack(
                    &pContext->innerState, mapProperties, pPdStruct) &&
                guardedThis && guardedSource;
        }
        XExternalArchive::EXTERNAL_FAILURE externalFailure =
            XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        if (pExternalArchive) {
            externalFailure = pExternalArchive->getLastExternalFailure();
            pExternalArchive->clearHelperDeadline();
        }
        if (bInitialized) {
            if (pExternalArchive &&
                pExternalArchive->isDeferredArchiveMaterialized(
                    &pContext->innerState)) {
                clearPrivateUnpackCredential(pContext);
            }
            break;
        }

        clearPrivateUnpackCredential(pContext);
        if (pContext->pArchive) {
            pContext->pArchive->finishUnpack(
                &pContext->innerState, nullptr);
            delete pContext->pArchive;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
        }
        delete pContext;
        pContext = nullptr;

        const QString sCandidateError =
            XBinary::getPdStructErrorString(pPdStruct);
        if (!info.bProvisional || !isExternalSfxType(info.arcType) ||
            (externalFailure !=
             XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED) ||
            !guardedThis ||
            !guardedSource ||
            (info.nArchiveOffset >=
             (std::numeric_limits<qint64>::max)())) {
            break;
        }

        // Only an authoritative archive rejection may advance to the next
        // same-family signature. Operational failures (timeout, cancellation,
        // policy, launch/containment, or password) stop immediately, and all
        // attempts share the single deadline created above.
        sLastCandidateError = sCandidateError;
        XBinary::setPdStructErrorString(pPdStruct, sInitialError);
        retryType = info.arcType;
        nMinimumArchiveOffset = info.nArchiveOffset + 1;
    }

    if (!pContext) {
        if ((XBinary::getPdStructErrorString(pPdStruct) == sInitialError) &&
            !sLastCandidateError.isEmpty()) {
            XBinary::setPdStructErrorString(
                pPdStruct, sLastCandidateError);
        }
        return false;
    }

    pState->nNumberOfRecords = pContext->innerState.nNumberOfRecords;
    pState->nTotalSize = nTotalSize;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;
    pContext->pOwnerState = pState;
    pState->pContext = pContext;
    m_setUnpackContexts.insert(pContext);

    return true;
}

XBinary::ARCHIVERECORD XSFX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return result;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);

    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return result;
    }

    result = pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return ARCHIVERECORD();
    return result;
}

bool XSFX::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) pPdStruct = &pdStructEmpty;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    QPointer<QIODevice> guardedSource(getDevice());
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !guardedOutput || !guardedSource || !guardedOutput->isOpen() ||
        !guardedOutput->isWritable() || guardedOutput->isSequential() || !guardedThis || !guardedOutput ||
        (guardedOutput->openMode() & (QIODevice::Append | QIODevice::Text)) ||
        !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return false;
    }

    // XFU-015: thread the operation output budget into the inner archive's
    // state; the inner unpackCurrent performs its own entry accounting and
    // produced-byte debits (for the deferred route this charges production
    // into the private stage, so publishStage must not debit the copy).
    pContext->innerState.spOutputBudget = pState->spOutputBudget;

    const bool bDeferredCandidate = pContext->info.bProvisional &&
        ((pContext->info.arcType == ARC_ZPAQ) ||
         (pContext->info.arcType == ARC_FREEARC));
    if (!bDeferredCandidate) {
        const bool bResult = pContext->pArchive->unpackCurrent(
            &pContext->innerState, guardedOutput.data(), pPdStruct);
        if (!guardedThis || !guardedOutput ||
            !m_setUnpackContexts.contains(pContext) ||
            (pState->pContext != pContext)) return false;
        pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
        pState->mapArchiveProperties =
            pContext->innerState.mapArchiveProperties;
        return bResult;
    }

    const QDeadlineTimer helperDeadline =
        XExternalArchive::createHelperDeadline();
    XExternalArchive *pCurrentExternalArchive = externalArchiveFor(
        pContext->pArchive, pContext->info.arcType);
    if (!pCurrentExternalArchive) return false;

    const qint32 nRequestedIndex = pState->nCurrentIndex;
    const qint64 nOriginalOuterOffset = pState->nCurrentOffset;
    const QString sInitialError =
        XBinary::getPdStructErrorString(pPdStruct);
    const auto recordsEqual = [](const ARCHIVERECORD &a,
                                 const ARCHIVERECORD &b) {
        return (a.nStreamOffset == b.nStreamOffset) &&
               (a.nStreamSize == b.nStreamSize) &&
               (a.mapProperties == b.mapProperties);
    };
    const auto contextIsCurrent = [&]() {
        return guardedThis && guardedOutput && guardedSource &&
               m_setUnpackContexts.contains(pContext) &&
               (pState->pContext == pContext) &&
               (pContext->pOwnerState == pState) &&
               (pContext->pOuterSourceDevice == guardedSource) &&
               (pContext->nOwnerDeviceGeneration == getDeviceGeneration()) &&
               (pState->nCurrentIndex == nRequestedIndex) &&
               (pState->nCurrentOffset == nOriginalOuterOffset);
    };
    const auto destroyDetachedContext = [](UNPACK_CONTEXT *pDetached) {
        if (!pDetached) return;
        clearPrivateUnpackCredential(pDetached);
        if (pDetached->pArchive) {
            pDetached->pArchive->finishUnpack(
                &pDetached->innerState, nullptr);
            delete pDetached->pArchive;
        }
        if (pDetached->pSubDevice) {
            pDetached->pSubDevice->close();
            delete pDetached->pSubDevice;
        }
        delete pDetached;
    };

    const auto collectManifest = [&](const INTERNAL_INFO &info,
                                     QList<ARCHIVERECORD> *pRecords,
                                     QMap<FPART_PROP, QVariant> *pProperties,
                                     XExternalArchive::EXTERNAL_FAILURE *pFailure) {
        if (pFailure)
            *pFailure = XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        if (!pRecords || !pProperties || !guardedThis || !guardedSource)
            return false;
        pRecords->clear();
        pProperties->clear();

        SubDevice *pSubDevice = new (std::nothrow) SubDevice(
            guardedSource.data(), info.nArchiveOffset, info.nArchiveSize);
        XArchive *pArchive = nullptr;
        XExternalArchive *pExternalArchive = nullptr;
        UNPACK_STATE state = {};
        bool bResult = pSubDevice && pSubDevice->open(QIODevice::ReadOnly) &&
                       guardedThis && guardedSource;
        if (bResult) {
            pArchive = _createArchive(info.arcType, pSubDevice,
                                      info.bAllowOpaqueZpaq);
            pExternalArchive = externalArchiveFor(pArchive, info.arcType);
            if (pExternalArchive)
                pExternalArchive->setHelperDeadline(helperDeadline);
            QMap<UNPACK_PROP, QVariant> attemptProperties =
                privateUnpackProperties(pContext);
            bResult = pArchive && pExternalArchive &&
                pArchive->initUnpack(&state, attemptProperties, pPdStruct) &&
                guardedThis && guardedSource &&
                (state.nNumberOfRecords >= 0);
            scrubPublicUnpackProperties(&attemptProperties);
            if (pExternalArchive && pFailure)
                *pFailure = pExternalArchive->getLastExternalFailure();
        }
        if (bResult) {
            *pProperties = state.mapArchiveProperties;
            pRecords->reserve(state.nNumberOfRecords);
            for (qint32 i = 0;
                 bResult && (i < state.nNumberOfRecords); ++i) {
                const ARCHIVERECORD record =
                    pArchive->infoCurrent(&state, pPdStruct);
                bResult = guardedThis && guardedSource &&
                    record.mapProperties.contains(FPART_PROP_ORIGINALNAME) &&
                    (state.nCurrentIndex == i);
                if (bResult) pRecords->append(record);
                if (bResult && (i + 1 < state.nNumberOfRecords)) {
                    bResult = pArchive->moveToNext(&state, pPdStruct) &&
                              guardedThis && guardedSource;
                }
            }
            if (!bResult && pFailure) {
                *pFailure = XBinary::isPdStructNotCanceled(pPdStruct)
                    ? XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED
                    : XExternalArchive::EXTERNAL_FAILURE_CANCELED;
            }
        }
        if (pExternalArchive) pExternalArchive->clearHelperDeadline();
        if (pArchive) {
            const bool bFinished =
                pArchive->finishUnpack(&state, nullptr);
            if (bResult && !bFinished && pFailure)
                *pFailure = XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
            bResult = bResult && bFinished && guardedThis && guardedSource;
            delete pArchive;
        }
        if (pSubDevice) {
            pSubDevice->close();
            delete pSubDevice;
        }
        if (bResult && pFailure)
            *pFailure = XExternalArchive::EXTERNAL_FAILURE_NONE;
        return bResult && guardedThis && guardedSource;
    };

    const auto initializeDetachedContext = [&]
        (const INTERNAL_INFO &info,
         XExternalArchive::EXTERNAL_FAILURE *pFailure) {
        if (pFailure)
            *pFailure = XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        UNPACK_CONTEXT *pDetached = new (std::nothrow) UNPACK_CONTEXT;
        if (!pDetached) return static_cast<UNPACK_CONTEXT *>(nullptr);
        pDetached->pOuterSourceDevice = guardedSource;
        pDetached->nOwnerDeviceGeneration = getDeviceGeneration();
        pDetached->pOwnerState = nullptr;
        pDetached->info = info;
        pDetached->pSubDevice = nullptr;
        pDetached->pArchive = nullptr;
        pDetached->innerState = UNPACK_STATE();
        QMap<UNPACK_PROP, QVariant> attemptProperties =
            privateUnpackProperties(pContext);
        initializePrivateUnpackProperties(
            pDetached, attemptProperties, true);

        pDetached->pSubDevice = new (std::nothrow) SubDevice(
            guardedSource.data(), info.nArchiveOffset, info.nArchiveSize);
        bool bInitialized = pDetached->pSubDevice &&
            pDetached->pSubDevice->open(QIODevice::ReadOnly) &&
            guardedThis && guardedSource;
        if (bInitialized) {
            pDetached->pArchive = _createArchive(
                info.arcType, pDetached->pSubDevice,
                info.bAllowOpaqueZpaq);
            XExternalArchive *pExternalArchive = externalArchiveFor(
                pDetached->pArchive, info.arcType);
            if (pExternalArchive)
                pExternalArchive->setHelperDeadline(helperDeadline);
            bInitialized = pDetached->pArchive && pExternalArchive &&
                pDetached->pArchive->initUnpack(
                    &pDetached->innerState,
                    attemptProperties, pPdStruct) &&
                guardedThis && guardedSource &&
                (pDetached->innerState.nNumberOfRecords ==
                  pState->nNumberOfRecords);
            if (pExternalArchive && pFailure)
                *pFailure = pExternalArchive->getLastExternalFailure();
            if (!bInitialized && pExternalArchive && pFailure &&
                (*pFailure == XExternalArchive::EXTERNAL_FAILURE_NONE)) {
                *pFailure = XBinary::isPdStructNotCanceled(pPdStruct)
                    ? XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED
                    : XExternalArchive::EXTERNAL_FAILURE_CANCELED;
            }
        }
        scrubPublicUnpackProperties(&attemptProperties);
        for (qint32 i = 0;
             bInitialized && (i < nRequestedIndex); ++i) {
            bInitialized = pDetached->pArchive->moveToNext(
                               &pDetached->innerState, pPdStruct) &&
                           guardedThis && guardedSource;
        }
        bInitialized = bInitialized &&
            (pDetached->innerState.nCurrentIndex == nRequestedIndex) &&
            (pDetached->innerState.nCurrentOffset == nOriginalOuterOffset);
        if (!bInitialized) {
            if (pFailure &&
                (*pFailure == XExternalArchive::EXTERNAL_FAILURE_NONE)) {
                *pFailure = XBinary::isPdStructNotCanceled(pPdStruct)
                    ? XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED
                    : XExternalArchive::EXTERNAL_FAILURE_CANCELED;
            }
            destroyDetachedContext(pDetached);
            return static_cast<UNPACK_CONTEXT *>(nullptr);
        }
        if (pFailure)
            *pFailure = XExternalArchive::EXTERNAL_FAILURE_NONE;
        return pDetached;
    };

    const auto publishStage = [&](QIODevice *pStage,
                                  UNPACK_CONTEXT *pDecodedContext,
                                  const ARCHIVERECORD &expectedRecord) {
        QPointer<QIODevice> guardedStage(pStage);
        if (!guardedStage || !pDecodedContext ||
            !pDecodedContext->pArchive || !guardedStage->isOpen() ||
            !guardedStage->isReadable() || guardedStage->isSequential() ||
            !XBinary::isResizeEnable(guardedOutput.data()) ||
            XBinary::devicesAlias(guardedStage.data(),
                                  guardedOutput.data()) ||
            XBinary::devicesAlias(guardedSource.data(),
                                  guardedOutput.data()) ||
            !contextIsCurrent() ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        const qint64 nStageSize = guardedStage->size();
        const qint64 nOriginalPosition = guardedOutput->pos();
        if (!guardedStage || !guardedOutput || (nStageSize < 0) ||
            (nOriginalPosition < 0) || !guardedStage->seek(0)) return false;

        QByteArray baBuffer;
        baBuffer.resize(0x10000);
        if (baBuffer.size() != 0x10000) return false;
        bool bOutputCleared = false;
        const auto failPublication = [&]() {
            if (guardedOutput && bOutputCleared) {
                XBinary::resize(guardedOutput.data(), 0);
                if (guardedOutput) guardedOutput->seek(0);
            } else if (guardedOutput && (nOriginalPosition >= 0)) {
                guardedOutput->seek(nOriginalPosition);
            }
            return false;
        };

        if (!guardedOutput->seek(0) || !contextIsCurrent()) return false;
        if (!XBinary::resize(guardedOutput.data(), 0)) {
            if (guardedOutput) guardedOutput->seek(nOriginalPosition);
            return false;
        }
        bOutputCleared = true;
        if (!guardedOutput ||
            !XBinary::resize(guardedOutput.data(), nStageSize) ||
            !contextIsCurrent() || !guardedOutput->seek(0)) {
            return failPublication();
        }

        qint64 nPublished = 0;
        while (nPublished < nStageSize) {
            if (!guardedStage || !guardedOutput || !contextIsCurrent() ||
                !XBinary::isPdStructNotCanceled(pPdStruct) ||
                !guardedStage->seek(nPublished)) return failPublication();
            const qint64 nRequest = qMin<qint64>(
                baBuffer.size(), nStageSize - nPublished);
            const qint64 nRead = guardedStage->read(
                baBuffer.data(), nRequest);
            if ((nRead <= 0) || (nRead > nRequest) ||
                !contextIsCurrent() ||
                (safeWriteData(guardedOutput.data(), nPublished,
                               baBuffer.constData(), nRead,
                               pPdStruct) != nRead) ||
                !contextIsCurrent()) return failPublication();
            nPublished += nRead;
        }

        if (!guardedOutput || !contextIsCurrent() ||
            (guardedOutput->size() != nPublished) ||
            !guardedOutput->seek(nPublished) || !contextIsCurrent() ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            return failPublication();
        }

        // Output callbacks run after the helper authenticated the private
        // stage. Revalidate the inner source once more before success escapes.
        const ARCHIVERECORD currentRecord =
            pDecodedContext->pArchive->infoCurrent(
                &pDecodedContext->innerState, pPdStruct);
        if (!contextIsCurrent() ||
            !recordsEqual(currentRecord, expectedRecord)) {
            return failPublication();
        }
        return true;
    };

    const ARCHIVERECORD expectedCurrent =
        pContext->pArchive->infoCurrent(&pContext->innerState, pPdStruct);
    if (!contextIsCurrent() ||
        !expectedCurrent.mapProperties.contains(FPART_PROP_ORIGINALNAME)) {
        return false;
    }

    QTemporaryFile stagedOutput(QDir(QDir::tempPath()).filePath(
        QStringLiteral("xfileunpacker-sfx-member-XXXXXX")));
    if (!stagedOutput.open()) {
        XBinary::setPdStructErrorString(
            pPdStruct, tr("Cannot create a private SFX member stage"));
        return false;
    }
    pCurrentExternalArchive->setHelperDeadline(helperDeadline);
    bool bDecoded = pContext->pArchive->unpackCurrent(
        &pContext->innerState, &stagedOutput, pPdStruct);
    const XExternalArchive::EXTERNAL_FAILURE decodeFailure =
        pCurrentExternalArchive->getLastExternalFailure();
    pCurrentExternalArchive->clearHelperDeadline();
    if (!contextIsCurrent()) return false;
    if (bDecoded) {
        clearPrivateUnpackCredential(pContext);
        const bool bPublished = publishStage(
            &stagedOutput, pContext, expectedCurrent);
        if (!contextIsCurrent()) return false;
        if (!bPublished) {
            pContext->innerState.nCurrentOffset = nOriginalOuterOffset;
            return false;
        }
        pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
        pState->mapArchiveProperties =
            pContext->innerState.mapArchiveProperties;
        return true;
    }
    pContext->innerState.nCurrentOffset = nOriginalOuterOffset;

    const QString sDecodeError =
        XBinary::getPdStructErrorString(pPdStruct);
    if (!pContext->info.bProvisional ||
        (decodeFailure !=
         XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    // The first candidate has already published a manifest. A later candidate
    // may replace it only after its complete, ordered record set and archive
    // properties match exactly. This prevents a body failure from silently
    // changing what the caller inspected before requesting extraction.
    XBinary::setPdStructErrorString(pPdStruct, sInitialError);
    QList<ARCHIVERECORD> listExpectedManifest;
    QMap<FPART_PROP, QVariant> mapExpectedProperties;
    XExternalArchive::EXTERNAL_FAILURE manifestFailure =
        XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
    if (!collectManifest(pContext->info, &listExpectedManifest,
                         &mapExpectedProperties, &manifestFailure) ||
        !contextIsCurrent()) {
        return false;
    }

    XSFX detector(guardedSource.data(), isImage(), getModuleAddress(),
                  m_requiredArcType);
    XSFX_ZPAQ_SCAN_CACHE zpaqScanCache;
    XSFX_FREEARC_SCAN_CACHE freeArcScanCache;
    qint64 nMinimumArchiveOffset = pContext->info.nArchiveOffset + 1;
    const ARCTYPE fallbackType = pContext->info.arcType;
    QString sLastDecodeError = sDecodeError;

    for (qint32 nAttempt = 0;
         (nAttempt < SFX_SIGNATURE_CANDIDATE_LIMIT) &&
         contextIsCurrent() &&
         XBinary::isPdStructNotCanceled(pPdStruct);
         ++nAttempt) {
        XBinary::setPdStructErrorString(pPdStruct, sInitialError);
        const INTERNAL_INFO info = detector._detect(
            pPdStruct, &zpaqScanCache, &freeArcScanCache,
            nMinimumArchiveOffset);
        if (!contextIsCurrent() || !info.bIsValid) break;
        if (info.nArchiveOffset >=
            (std::numeric_limits<qint64>::max)()) break;
        nMinimumArchiveOffset = info.nArchiveOffset + 1;
        if (info.arcType != fallbackType) continue;

        QList<ARCHIVERECORD> listCandidateManifest;
        QMap<FPART_PROP, QVariant> mapCandidateProperties;
        XExternalArchive::EXTERNAL_FAILURE candidateFailure =
            XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        if (!collectManifest(info, &listCandidateManifest,
                             &mapCandidateProperties,
                             &candidateFailure)) {
            sLastDecodeError =
                XBinary::getPdStructErrorString(pPdStruct);
            if (!contextIsCurrent() ||
                !info.bProvisional ||
                (candidateFailure !=
                 XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED)) break;
            continue;
        }
        bool bEquivalent =
            (mapExpectedProperties == mapCandidateProperties) &&
            (listExpectedManifest.size() == listCandidateManifest.size());
        for (qint32 i = 0;
             bEquivalent && (i < listExpectedManifest.size()); ++i) {
            bEquivalent = recordsEqual(listExpectedManifest.at(i),
                                       listCandidateManifest.at(i));
        }
        if (!bEquivalent) continue;

        candidateFailure =
            XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        UNPACK_CONTEXT *pCandidate = initializeDetachedContext(
            info, &candidateFailure);
        if (!pCandidate || !contextIsCurrent()) {
            destroyDetachedContext(pCandidate);
            sLastDecodeError =
                XBinary::getPdStructErrorString(pPdStruct);
            if (!contextIsCurrent() || !info.bProvisional ||
                (candidateFailure !=
                 XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED)) break;
            continue;
        }
        // XFU-015: the candidate's inner unpackCurrent performs its own
        // entry accounting and debits its production into the stage.
        pCandidate->innerState.spOutputBudget = pState->spOutputBudget;
        QTemporaryFile candidateStage(QDir(QDir::tempPath()).filePath(
            QStringLiteral("xfileunpacker-sfx-fallback-XXXXXX")));
        XExternalArchive *pCandidateExternalArchive = externalArchiveFor(
            pCandidate->pArchive, info.arcType);
        bool bCandidateDecoded = candidateStage.open();
        candidateFailure =
            XExternalArchive::EXTERNAL_FAILURE_INFRASTRUCTURE;
        if (bCandidateDecoded && pCandidateExternalArchive) {
            bCandidateDecoded = pCandidate->pArchive->unpackCurrent(
                &pCandidate->innerState, &candidateStage, pPdStruct) &&
                contextIsCurrent();
            candidateFailure =
                pCandidateExternalArchive->getLastExternalFailure();
            pCandidateExternalArchive->clearHelperDeadline();
        } else {
            bCandidateDecoded = false;
        }
        if (!bCandidateDecoded) {
            sLastDecodeError =
                XBinary::getPdStructErrorString(pPdStruct);
            const bool bMayContinue = info.bProvisional &&
                (candidateFailure ==
                 XExternalArchive::EXTERNAL_FAILURE_ARCHIVE_REJECTED);
            destroyDetachedContext(pCandidate);
            if (!bMayContinue) break;
            continue;
        }
        clearPrivateUnpackCredential(pCandidate);

        const ARCHIVERECORD candidateCurrent =
            pCandidate->pArchive->infoCurrent(
                &pCandidate->innerState, pPdStruct);
        if (!contextIsCurrent() ||
            !recordsEqual(candidateCurrent, expectedCurrent) ||
            !publishStage(&candidateStage, pCandidate,
                          expectedCurrent)) {
            pCandidate->innerState.nCurrentOffset = nOriginalOuterOffset;
            destroyDetachedContext(pCandidate);
            return false;
        }

        UNPACK_CONTEXT *pOldContext = pContext;
        pCandidate->pOwnerState = pState;
        m_setUnpackContexts.remove(pOldContext);
        m_setUnpackContexts.insert(pCandidate);
        pState->pContext = pCandidate;
        pContext = pCandidate;
        pState->nCurrentOffset = pCandidate->innerState.nCurrentOffset;
        pState->mapArchiveProperties =
            pCandidate->innerState.mapArchiveProperties;
        destroyDetachedContext(pOldContext);
        return guardedThis && guardedOutput && guardedSource &&
               m_setUnpackContexts.contains(pCandidate) &&
               (pState->pContext == pCandidate);
    }

    XBinary::setPdStructErrorString(pPdStruct, sLastDecodeError);
    return false;
}

bool XSFX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);
    if (!pState || !pState->baUnpackSourceToken.isEmpty() || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != getDevice()) || (pContext->nOwnerDeviceGeneration != getDeviceGeneration()) || !pContext->pArchive ||
        (pContext->innerState.nCurrentIndex != pState->nCurrentIndex) ||
        (pContext->innerState.nCurrentOffset != pState->nCurrentOffset) ||
        (pContext->innerState.nNumberOfRecords != pState->nNumberOfRecords)) {
        return false;
    }

    bool bResult = pContext->pArchive->moveToNext(&pContext->innerState, pPdStruct);
    if (!guardedThis || !m_setUnpackContexts.contains(pContext) || (pState->pContext != pContext)) return false;
    pState->nCurrentIndex = pContext->innerState.nCurrentIndex;
    pState->nCurrentOffset = pContext->innerState.nCurrentOffset;
    pState->mapArchiveProperties = pContext->innerState.mapArchiveProperties;

    return bResult;
}

bool XSFX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }
    if (!pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<bool> pOperationState = m_pUnpackOperationState;
    if (!pOperationState || *pOperationState) return false;
    QScopedValueRollback<bool> operationGuard(*pOperationState, true);
    QPointer<XSFX> guardedThis(this);

    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!m_setUnpackContexts.contains(pContext) || (pContext->pOwnerState != pState)) return false;
        m_setUnpackContexts.remove(pContext);
        pState->pContext = nullptr;

        if (pContext->pArchive) {
            bResult = pContext->pArchive->finishUnpack(&pContext->innerState, nullptr);
            delete pContext->pArchive;
            pContext->pArchive = nullptr;
        }
        if (pContext->pSubDevice) {
            pContext->pSubDevice->close();
            delete pContext->pSubDevice;
            pContext->pSubDevice = nullptr;
        }

        clearPrivateUnpackCredential(pContext);
        delete pContext;
        if (!guardedThis) return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();

    return bResult;
}
