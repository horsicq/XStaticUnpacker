/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xupx.h"

#include "Algos/xucldecoder.h"
#include "LzmaDec.h"
#include "xmach.h"

#include <algorithm>
#include <QBuffer>
#include <QFile>
#include <QFileInfo>
#include <zlib.h>

// clang-format off
static XBinary::XCONVERT _TABLE_XUPX_UPX_F[] = {
    {XUPX::UPX_F_DOS_COM, "DOS_COM", QString("DOS COM")},
    {XUPX::UPX_F_DOS_SYS, "DOS_SYS", QString("DOS SYS")},
    {XUPX::UPX_F_DOS_EXE, "DOS_EXE", QString("DOS EXE")},
    {XUPX::UPX_F_DJGPP2_COFF, "DJGPP2_COFF", QString("DJGPP2 COFF")},
    {XUPX::UPX_F_WATCOM_LE, "WATCOM_LE", QString("Watcom LE")},
    {XUPX::UPX_F_DOS_EXEH, "DOS_EXEH", QString("DOS EXEH")},
    {XUPX::UPX_F_TMT_ADAM, "TMT_ADAM", QString("TMT ADAM")},
    {XUPX::UPX_F_W32PE_I386, "W32PE_I386", QString("PE i386")},
    {XUPX::UPX_F_LINUX_i386, "LINUX_i386", QString("Linux i386")},
    {XUPX::UPX_F_LINUX_ELF_i386, "LINUX_ELF_i386", QString("Linux ELF i386")},
    {XUPX::UPX_F_LINUX_SH_i386, "LINUX_SH_i386", QString("Linux SH i386")},
    {XUPX::UPX_F_VMLINUZ_i386, "VMLINUZ_i386", QString("vmlinuz i386")},
    {XUPX::UPX_F_BVMLINUZ_i386, "BVMLINUZ_i386", QString("bvmlinuz i386")},
    {XUPX::UPX_F_ELKS_8086, "ELKS_8086", QString("ELKS 8086")},
    {XUPX::UPX_F_PS1_EXE, "PS1_EXE", QString("PS1 EXE")},
    {XUPX::UPX_F_VMLINUX_i386, "VMLINUX_i386", QString("vmlinux i386")},
    {XUPX::UPX_F_LINUX_ELFI_i386, "LINUX_ELFI_i386", QString("Linux ELFI i386")},
    {XUPX::UPX_F_WINCE_ARM, "WINCE_ARM", QString("Windows CE ARM")},
    {XUPX::UPX_F_LINUX_ELF64_AMD64, "LINUX_ELF64_AMD64", QString("Linux ELF64 AMD64")},
    {XUPX::UPX_F_LINUX_ELF32_ARM, "LINUX_ELF32_ARM", QString("Linux ELF32 ARM")},
    {XUPX::UPX_F_BSD_i386, "BSD_i386", QString("BSD i386")},
    {XUPX::UPX_F_BSD_ELF_i386, "BSD_ELF_i386", QString("BSD ELF i386")},
    {XUPX::UPX_F_BSD_SH_i386, "BSD_SH_i386", QString("BSD SH i386")},
    {XUPX::UPX_F_VMLINUX_AMD64, "VMLINUX_AMD64", QString("vmlinux AMD64")},
    {XUPX::UPX_F_VMLINUX_ARM, "VMLINUX_ARM", QString("vmlinux ARM")},
    {XUPX::UPX_F_MACH_i386, "MACH_i386", QString("Mach-O i386")},
    {XUPX::UPX_F_LINUX_ELF32_MIPSEL, "LINUX_ELF32_MIPSEL", QString("Linux ELF32 MIPSEL")},
    {XUPX::UPX_F_VMLINUZ_ARM, "VMLINUZ_ARM", QString("vmlinuz ARM")},
    {XUPX::UPX_F_MACH_ARM, "MACH_ARM", QString("Mach-O ARM")},
    {XUPX::UPX_F_DYLIB_i386, "DYLIB_i386", QString("dylib i386")},
    {XUPX::UPX_F_MACH_AMD64, "MACH_AMD64", QString("Mach-O AMD64")},
    {XUPX::UPX_F_DYLIB_AMD64, "DYLIB_AMD64", QString("dylib AMD64")},
    {XUPX::UPX_F_W64PE_AMD64, "W64PE_AMD64", QString("PE64 AMD64")},
    {XUPX::UPX_F_MACH_ARM64, "MACH_ARM64", QString("Mach-O ARM64")},
    {XUPX::UPX_F_LINUX_ELF64_PPC64LE, "LINUX_ELF64_PPC64LE", QString("Linux ELF64 PPC64LE")},
    {XUPX::UPX_F_VMLINUX_PPC64LE, "VMLINUX_PPC64LE", QString("vmlinux PPC64LE")},
    {XUPX::UPX_F_LINUX_ELF64_ARM64, "LINUX_ELF64_ARM64", QString("Linux ELF64 ARM64")},
    {XUPX::UPX_F_W64PE_ARM64, "W64PE_ARM64", QString("PE64 ARM64")},
    {XUPX::UPX_F_W64PE_ARM64EC, "W64PE_ARM64EC", QString("PE64 ARM64EC")},

    {XUPX::UPX_F_ATARI_TOS, "ATARI_TOS", QString("Atari TOS")},
    {XUPX::UPX_F_MACH_PPC32, "MACH_PPC32", QString("Mach-O PPC32")},
    {XUPX::UPX_F_LINUX_ELF32_PPC32, "LINUX_ELF32_PPC32", QString("Linux ELF32 PPC32")},
    {XUPX::UPX_F_LINUX_ELF32_ARMEB, "LINUX_ELF32_ARMEB", QString("Linux ELF32 ARMEB")},
    {XUPX::UPX_F_MACH_FAT, "MACH_FAT", QString("Mach-O FAT")},
    {XUPX::UPX_F_VMLINUX_ARMEB, "VMLINUX_ARMEB", QString("vmlinux ARMEB")},
    {XUPX::UPX_F_VMLINUX_PPC32, "VMLINUX_PPC32", QString("vmlinux PPC32")},
    {XUPX::UPX_F_LINUX_ELF32_MIPS, "LINUX_ELF32_MIPS", QString("Linux ELF32 MIPS")},
    {XUPX::UPX_F_DYLIB_PPC32, "DYLIB_PPC32", QString("dylib PPC32")},
    {XUPX::UPX_F_MACH_PPC64, "MACH_PPC64", QString("Mach-O PPC64")},
    {XUPX::UPX_F_LINUX_ELF64_PPC64, "LINUX_ELF64_PPC64", QString("Linux ELF64 PPC64")},
    {XUPX::UPX_F_VMLINUX_PPC64, "VMLINUX_PPC64", QString("vmlinux PPC64")},
    {XUPX::UPX_F_DYLIB_PPC64, "DYLIB_PPC64", QString("dylib PPC64")},
};
// clang-format on

XBinary::XCONVERT _TABLE_XUPX_STRUCTID[] = {
    {XUPX::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XUPX::STRUCTID_HEADER, "HEADER", QString("Header")},
};

const qint64 XUPX_TRAILER_READ_SIZE = 0x3000;
const qint64 XUPX_HEADER_SEARCH_SIZE = 0x1000;
const qint64 XUPX_PACK_HEADER_SIZE = 36;
const qint64 XUPX_MIN_PACK_HEADER_SIZE = 20;

static quint8 upxMachFormatFromHeader(quint32 nCpuType, quint32 nFileType)
{
    const bool bIsDylib = (nFileType == XMACH_DEF::S_MH_DYLIB);

    switch (nCpuType) {
        case XMACH_DEF::S_CPU_TYPE_I386: return bIsDylib ? XUPX::UPX_F_DYLIB_i386 : XUPX::UPX_F_MACH_i386;
        case XMACH_DEF::S_CPU_TYPE_X86_64: return bIsDylib ? XUPX::UPX_F_DYLIB_AMD64 : XUPX::UPX_F_MACH_AMD64;
        case XMACH_DEF::S_CPU_TYPE_ARM: return XUPX::UPX_F_MACH_ARM;
        case XMACH_DEF::S_CPU_TYPE_ARM64: return XUPX::UPX_F_MACH_ARM64;
        case XMACH_DEF::S_CPU_TYPE_POWERPC: return bIsDylib ? XUPX::UPX_F_DYLIB_PPC32 : XUPX::UPX_F_MACH_PPC32;
        case XMACH_DEF::S_CPU_TYPE_POWERPC64: return bIsDylib ? XUPX::UPX_F_DYLIB_PPC64 : XUPX::UPX_F_MACH_PPC64;
        default: break;
    }

    return 0;
}

static void *xupxSzAlloc(ISzAllocPtr, size_t nSize)
{
    return malloc(nSize);
}

static void xupxSzFree(ISzAllocPtr, void *pAddress)
{
    free(pAddress);
}

static ISzAlloc g_xupxAlloc = {xupxSzAlloc, xupxSzFree};

static QString upxMethodToString(quint8 nMethod)
{
    switch (nMethod) {
        case XUPX::UPX_M_NRV2B_LE32: return "NRV2B_LE32";
        case XUPX::UPX_M_NRV2B_8: return "NRV2B_8";
        case XUPX::UPX_M_NRV2B_LE16: return "NRV2B_LE16";
        case XUPX::UPX_M_NRV2D_LE32: return "NRV2D_LE32";
        case XUPX::UPX_M_NRV2D_8: return "NRV2D_8";
        case XUPX::UPX_M_NRV2D_LE16: return "NRV2D_LE16";
        case XUPX::UPX_M_NRV2E_LE32: return "NRV2E_LE32";
        case XUPX::UPX_M_NRV2E_8: return "NRV2E_8";
        case XUPX::UPX_M_NRV2E_LE16: return "NRV2E_LE16";
        case XUPX::UPX_M_LZMA: return "LZMA";
        case XUPX::UPX_M_DEFLATE: return "DEFLATE";
        default: return QString("Unknown (%1)").arg(nMethod);
    }
}

static bool upxMethodToUCLMethod(quint8 nMethod, XUCLDecoder::METHOD *pMethod)
{
    bool bResult = true;

    switch (nMethod) {
        case XUPX::UPX_M_NRV2B_8: *pMethod = XUCLDecoder::METHOD_NRV2B_8; break;
        case XUPX::UPX_M_NRV2B_LE16: *pMethod = XUCLDecoder::METHOD_NRV2B_LE16; break;
        case XUPX::UPX_M_NRV2B_LE32: *pMethod = XUCLDecoder::METHOD_NRV2B_LE32; break;
        case XUPX::UPX_M_NRV2D_8: *pMethod = XUCLDecoder::METHOD_NRV2D_8; break;
        case XUPX::UPX_M_NRV2D_LE16: *pMethod = XUCLDecoder::METHOD_NRV2D_LE16; break;
        case XUPX::UPX_M_NRV2D_LE32: *pMethod = XUCLDecoder::METHOD_NRV2D_LE32; break;
        case XUPX::UPX_M_NRV2E_8: *pMethod = XUCLDecoder::METHOD_NRV2E_8; break;
        case XUPX::UPX_M_NRV2E_LE16: *pMethod = XUCLDecoder::METHOD_NRV2E_LE16; break;
        case XUPX::UPX_M_NRV2E_LE32: *pMethod = XUCLDecoder::METHOD_NRV2E_LE32; break;
        default: bResult = false; break;
    }

    return bResult;
}

static bool applyPEFilter(unsigned char *pData, qint64 nDataSize, quint8 nFilter, quint8 nFilterCTO, quint32 nAddValue)
{
    if ((!pData) || (nDataSize <= 0)) {
        return false;
    }

    if (nFilter == 0) {
        return true;
    }

    if (nFilter == 0x14) {
        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if (pData[i] == 0xe8) {
                quint32 nJC = XBinary::_read_uint32((char *)pData + i + 1, true);
                XBinary::_write_uint32((char *)pData + i + 1, nJC - (quint32)i - 1 - nAddValue);
                i += 4;
            }
        }
    } else if (nFilter == 0x16) {
        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if ((pData[i] == 0xe8) || (pData[i] == 0xe9)) {
                quint32 nJC = XBinary::_read_uint32((char *)pData + i + 1, true);
                XBinary::_write_uint32((char *)pData + i + 1, nJC - (quint32)i - 1 - nAddValue);
                i += 4;
            }
        }
    } else if (nFilter == 0x24) {
        quint32 nCTO = ((quint32)nFilterCTO) << 24;

        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if ((pData[i] == 0xe8) && ((unsigned char)pData[i + 1] == nFilterCTO)) {
                quint32 nJC = XBinary::_read_uint32((char *)pData + i + 1, true);
                XBinary::_write_uint32((char *)pData + i + 1, nJC - (quint32)i - 1 - nAddValue - nCTO);
                i += 4;
            }
        }
    } else if (nFilter == 0x26) {
        quint32 nCTO = ((quint32)nFilterCTO) << 24;

        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            if (((pData[i] == 0xe8) || (pData[i] == 0xe9)) && ((unsigned char)pData[i + 1] == nFilterCTO)) {
                quint32 nJC = XBinary::_read_uint32((char *)pData + i + 1, true);
                XBinary::_write_uint32((char *)pData + i + 1, nJC - (quint32)i - 1 - nAddValue - nCTO);
                i += 4;
            }
        }
    } else if (nFilter == 0x49) {
        quint32 nCTO = ((quint32)nFilterCTO) << 24;
        quint32 nLastCall = 0;

        for (qint64 i = 0; i < (nDataSize - 5); i++) {
            bool bMatch = (pData[i] == 0xe8) || (pData[i] == 0xe9);

            if ((!bMatch) && (i > 0) && ((9 <= (0x0f & nFilter)) && (nLastCall != (quint32)i) && (0x0f == pData[i - 1]) && (0x80 <= pData[i]) && (pData[i] <= 0x8f))) {
                bMatch = true;
            }

            if (bMatch && ((unsigned char)pData[i + 1] == nFilterCTO)) {
                quint32 nJC = XBinary::_read_uint32((char *)pData + i + 1, true);
                XBinary::_write_uint32((char *)pData + i + 1, nJC - (quint32)i - 1 - nAddValue - nCTO);
                i += 4;
                nLastCall = (quint32)i + 1;
            }
        }
    } else {
        return false;
    }

    return true;
}

static bool applyUPXBlockFilter(unsigned char *pData, qint64 nDataSize, quint8 nFilter, quint8 nFilterCTO)
{
    // First reconstruction pass: reuse the branch/call-style filters already implemented here.
    return applyPEFilter(pData, nDataSize, nFilter, nFilterCTO, 0);
}

static quint64 upxAlignUp(quint64 nValue, quint64 nAlign)
{
    if (nAlign <= 1) {
        return nValue;
    }

    return (nValue + nAlign - 1) & ~(nAlign - 1);
}

static quint64 findELFLoadGap(const QList<XELF_DEF::Elf_Phdr> &listProgramHeaders, qint32 nIndex, quint64 nFileSize)
{
    if ((nIndex < 0) || (nIndex >= listProgramHeaders.count())) {
        return 0;
    }

    const XELF_DEF::Elf_Phdr &current = listProgramHeaders.at(nIndex);

    if (current.p_type != XELF_DEF::S_PT_LOAD) {
        return 0;
    }

    quint64 nCurrentEnd = current.p_offset + current.p_filesz;

    if (nCurrentEnd > nFileSize) {
        return 0;
    }

    quint64 nNextOffset = nFileSize;

    for (qint32 i = 0; i < listProgramHeaders.count(); i++) {
        if (i == nIndex) {
            continue;
        }

        const XELF_DEF::Elf_Phdr &candidate = listProgramHeaders.at(i);

        if ((candidate.p_type == XELF_DEF::S_PT_LOAD) && (candidate.p_offset >= nCurrentEnd) && (candidate.p_offset < nNextOffset)) {
            nNextOffset = candidate.p_offset;
        }
    }

    return nNextOffset - nCurrentEnd;
}

enum DOS_EXE_UPX_FLAGS {
    DOS_EXE_FLAG_NORELOC = 1,
    DOS_EXE_FLAG_USEJUMP = 2,
    DOS_EXE_FLAG_SS = 4,
    DOS_EXE_FLAG_SP = 8,
    DOS_EXE_FLAG_MINMEM = 16,
    DOS_EXE_FLAG_MAXMEM = 32
};

XUPX::XUPX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XUPX::~XUPX()
{
}

QList<QString> XUPX::getSearchSignatures()
{
    return XBinary::getSearchSignatures();
}

XBinary *XUPX::createInstance(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress)
{
    return new XUPX(pDevice, bIsImage, nModuleAddress);
}

QString XUPX::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XUPX_STRUCTID, sizeof(_TABLE_XUPX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

QString XUPX::structIDToFtString(quint32 nID)
{
    return XBinary::XCONVERT_idToFtString(nID, _TABLE_XUPX_STRUCTID, sizeof(_TABLE_XUPX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

quint32 XUPX::ftStringToStructID(const QString &sFtString)
{
    return XCONVERT_ftStringToId(sFtString, _TABLE_XUPX_STRUCTID, sizeof(_TABLE_XUPX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XUPX::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

bool XUPX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XUPX upx(pDevice);

    return upx.isValid(pPdStruct);
}

bool XUPX::_isPackHeaderValid(const INTERNAL_INFO &info)
{
    return (info.magic[0] == 'U') && (info.magic[1] == 'P') && (info.magic[2] == 'X') && (info.magic[3] == '!');
}

bool XUPX::_isPEFileType(FT fileType)
{
    return (fileType == FT_PE32) || (fileType == FT_PE64);
}

bool XUPX::_isELFFileType(FT fileType)
{
    return (fileType == FT_ELF32) || (fileType == FT_ELF64);
}

bool XUPX::_isMachFileType(FT fileType)
{
    return (fileType == FT_MACHO32) || (fileType == FT_MACHO64) || (fileType == FT_MACHOFAT);
}

bool XUPX::_isDOSFileType(FT fileType)
{
    return (fileType == FT_MSDOS) || (fileType == FT_COM);
}

bool XUPX::_isDOSFormat(quint8 nFormat)
{
    return (nFormat == UPX_F_DOS_COM) || (nFormat == UPX_F_DOS_SYS) || (nFormat == UPX_F_DOS_EXE) || (nFormat == UPX_F_DOS_EXEH);
}

bool XUPX::_readPackHeader(qint64 nOffset, qint64 nHeaderSize, bool bIsBigEndian, INTERNAL_INFO *pInfo, PDSTRUCT *pPdStruct)
{
    if ((!pInfo) || (nOffset < 0) || (nHeaderSize < XUPX_MIN_PACK_HEADER_SIZE) || (nOffset >= this->getSize())) {
        return false;
    }

    qint64 nAvailableSize = qMin(nHeaderSize, this->getSize() - nOffset);

    if (nAvailableSize < XUPX_MIN_PACK_HEADER_SIZE) {
        return false;
    }

    QByteArray baHeader = read_array_process(nOffset, nAvailableSize, pPdStruct);

    if (baHeader.size() != nAvailableSize) {
        return false;
    }

    INTERNAL_INFO info = _read_packheader(baHeader.data(), baHeader.size(), bIsBigEndian);

    if (!_isPackHeaderValid(info)) {
        return false;
    }

    info.bIsValid = true;
    info.nHeaderOffset = nOffset;
    info.nDataOffset = nOffset + info.nPackHeaderSize;

    *pInfo = info;

    return true;
}

bool XUPX::_detectELFInfo(INTERNAL_INFO *pInfo, PDSTRUCT *pPdStruct)
{
    if (!pInfo) {
        return false;
    }

    XELF elf(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!elf.isValid(pPdStruct)) {
        return false;
    }

    const bool bIsBigEndian = (elf.getEndian() == ENDIAN_BIG);
    const qint64 nReadSize = qMin((qint64)XUPX_TRAILER_READ_SIZE, this->getSize());

    if (nReadSize < XUPX_PACK_HEADER_SIZE) {
        return false;
    }

    const qint64 nBufferOffset = this->getSize() - nReadSize;
    QByteArray baBuffer = elf.read_array_process(nBufferOffset, nReadSize, pPdStruct);

    if (baBuffer.size() != nReadSize) {
        return false;
    }

    qint64 nBufferSize = getPhysSize(baBuffer.data(), baBuffer.size());
    nBufferSize = align_up(nBufferSize, 4);

    if ((nBufferSize < XUPX_PACK_HEADER_SIZE) || (nBufferSize > baBuffer.size())) {
        return false;
    }

    INTERNAL_INFO info = _read_packheader(baBuffer.data() + nBufferSize - XUPX_PACK_HEADER_SIZE, XUPX_PACK_HEADER_SIZE, bIsBigEndian);

    if (!_isPackHeaderValid(info)) {
        return false;
    }

    info.bIsValid = true;
    info.fileType = elf.getFileType();
    info.nHeaderOffset = nBufferOffset + nBufferSize - XUPX_PACK_HEADER_SIZE;
    info.nDataOffset = XBinary::_read_uint32_safe(baBuffer.data(), baBuffer.size(), nBufferSize - XUPX_PACK_HEADER_SIZE + info.nPackHeaderSize, bIsBigEndian);

    QByteArray baProgramInfo = read_array_process(info.nDataOffset, sizeof(p_info), pPdStruct);
    QByteArray baBlockInfo = read_array_process(info.nDataOffset + sizeof(p_info), sizeof(b_info), pPdStruct);

    if ((baProgramInfo.size() == (qint64)sizeof(p_info)) && (baBlockInfo.size() == (qint64)sizeof(b_info))) {
        p_info programInfo = {};
        b_info blockInfo = {};

        XBinary::_copyMemory((char *)(&programInfo), baProgramInfo.constData(), sizeof(p_info));
        XBinary::_copyMemory((char *)(&blockInfo), baBlockInfo.constData(), sizeof(b_info));

        info.u_len = XBinary::_read_uint32((char *)(&programInfo.p_filesize), bIsBigEndian);
        info.c_len = XBinary::_read_uint32((char *)(&blockInfo.sz_cpr), bIsBigEndian);
    }

    *pInfo = info;

    return true;
}

bool XUPX::_detectMachInfo(INTERNAL_INFO *pInfo, PDSTRUCT *pPdStruct)
{
    if (!pInfo) {
        return false;
    }

    XMACH mach(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!mach.isValid(pPdStruct)) {
        return false;
    }

    const bool bIsBigEndian = (mach.getEndian() == ENDIAN_BIG);
    const quint32 nHeaderSize = (quint32)(mach.getHeaderSize() + mach.getHeader_sizeofcmds());
    const quint8 nFormat = upxMachFormatFromHeader((quint32)mach.getHeader_cputype(), mach.getHeader_filetype());

    if ((!nHeaderSize) || (nHeaderSize >= (quint32)getSize()) || (!nFormat)) {
        return false;
    }

    auto isMethodSupported = [](quint8 nMethod) -> bool {
        switch (nMethod) {
            case XUPX::UPX_M_NRV2B_LE32:
            case XUPX::UPX_M_NRV2B_8:
            case XUPX::UPX_M_NRV2B_LE16:
            case XUPX::UPX_M_NRV2D_LE32:
            case XUPX::UPX_M_NRV2D_8:
            case XUPX::UPX_M_NRV2D_LE16:
            case XUPX::UPX_M_NRV2E_LE32:
            case XUPX::UPX_M_NRV2E_8:
            case XUPX::UPX_M_NRV2E_LE16:
            case XUPX::UPX_M_LZMA:
            case XUPX::UPX_M_DEFLATE: return true;
            default: break;
        }

        return false;
    };

    auto validateDataOffset = [&](qint64 nDataOffset, INTERNAL_INFO *pResult) -> bool {
        if ((!pResult) || (nDataOffset < nHeaderSize) || ((nDataOffset + (qint64)sizeof(p_info) + (qint64)sizeof(b_info)) > getSize()) || (nDataOffset & 3)) {
            return false;
        }

        QByteArray baProgramInfo = read_array_process(nDataOffset, sizeof(p_info), pPdStruct);
        QByteArray baBlockInfo = read_array_process(nDataOffset + sizeof(p_info), sizeof(b_info), pPdStruct);

        if ((baProgramInfo.size() != (qint64)sizeof(p_info)) || (baBlockInfo.size() != (qint64)sizeof(b_info))) {
            return false;
        }

        p_info programInfo = {};
        b_info blockInfo = {};

        XBinary::_copyMemory((char *)&programInfo, baProgramInfo.constData(), sizeof(programInfo));
        XBinary::_copyMemory((char *)&blockInfo, baBlockInfo.constData(), sizeof(blockInfo));

        const quint32 nOrigFileSize = XBinary::_read_uint32((char *)&programInfo.p_filesize, bIsBigEndian);
        const quint32 nBlockSize = XBinary::_read_uint32((char *)&programInfo.p_blocksize, bIsBigEndian);
        const quint32 nHeaderUnpackedSize = XBinary::_read_uint32((char *)&blockInfo.sz_unc, bIsBigEndian);
        const quint32 nHeaderCompressedSize = XBinary::_read_uint32((char *)&blockInfo.sz_cpr, bIsBigEndian);

        if ((!nOrigFileSize) || (!nBlockSize) || (nBlockSize > nOrigFileSize) || (nOrigFileSize <= (quint32)getSize()) || (nHeaderUnpackedSize != nHeaderSize) ||
            (!nHeaderCompressedSize) || (nHeaderCompressedSize > nBlockSize) || (!isMethodSupported(blockInfo.b_method))) {
            return false;
        }

        pResult->bIsValid = true;
        pResult->fileType = mach.getFileType();
        pResult->format = nFormat;
        pResult->method = blockInfo.b_method;
        pResult->filter = blockInfo.b_ftid;
        pResult->filter_cto = blockInfo.b_cto8;
        pResult->u_len = nOrigFileSize;
        pResult->u_file_size = nOrigFileSize;
        pResult->c_len = nHeaderCompressedSize;
        pResult->nDataOffset = nDataOffset;

        return true;
    };

    const qint64 nSearchSize = qMin((qint64)XUPX_HEADER_SEARCH_SIZE, getSize());
    QByteArray baSearch = read_array_process(0, nSearchSize, pPdStruct);

    if (baSearch.size() == nSearchSize) {
        qint32 nIndex = -1;

        while ((nIndex = baSearch.indexOf("UPX!", nIndex + 1)) != -1) {
            INTERNAL_INFO info = _read_packheader(baSearch.data() + nIndex, qMin((qint64)XUPX_PACK_HEADER_SIZE, nSearchSize - nIndex), bIsBigEndian);

            if (!_isPackHeaderValid(info)) {
                continue;
            }

            qint64 nDataOffset = XBinary::_read_uint32_safe(baSearch.data(), baSearch.size(), nIndex + info.nPackHeaderSize, bIsBigEndian);

            if (validateDataOffset(nDataOffset, &info)) {
                info.nHeaderOffset = nIndex;
                info.fileType = mach.getFileType();
                info.format = nFormat;
                *pInfo = info;

                return true;
            }
        }
    }

    const qint64 nScanStart = upxAlignUp(nHeaderSize, 4);
    const qint64 nScanSize = qMin((qint64)0x4000, getSize() - nScanStart);
    QByteArray baScan = read_array_process(nScanStart, nScanSize, pPdStruct);

    if (baScan.size() != nScanSize) {
        return false;
    }

    for (qint64 i = 0; (i + (qint64)sizeof(p_info) + (qint64)sizeof(b_info)) <= baScan.size(); i += 4) {
        INTERNAL_INFO info = {};

        if (validateDataOffset(nScanStart + i, &info)) {
            *pInfo = info;
            return true;
        }
    }

    return false;
}

bool XUPX::_detectPEInfo(INTERNAL_INFO *pInfo, PDSTRUCT *pPdStruct)
{
    if (!pInfo) {
        return false;
    }

    XPE pe(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!pe.isValid(pPdStruct)) {
        return false;
    }

    const qint64 nSearchSize = qMin((qint64)XUPX_HEADER_SEARCH_SIZE, this->getSize());

    if (nSearchSize < XUPX_MIN_PACK_HEADER_SIZE) {
        return false;
    }

    const qint64 nOffset = find_ansiString(0, nSearchSize, "UPX!");

    if (nOffset == -1) {
        return false;
    }

    INTERNAL_INFO info = {};

    if (!_readPackHeader(nOffset, XUPX_PACK_HEADER_SIZE, false, &info, pPdStruct)) {
        return false;
    }

    info.fileType = pe.getFileType();

    *pInfo = info;

    return true;
}

bool XUPX::_detectGenericInfo(INTERNAL_INFO *pInfo, PDSTRUCT *pPdStruct)
{
    if (!pInfo) {
        return false;
    }

    const qint64 nSearchSize = qMin((qint64)XUPX_HEADER_SEARCH_SIZE, this->getSize());

    if (nSearchSize < XUPX_MIN_PACK_HEADER_SIZE) {
        return false;
    }

    const qint64 nOffset = find_ansiString(0, nSearchSize, "UPX!");

    if (nOffset == -1) {
        return false;
    }

    INTERNAL_INFO info = {};

    if (!_readPackHeader(nOffset, XUPX_PACK_HEADER_SIZE, false, &info, pPdStruct)) {
        return false;
    }

    XMSDOS msdos(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (msdos.isValid(pPdStruct)) {
        info.fileType = msdos.getFileType();
    } else if ((info.format == UPX_F_DOS_COM) || (info.format == UPX_F_DOS_SYS)) {
        info.fileType = FT_COM;
    } else if ((info.format == UPX_F_DOS_EXE) || (info.format == UPX_F_DOS_EXEH)) {
        info.fileType = FT_MSDOS;
    }

    *pInfo = info;

    return true;
}

XUPX::INTERNAL_INFO XUPX::_read_packheader(char *pInfoData, qint32 nDataSize, bool bIsBigEndian)
{
    XUPX::INTERNAL_INFO result = {};

    if (nDataSize >= 8) {
        memcpy(result.magic, pInfoData, 4);
        result.version = (quint8)pInfoData[4];
        result.format = (quint8)pInfoData[5];
        result.method = (quint8)pInfoData[6];
        result.level = (quint8)pInfoData[7];
    }

    if (result.format < 128) {
        result.u_adler = _read_uint32(pInfoData + 8, bIsBigEndian);
        result.c_adler = _read_uint32(pInfoData + 12, bIsBigEndian);

        if ((result.format == UPX_F_DOS_COM) || (result.format == UPX_F_DOS_SYS)) {
            if (nDataSize >= 21) {
                result.u_len = _read_uint16(pInfoData + 16, bIsBigEndian);
                result.c_len = _read_uint16(pInfoData + 18, bIsBigEndian);
                result.u_file_size = result.u_len;
                result.off_filter = 20;
            }
        } else if ((result.format == UPX_F_DOS_EXE) || (result.format == UPX_F_DOS_EXEH)) {
            if (nDataSize >= 26) {
                result.u_len = _read_uint24(pInfoData + 16, bIsBigEndian);
                result.c_len = _read_uint24(pInfoData + 19, bIsBigEndian);
                result.u_file_size = _read_uint24(pInfoData + 22, bIsBigEndian);
                result.off_filter = 25;
            }
        } else {
            if (nDataSize >= 32) {
                result.u_len = _read_uint32(pInfoData + 16, bIsBigEndian);
                result.c_len = _read_uint32(pInfoData + 20, bIsBigEndian);
                result.u_file_size = _read_uint32(pInfoData + 24, bIsBigEndian);
                result.off_filter = 28;
                result.filter_cto = (quint8)pInfoData[29];
                result.n_mru = (quint8)(pInfoData[30] ? 1 + pInfoData[30] : 0);
            }
        }
    } else {
        if (nDataSize >= 32) {
            result.u_len = _read_uint32(pInfoData + 8, bIsBigEndian);
            result.c_len = _read_uint32(pInfoData + 12, bIsBigEndian);
            result.u_adler = _read_uint32(pInfoData + 16, bIsBigEndian);
            result.c_adler = _read_uint32(pInfoData + 20, bIsBigEndian);
            result.u_file_size = _read_uint32(pInfoData + 24, bIsBigEndian);
            result.off_filter = 28;
            result.filter_cto = (quint8)pInfoData[29];
            result.n_mru = (quint8)(pInfoData[30] ? 1 + pInfoData[30] : 0);
        }
    }

    if (result.version <= 3) {
        result.nPackHeaderSize = 24;
    } else if (result.version <= 9) {
        if ((result.format == UPX_F_DOS_COM) || (result.format == UPX_F_DOS_SYS)) {
            result.nPackHeaderSize = 20;
        } else if ((result.format == UPX_F_DOS_EXE) || (result.format == UPX_F_DOS_EXEH)) {
            result.nPackHeaderSize = 25;
        } else {
            result.nPackHeaderSize = 28;
        }
    } else {
        if ((result.format == UPX_F_DOS_COM) || (result.format == UPX_F_DOS_SYS)) {
            result.nPackHeaderSize = 22;
        } else if ((result.format == UPX_F_DOS_EXE) || (result.format == UPX_F_DOS_EXEH)) {
            result.nPackHeaderSize = 27;
        } else {
            result.nPackHeaderSize = 32;
        }
    }

    if ((result.version > 10) && (result.off_filter < (quint32)nDataSize)) {
        result.filter = (quint8)pInfoData[result.off_filter];
    }

    return result;
}

XUPX::INTERNAL_INFO XUPX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    XUPX::INTERNAL_INFO result = {};

    if (_detectELFInfo(&result, pPdStruct)) {
        return result;
    }

    if (_detectMachInfo(&result, pPdStruct)) {
        return result;
    }

    if (_detectPEInfo(&result, pPdStruct)) {
        return result;
    }

    if (_detectGenericInfo(&result, pPdStruct)) {
        return result;
    }

    return result;
}

XBinary::FT XUPX::getFileType()
{
    return XBinary::FT_UPX;
}

QString XUPX::getMIMEString()
{
    return "application/x-upx";
}

QString XUPX::getArch()
{
    QString sResult;

    INTERNAL_INFO info = getInternalInfo();

    if (info.bIsValid) {
        // Map UPX format to architecture
        if ((info.format == UPX_F_W32PE_I386) || (info.format == UPX_F_LINUX_i386) || (info.format == UPX_F_LINUX_ELF_i386) || (info.format == UPX_F_LINUX_SH_i386) ||
            (info.format == UPX_F_VMLINUZ_i386) || (info.format == UPX_F_BVMLINUZ_i386) || (info.format == UPX_F_VMLINUX_i386) ||
            (info.format == UPX_F_LINUX_ELFI_i386) || (info.format == UPX_F_BSD_i386) || (info.format == UPX_F_BSD_ELF_i386) || (info.format == UPX_F_BSD_SH_i386) ||
            (info.format == UPX_F_MACH_i386) || (info.format == UPX_F_DYLIB_i386)) {
            sResult = "i386";
        } else if ((info.format == UPX_F_LINUX_ELF64_AMD64) || (info.format == UPX_F_VMLINUX_AMD64) || (info.format == UPX_F_MACH_AMD64) ||
                   (info.format == UPX_F_DYLIB_AMD64) || (info.format == UPX_F_W64PE_AMD64)) {
            sResult = "AMD64";
        } else if ((info.format == UPX_F_WINCE_ARM) || (info.format == UPX_F_LINUX_ELF32_ARM) || (info.format == UPX_F_VMLINUX_ARM) ||
                   (info.format == UPX_F_VMLINUZ_ARM) || (info.format == UPX_F_MACH_ARM) || (info.format == UPX_F_LINUX_ELF32_ARMEB) ||
                   (info.format == UPX_F_VMLINUX_ARMEB)) {
            sResult = "ARM";
        } else if ((info.format == UPX_F_MACH_ARM64) || (info.format == UPX_F_LINUX_ELF64_ARM64) || (info.format == UPX_F_W64PE_ARM64) ||
                   (info.format == UPX_F_W64PE_ARM64EC)) {
            sResult = "ARM64";
        } else if ((info.format == UPX_F_LINUX_ELF32_MIPSEL) || (info.format == UPX_F_LINUX_ELF32_MIPS)) {
            sResult = "MIPS";
        } else if ((info.format == UPX_F_MACH_PPC32) || (info.format == UPX_F_LINUX_ELF32_PPC32) || (info.format == UPX_F_VMLINUX_PPC32) ||
                   (info.format == UPX_F_DYLIB_PPC32)) {
            sResult = "PPC32";
        } else if ((info.format == UPX_F_LINUX_ELF64_PPC64LE) || (info.format == UPX_F_VMLINUX_PPC64LE) || (info.format == UPX_F_MACH_PPC64) ||
                   (info.format == UPX_F_LINUX_ELF64_PPC64) || (info.format == UPX_F_VMLINUX_PPC64) || (info.format == UPX_F_DYLIB_PPC64)) {
            sResult = "PPC64";
        } else if ((info.format == UPX_F_DOS_COM) || (info.format == UPX_F_DOS_SYS) || (info.format == UPX_F_DOS_EXE) || (info.format == UPX_F_DOS_EXEH) ||
                   (info.format == UPX_F_ELKS_8086)) {
            sResult = "8086";
        }
    }

    return sResult;
}

XBinary::MODE XUPX::getMode()
{
    return XBinary::MODE_DATA;
}

XBinary::ENDIAN XUPX::getEndian()
{
    return XBinary::ENDIAN_LITTLE;
}

QString XUPX::getFileFormatExt()
{
    return "";  // UPX can be applied to various formats
}

QString XUPX::getFileFormatExtsString()
{
    return "*";  // UPX can be applied to various formats
}

qint64 XUPX::getFileFormatSize(PDSTRUCT *pPdStruct)
{
    return getSize();
}

QString XUPX::getVersion()
{
    INTERNAL_INFO info = getInternalInfo();
    if (info.bIsValid) {
        return QString::number(info.version);
    }

    return QString();
}

QList<XBinary::MAPMODE> XUPX::getMapModesList()
{
    QList<MAPMODE> listResult;

    listResult.append(MAPMODE_REGIONS);
    listResult.append(MAPMODE_DATA);

    return listResult;
}

XBinary::_MEMORY_MAP XUPX::getMemoryMap(MAPMODE mapMode, PDSTRUCT *pPdStruct)
{
    XBinary::_MEMORY_MAP result = {};

    if (mapMode == MAPMODE_UNKNOWN) {
        mapMode = MAPMODE_DATA;
    }

    if (mapMode == MAPMODE_REGIONS) {
        result = _getMemoryMap(FILEPART_HEADER | FILEPART_DATA | FILEPART_OVERLAY, pPdStruct);
    } else if (mapMode == MAPMODE_DATA) {
        result = _getMemoryMap(FILEPART_DATA | FILEPART_OVERLAY, pPdStruct);
    }

    return result;
}

QList<XBinary::DATA_HEADER> XUPX::getDataHeaders(const DATA_HEADERS_OPTIONS &dataHeadersOptions, PDSTRUCT *pPdStruct)
{
    QList<DATA_HEADER> listResult;

    if (dataHeadersOptions.nID == STRUCTID_UNKNOWN) {
        DATA_HEADERS_OPTIONS _dataHeadersOptions = dataHeadersOptions;
        _dataHeadersOptions.bChildren = true;
        _dataHeadersOptions.dsID_parent = _addDefaultHeaders(&listResult, pPdStruct);
        _dataHeadersOptions.dhMode = XBinary::DHMODE_HEADER;
        _dataHeadersOptions.fileType = dataHeadersOptions.pMemoryMap->fileType;

        _dataHeadersOptions.nID = STRUCTID_HEADER;
        _dataHeadersOptions.nLocation = 0;
        _dataHeadersOptions.locType = XBinary::LT_OFFSET;

        listResult.append(getDataHeaders(_dataHeadersOptions, pPdStruct));
    } else if (dataHeadersOptions.nID == STRUCTID_HEADER) {
        DATA_HEADER dataHeader = _initDataHeader(dataHeadersOptions, XUPX::structIDToString(dataHeadersOptions.nID));
        dataHeader.nSize = 0;  // TODO

        // TODO: Add records

        listResult.append(dataHeader);
    }

    return listResult;
}

bool XUPX::_prepareOutputDevice(QIODevice *pDevice, bool *pbCloseOutputDevice)
{
    if ((!pDevice) || (!pbCloseOutputDevice)) {
        return false;
    }

    *pbCloseOutputDevice = false;

    if (!pDevice->isOpen()) {
        if (!pDevice->open(QIODevice::WriteOnly)) {
            return false;
        }

        *pbCloseOutputDevice = true;
    }

    if (!(pDevice->openMode() & QIODevice::WriteOnly)) {
        if (*pbCloseOutputDevice) {
            pDevice->close();
            *pbCloseOutputDevice = false;
        }

        return false;
    }

    if (XBinary::isResizeEnable(pDevice)) {
        XBinary::resize(pDevice, 0);
    }

    if (!pDevice->isSequential()) {
        pDevice->seek(0);
    }

    return true;
}

bool XUPX::_writeBufferToDevice(const QByteArray &baData, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pDevice) {
        return false;
    }

    bool bCloseOutputDevice = false;

    if (!_prepareOutputDevice(pDevice, &bCloseOutputDevice)) {
        return false;
    }

    const qint64 nChunkSize = 0x100000;
    qint64 nOffset = 0;
    bool bResult = true;

    while ((nOffset < baData.size()) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        qint64 nCurrentChunkSize = qMin(nChunkSize, (qint64)baData.size() - nOffset);

        if (pDevice->write(baData.constData() + nOffset, nCurrentChunkSize) != nCurrentChunkSize) {
            bResult = false;
            break;
        }

        nOffset += nCurrentChunkSize;
    }

    if (bCloseOutputDevice) {
        pDevice->close();
    }

    return bResult && XBinary::isPdStructNotCanceled(pPdStruct) && (nOffset == baData.size());
}

bool XUPX::unpack(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    return _unpackToFile(pDevice, pPdStruct);
}

bool XUPX::_unpackToFile(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    bool bResult = false;

    INTERNAL_INFO info = getInternalInfo(pPdStruct);

    if (info.bIsValid) {
        if (_isPEFileType(info.fileType)) {
            bResult = _unpackPE(pDevice, info, pPdStruct);
        } else if (_isELFFileType(info.fileType)) {
            bResult = _unpackELF(pDevice, info, pPdStruct);
        } else if (_isMachFileType(info.fileType)) {
            bResult = _unpackMach(pDevice, info, pPdStruct);
        } else if (_isDOSFileType(info.fileType) || _isDOSFormat(info.format)) {
            bResult = _unpackDOS(pDevice, info, pPdStruct);
        }
    }

    return bResult;
}

XBinary::ARCHIVERECORD XUPX::_createArchiveRecord(const INTERNAL_INFO &info)
{
    ARCHIVERECORD result = {};

    result.nStreamOffset = 0;
    result.nStreamSize = getSize();
    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, _getUnpackedFileName());
    result.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, getSize());
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, (qint64)(info.u_file_size ? info.u_file_size : info.u_len));
    result.mapProperties.insert(FPART_PROP_FILETYPE, (qint32)info.fileType);
    result.mapProperties.insert(FPART_PROP_HANDLEMETHOD, HANDLE_METHOD_FILE);
    result.mapProperties.insert(FPART_PROP_ISFOLDER, false);

    QString sMethod = QString("UPX %1").arg(getCompressionMethod());
    QString sVersion = getPackerVersion();

    if (!sVersion.isEmpty()) {
        sMethod += QString(" (v%1)").arg(sVersion);
    }

    result.mapProperties.insert(FPART_PROP_INFO, sMethod);

    return result;
}

QString XUPX::_getUnpackedFileName()
{
    QString sResult = "content";

    if (QFile *pFile = qobject_cast<QFile *>(getDevice())) {
        QFileInfo fi(pFile->fileName());

        if (!fi.fileName().isEmpty()) {
            sResult = fi.fileName();
        }
    } else if (getDevice() && !getDevice()->objectName().isEmpty()) {
        QFileInfo fi(getDevice()->objectName());

        if (!fi.fileName().isEmpty()) {
            sResult = fi.fileName();
        }
    }

    return sResult;
}

bool XUPX::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) {
        return false;
    }

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties = mapProperties;
    pState->pContext = nullptr;

    INTERNAL_INFO info = getInternalInfo(pPdStruct);

    if (!info.bIsValid) {
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->listRecords.append(_createArchiveRecord(info));

    pState->pContext = pContext;
    pState->nNumberOfRecords = pContext->listRecords.count();

    return (pState->nNumberOfRecords > 0);
}

XBinary::ARCHIVERECORD XUPX::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    ARCHIVERECORD result = {};

    if ((!pState) || (!pState->pContext)) {
        return result;
    }

    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;

    if ((pState->nCurrentIndex >= 0) && (pState->nCurrentIndex < pContext->listRecords.count())) {
        result = pContext->listRecords.at(pState->nCurrentIndex);
    }

    return result;
}

bool XUPX::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if ((!pState) || (!pState->pContext)) {
        return false;
    }

    pState->nCurrentIndex++;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XUPX::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    if (!pState) {
        return false;
    }

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

bool XUPX::isPackedFile(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

QString XUPX::getPackerVersion(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO info = getInternalInfo(pPdStruct);
    if (info.bIsValid) {
        return QString::number(info.version);
    }
    return QString();
}

QString XUPX::getCompressionMethod(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO info = getInternalInfo(pPdStruct);
    if (info.bIsValid) {
        return upxMethodToString(info.method);
    }
    return QString();
}

bool XUPX::_upxDecompress(const unsigned char *pSrc, quint32 nSrcSize, unsigned char *pDst, quint32 *pnDstSize, quint8 method)
{
    if ((!pSrc) || (!pDst) || (!pnDstSize)) {
        return false;
    }

    bool bResult = false;

    switch (method) {
        case UPX_M_NRV2B_8:
        case UPX_M_NRV2B_LE16:
        case UPX_M_NRV2B_LE32:
        case UPX_M_NRV2D_8:
        case UPX_M_NRV2D_LE16:
        case UPX_M_NRV2D_LE32:
        case UPX_M_NRV2E_8:
        case UPX_M_NRV2E_LE16:
        case UPX_M_NRV2E_LE32: {
            XUCLDecoder::METHOD uclMethod = XUCLDecoder::METHOD_NRV2B_8;

            if (upxMethodToUCLMethod(method, &uclMethod)) {
                QByteArray baInput((const char *)pSrc, (qint32)nSrcSize);
                QByteArray baOutput;
                baOutput.resize(*pnDstSize);

                QBuffer bufferInput(&baInput);
                QBuffer bufferOutput(&baOutput);

                if (bufferInput.open(QIODevice::ReadOnly) && bufferOutput.open(QIODevice::WriteOnly)) {
                    XBinary::DATAPROCESS_STATE decompressState = {};
                    decompressState.pDeviceInput = &bufferInput;
                    decompressState.pDeviceOutput = &bufferOutput;
                    decompressState.nInputOffset = 0;
                    decompressState.nInputLimit = nSrcSize;
                    decompressState.nProcessedOffset = 0;
                    decompressState.nProcessedLimit = -1;
                    decompressState.mapProperties.insert(XBinary::FPART_PROP_TYPE, (quint32)uclMethod);
                    decompressState.mapProperties.insert(XBinary::FPART_PROP_UNCOMPRESSEDSIZE, (qint64)(*pnDstSize));

                    bResult = XUCLDecoder::decompress(&decompressState);

                    if (bResult) {
                        *pnDstSize = (quint32)decompressState.nCountOutput;

                        if (*pnDstSize > (quint32)baOutput.size()) {
                            bResult = false;
                        } else if (*pnDstSize > 0) {
                            memcpy(pDst, baOutput.constData(), *pnDstSize);
                        }
                    }
                }
            }
            break;
        }

        case UPX_M_LZMA: {
            if (nSrcSize < 3) {
                return false;
            }

            quint8 pb = pSrc[0] & 7;
            quint8 lp = pSrc[1] >> 4;
            quint8 lc = pSrc[1] & 0x0f;

            if ((pb >= 5) || (lp >= 5) || (lc >= 9)) {
                return false;
            }

            if ((pSrc[0] >> 3) != (lc + lp)) {
                return false;
            }

            unsigned char props[5] = {};
            props[0] = (unsigned char)((pb * 5 + lp) * 9 + lc);
            XBinary::_write_uint32((char *)props + 1, qMax<quint32>(1, *pnDstSize), false);

            SizeT nSrcProcessed = nSrcSize - 2;
            SizeT nDstProcessed = *pnDstSize;
            ELzmaStatus status = LZMA_STATUS_NOT_FINISHED;
            SRes nRes = LzmaDecode((Byte *)pDst, &nDstProcessed, (const Byte *)(pSrc + 2), &nSrcProcessed, props, 5, LZMA_FINISH_END, &status, &g_xupxAlloc);

            *pnDstSize = (quint32)nDstProcessed;
            bResult = (nRes == SZ_OK) &&
                      ((status == LZMA_STATUS_FINISHED_WITH_MARK) || (status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK));
            break;
        }

        case UPX_M_DEFLATE: {
            z_stream stream = {};
            stream.next_in = (Bytef *)pSrc;
            stream.avail_in = nSrcSize;
            stream.next_out = (Bytef *)pDst;
            stream.avail_out = *pnDstSize;

            if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
                return false;
            }

            int nRes = Z_OK;

            while (nRes == Z_OK) {
                nRes = inflate(&stream, Z_FINISH);
            }

            inflateEnd(&stream);

            *pnDstSize = (quint32)stream.total_out;
            bResult = (nRes == Z_STREAM_END);
            break;
        }

        default: break;
    }

    return bResult;
}

bool XUPX::_fallbackUnpack(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    return _runUPXDecompress(pDevice, pPdStruct);
}

bool XUPX::_unpackPE(QIODevice *pDevice, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    auto fallback = [&]() -> bool {
        return _fallbackUnpack(pDevice, pPdStruct);
    };

    if ((!getDevice()) || (!pDevice) || (!info.c_len) || (!info.u_len)) {
        return false;
    }

    QByteArray baCompressed = read_array_process(info.nDataOffset, info.c_len, pPdStruct);

    if ((quint32)baCompressed.size() != info.c_len) {
        return fallback();
    }

    QByteArray baPayload(info.u_len, 0);
    quint32 nPayloadSize = info.u_len;

    if (!_upxDecompress((const unsigned char *)baCompressed.constData(), (quint32)baCompressed.size(), (unsigned char *)baPayload.data(), &nPayloadSize, info.method)) {
        return fallback();
    }

    baPayload.resize(nPayloadSize);

    XPE pe(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!pe.isValid(pPdStruct)) {
        return fallback();
    }

    bool bIs64 = pe.is64();
    XMSDOS_DEF::IMAGE_DOS_HEADEREX idh = pe.getDosHeaderEx();
    QByteArray baStub = pe.getDosStub();
    qint64 nBaseAddress = pe.getBaseAddress();

    if (baPayload.size() < 4) {
        return fallback();
    }

    quint32 nExtraInfoOffset = XBinary::_read_uint32(baPayload.data() + baPayload.size() - 4, false);

    if ((!bIs64) && ((quint64)nExtraInfoOffset + sizeof(XPE_DEF::IMAGE_NT_HEADERS32) > (quint64)baPayload.size())) {
        return fallback();
    }

    if ((bIs64) && ((quint64)nExtraInfoOffset + sizeof(XPE_DEF::IMAGE_NT_HEADERS64) > (quint64)baPayload.size())) {
        return fallback();
    }

    char *pExtraInfo = baPayload.data() + nExtraInfoOffset;
    XPE_DEF::IMAGE_NT_HEADERS32 ih32 = {};
    XPE_DEF::IMAGE_NT_HEADERS64 ih64 = {};
    quint32 nFileAlignment = 0;
    quint32 nSectionAlignment = 0;
    qint64 nRVAmin = 0;
    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections;
    int nNumberOfSections = 0;
    quint32 nBaseOfCode = 0;
    quint32 nSizeOfCode = 0;

    if (!bIs64) {
        XBinary::_copyMemory((char *)&ih32, pExtraInfo, sizeof(XPE_DEF::IMAGE_NT_HEADERS32));
        nFileAlignment = ih32.OptionalHeader.FileAlignment;
        nSectionAlignment = ih32.OptionalHeader.SectionAlignment;
        nRVAmin = XBinary::align_up(ih32.OptionalHeader.SizeOfHeaders, nSectionAlignment);
        nNumberOfSections = ih32.FileHeader.NumberOfSections;
        nBaseOfCode = ih32.OptionalHeader.BaseOfCode;
        nSizeOfCode = ih32.OptionalHeader.SizeOfCode;
        pExtraInfo += sizeof(XPE_DEF::IMAGE_NT_HEADERS32);
    } else {
        XBinary::_copyMemory((char *)&ih64, pExtraInfo, sizeof(XPE_DEF::IMAGE_NT_HEADERS64));
        nFileAlignment = ih64.OptionalHeader.FileAlignment;
        nSectionAlignment = ih64.OptionalHeader.SectionAlignment;
        nRVAmin = XBinary::align_up(ih64.OptionalHeader.SizeOfHeaders, nSectionAlignment);
        nNumberOfSections = ih64.FileHeader.NumberOfSections;
        nBaseOfCode = ih64.OptionalHeader.BaseOfCode;
        nSizeOfCode = ih64.OptionalHeader.SizeOfCode;
        pExtraInfo += sizeof(XPE_DEF::IMAGE_NT_HEADERS64);
    }

    if (((!bIs64) && (ih32.Signature != XPE_DEF::S_IMAGE_NT_SIGNATURE)) || ((bIs64) && (ih64.Signature != XPE_DEF::S_IMAGE_NT_SIGNATURE))) {
        return fallback();
    }

    for (int i = 0; i < nNumberOfSections; i++) {
        XPE_DEF::IMAGE_SECTION_HEADER sectionHeader = {};
        XBinary::_copyMemory((char *)&sectionHeader, pExtraInfo, sizeof(XPE_DEF::IMAGE_SECTION_HEADER));
        listSections.append(sectionHeader);
        pExtraInfo += sizeof(XPE_DEF::IMAGE_SECTION_HEADER);
    }

    QByteArray baImage(nRVAmin + baPayload.size(), 0);
    XBinary::_copyMemory(baImage.data() + nRVAmin, baPayload.data(), baPayload.size());

    char *pMemOut0 = baImage.data();
    char *pMemOut = pMemOut0 + nRVAmin;

    if (nSizeOfCode && (nBaseOfCode >= (quint32)nRVAmin) && ((qint64)(nBaseOfCode - nRVAmin + nSizeOfCode) <= baPayload.size())) {
        unsigned char *pFilteredData = (unsigned char *)(pMemOut + nBaseOfCode - nRVAmin);
        qint64 nFilteredDataSize = nSizeOfCode;
        quint32 nAddValue = nBaseOfCode - nRVAmin;

        if (!applyPEFilter(pFilteredData, nFilteredDataSize, info.filter, info.filter_cto, nAddValue)) {
            return fallback();
        }
    }

    bool bIsImportPresent = false;
    bool bIsTdRelocsPresent = false;
    bool bIsRelocsPresent = false;
    bool bIsExportPresent = false;
    bool bIsResourcesPresent = false;

    if (!bIs64) {
        bIsImportPresent = ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        bIsTdRelocsPresent = ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 8;
        bIsRelocsPresent = (ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
                           (ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) &&
                           (!(ih32.FileHeader.Characteristics & XPE_DEF::S_IMAGE_FILE_RELOCS_STRIPPED));
        bIsExportPresent = ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress !=
                           pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress;
        bIsResourcesPresent = ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    } else {
        bIsImportPresent = ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        bIsTdRelocsPresent = ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 8;
        bIsRelocsPresent = (ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
                           (ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) &&
                           (!(ih64.FileHeader.Characteristics & XPE_DEF::S_IMAGE_FILE_RELOCS_STRIPPED));
        bIsExportPresent = ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress !=
                           pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress;
        bIsResourcesPresent = ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    }

    if (bIsImportPresent) {
        quint32 nImportOffset = XBinary::_read_uint32(pExtraInfo, false);
        quint32 nINamePosition = XBinary::_read_uint32(pExtraInfo + 4, false);
        pExtraInfo += 8;
        char *pIData = pMemOut + nImportOffset;
        QByteArray baImport = pe.getDataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);
        char *pOffset = nullptr;
        quint32 nDllNames = 0;

        for (pOffset = pIData; XBinary::_read_uint32(pOffset, false); ++pOffset) {
            quint32 nNameOffset = XBinary::_read_uint32(pOffset, false);

            if (nNameOffset >= (quint32)baImport.size()) {
                return fallback();
            }

            char *pDName = baImport.data() + nNameOffset;
            int nNameSize = (int)strlen(pDName);
            nDllNames += nNameSize + 1;
            pOffset += 8;

            for (; *pOffset;) {
                if (*pOffset == 1) {
                    pOffset++;
                    pOffset += strlen(pOffset) + 1;
                } else if ((unsigned char)(*pOffset) == 0xFF) {
                    pOffset += 1 + 2;
                } else {
                    pOffset += 1 + 4;
                }
            }
        }

        nDllNames = (quint32)XBinary::align_up(nDllNames, 2);
        char *pIID = nullptr;

        if (!bIs64) {
            pIID = pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        } else {
            pIID = pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }

        char *pDllNames = pMemOut0 + nINamePosition;
        char *pImportedNames = pDllNames + nDllNames;
        char *pImportedNamesStart = pImportedNames;

        for (pOffset = pIData; XBinary::_read_uint32(pOffset, false); ++pOffset) {
            quint32 nNameOffset = XBinary::_read_uint32(pOffset, false);
            char *pDName = baImport.data() + nNameOffset;
            int nNameSize = (int)strlen(pDName);
            quint32 nIAT = XBinary::_read_uint32(pOffset + 4, false) + nRVAmin;

            if (nINamePosition) {
                strcpy(pDllNames, pDName);
                XBinary::_write_uint32(pIID + offsetof(XPE_DEF::IMAGE_IMPORT_DESCRIPTOR, Name), (quint32)(pDllNames - pMemOut0), false);
                pDllNames += nNameSize + 1;
            } else {
                strcpy(pMemOut0 + XBinary::_read_uint32(pIID + offsetof(XPE_DEF::IMAGE_IMPORT_DESCRIPTOR, Name), false), pDName);
            }

            XBinary::_write_uint32(pIID + offsetof(XPE_DEF::IMAGE_IMPORT_DESCRIPTOR, FirstThunk), nIAT, false);
            char *pIAT = pMemOut0 + nIAT;
            pOffset += 8;
            int nStepIAT = bIs64 ? 8 : 4;

            for (; *pOffset; pIAT += nStepIAT) {
                if (*pOffset == 1) {
                    pOffset++;
                    int nIlen = (int)strlen(pOffset) + 1;

                    if (nINamePosition) {
                        if ((pImportedNames - pImportedNamesStart) & 1) {
                            pImportedNames -= 1;
                        }

                        strcpy(pImportedNames + 2, pOffset);
                        quint32 nDelta = (quint32)(pImportedNames - pMemOut0);
                        XBinary::_write_uint32(pIAT, nDelta, false);
                        pImportedNames += 2 + nIlen;
                    } else {
                        quint32 nIAddress = XBinary::_read_uint32(pIAT, false);
                        strcpy(pMemOut0 + nIAddress + 2, pOffset);
                    }

                    pOffset += nIlen;
                } else if ((unsigned char)(*pOffset) == 0xFF) {
                    if (!bIs64) {
                        XBinary::_write_uint32(pIAT, XBinary::_read_uint16(pOffset + 1, false) + 0x80000000, false);
                    } else {
                        XBinary::_write_uint64(pIAT, XBinary::_read_uint16(pOffset + 1, false) + 0x8000000000000000ULL, false);
                    }

                    pOffset += 1 + 2;
                } else {
                    quint32 nThunkOffset = XBinary::_read_uint32(pOffset + 1, false);

                    if ((qint64)nThunkOffset + 4 > baImport.size()) {
                        return fallback();
                    }

                    quint32 nThunkValue = XBinary::_read_uint32(baImport.data() + nThunkOffset, false);

                    if (!bIs64) {
                        XBinary::_write_uint32(pIAT, nThunkValue, false);
                    } else {
                        XBinary::_write_uint64(pIAT, nThunkValue, false);
                    }

                    pOffset += 1 + 4;
                }
            }

            if (!bIs64) {
                XBinary::_write_uint32(pIAT, 0, false);
            } else {
                XBinary::_write_uint64(pIAT, 0, false);
            }

            pIID += sizeof(XPE_DEF::IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    if (bIsTdRelocsPresent) {
        if (!bIs64) {
            XBinary::_copyMemory(pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
                                 "\x0\x0\x0\x0\x8\x0\x0\x0", 8);
        } else {
            XBinary::_copyMemory(pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
                                 "\x0\x0\x0\x0\x8\x0\x0\x0", 8);
        }
    } else if (bIsRelocsPresent) {
        quint32 nRelocsOffset = XBinary::_read_uint32(pExtraInfo, false);
        quint8 nBig = (quint8)XBinary::_read_uint32(pExtraInfo + 4, false);
        pExtraInfo += 5;
        char *pRelocs = pMemOut + nRelocsOffset;
        int nRelocsCount = 0;

        for (char *pTemp = pRelocs; *pTemp; pTemp++) {
            if ((unsigned char)(*pTemp) >= 0xF0) {
                if (((unsigned char)(*pTemp) == 0xF0) && (XBinary::_read_uint16(pTemp + 1, false) == 0)) {
                    pTemp += 4;
                }

                pTemp += 2;
            }

            nRelocsCount++;
        }

        QByteArray baBuffer(4 * nRelocsCount + 4, 0);
        char *pOutReloc = baBuffer.data();
        quint32 jc = (quint32)(-4);
        char *pTemp = pRelocs;

        for (; *pTemp; pTemp++) {
            if ((unsigned char)(*pTemp) < 0xF0) {
                jc += (unsigned char)(*pTemp);
            } else {
                quint32 dif = (*pTemp & 0x0F) * 0x10000 + XBinary::_read_uint16(pTemp + 1, false);
                pTemp += 2;

                if (dif == 0) {
                    dif = XBinary::_read_uint32(pTemp + 1, false);
                    pTemp += 4;
                }

                jc += dif;
            }

            XBinary::_write_uint32(pOutReloc, jc, false);
            pOutReloc += 4;

            char *pTempOffset = pMemOut + jc;

            if (!bIs64) {
                quint32 nTemp = XBinary::_read_uint32(pTempOffset, false);
                XBinary::_write_uint32(pTempOffset, nTemp, true);
            } else {
                quint64 nTemp = XBinary::_read_uint64(pTempOffset, false);
                XBinary::_write_uint64(pTempOffset, nTemp, true);
            }
        }

        Q_UNUSED(nBig)
        QList<XADDR> listRelocs;
        quint32 nRelocs2 = (quint32)((pOutReloc - baBuffer.data()) / 4);

        for (quint32 i = 0; i < nRelocs2; i++) {
            quint32 nOffset = XBinary::_read_uint32(baBuffer.data() + 4 * i, false);
            char *pTempOffset = pMemOut + nOffset;

            if (!bIs64) {
                XBinary::_write_uint32(pTempOffset, XBinary::_read_uint32(pTempOffset, false) + ih32.OptionalHeader.ImageBase + nRVAmin, false);
            } else {
                XBinary::_write_uint64(pTempOffset, XBinary::_read_uint64(pTempOffset, false) + ih64.OptionalHeader.ImageBase + nRVAmin, false);
            }

            listRelocs.append(nRVAmin + nOffset);
        }

        QByteArray baRelocs = XPE::relocsAsRVAListToByteArray(&listRelocs, bIs64);

        if (!bIs64) {
            XBinary::_copyMemory(pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, baRelocs.data(), baRelocs.size());
            ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = baRelocs.size();
        } else {
            XBinary::_copyMemory(pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, baRelocs.data(), baRelocs.size());
            ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = baRelocs.size();
        }
    }

    if (bIsExportPresent) {
        char *pExport = nullptr;

        if (!bIs64) {
            pExport = pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            pExport = pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        pe.read_array(pe.getDataDirectoryOffset(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT), pExport,
                      pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT).Size);

        qint32 nDelta = 0;

        if (!bIs64) {
            nDelta = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress -
                     ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            nDelta = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress -
                     ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        XBinary::_write_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, Name), XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, Name), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfFunctions),
                               XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfFunctions), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfNames),
                               XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfNames), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals),
                               XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals), false) - nDelta, false);

        quint32 nNumberOfNames = XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, NumberOfNames), false);
        quint32 nAddressOfNames = XBinary::_read_uint32(pExport + offsetof(XPE_DEF::IMAGE_EXPORT_DIRECTORY, AddressOfNames), false);
        char *pNames = pMemOut0 + nAddressOfNames;

        for (quint32 i = 0; i < nNumberOfNames; i++) {
            XBinary::_write_uint32(pNames, XBinary::_read_uint32(pNames, false) - nDelta, false);
            pNames += 4;
        }
    }

    if (bIsResourcesPresent) {
        quint16 nIconDirCount = XBinary::_read_uint16(pExtraInfo, false);
        pExtraInfo += 2;
        QList<XPE::RESOURCE_RECORD> listResources = pe.getResources(10000, pPdStruct);
        quint32 nSectionAddress = pe.getSection_VirtualAddress(2);
        quint32 nMaxOffset = 0;
        QMap<quint32, QString> mapResNames;

        for (int i = 0; i < listResources.count(); i++) {
            nMaxOffset = qMax((quint32)(listResources.at(i).nIRDEOffset + sizeof(XPE_DEF::IMAGE_RESOURCE_DATA_ENTRY)), nMaxOffset);

            for (int j = 0; j < 3; j++) {
                if (!listResources.at(i).irin[j].sName.isEmpty()) {
                    mapResNames.insert(listResources.at(i).irin[j].nNameOffset, listResources.at(i).irin[j].sName);
                }
            }
        }

        quint32 nResNamesData = 0;
        QMapIterator<quint32, QString> iRes(mapResNames);

        while (iRes.hasNext()) {
            iRes.next();
            nResNamesData += 2 + iRes.value().length() * 2;
        }

        nMaxOffset += nResNamesData;

        if (!bIs64) {
            nMaxOffset = qMin(nMaxOffset, ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
        } else {
            nMaxOffset = qMin(nMaxOffset, ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
        }

        if (!bIs64) {
            pe.read_array(pe.getDataDirectoryOffset(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE),
                          pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, nMaxOffset);
        } else {
            pe.read_array(pe.getDataDirectoryOffset(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE),
                          pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, nMaxOffset);
        }

        for (int i = 0; i < listResources.count(); i++) {
            if ((listResources.at(i).nOffset != -1) && (listResources.at(i).nAddress >= nSectionAddress + nBaseAddress)) {
                quint32 nOrigOffset = pe.read_uint32(listResources.at(i).nOffset - 4);
                char *pIRDE = nullptr;

                if (!bIs64) {
                    pIRDE = pMemOut0 + ih32.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + listResources.at(i).nIRDEOffset;
                } else {
                    pIRDE = pMemOut0 + ih64.OptionalHeader.DataDirectory[XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + listResources.at(i).nIRDEOffset;
                }

                XBinary::_write_uint32(pIRDE, nOrigOffset, false);
                pe.read_array(listResources.at(i).nOffset, pMemOut0 + nOrigOffset, XBinary::align_up(listResources.at(i).nSize, 4));

                if (nIconDirCount && (!listResources.at(i).irin[0].bIsName) && (listResources.at(i).irin[0].nID == XPE_DEF::S_RT_GROUP_ICON)) {
                    XBinary::_write_uint32(pMemOut0 + nOrigOffset + 4, nIconDirCount, false);
                    nIconDirCount = 0;
                }
            }
        }
    }

    qint64 nFileSize = 0;

    for (int i = 0; i < listSections.count(); i++) {
        XPE_DEF::IMAGE_SECTION_HEADER ish = listSections.at(i);

        if (ish.PointerToRawData) {
            nFileSize = qMax((qint64)(ish.PointerToRawData + ish.SizeOfRawData), nFileSize);
        }
    }

    if (!bIs64) {
        nFileSize = XBinary::align_up(nFileSize, ih32.OptionalHeader.FileAlignment);
    } else {
        nFileSize = XBinary::align_up(nFileSize, ih64.OptionalHeader.FileAlignment);
    }

    QByteArray baResultFile(nFileSize, 0);
    QBuffer buffer(&baResultFile);

    if (!buffer.open(QIODevice::ReadWrite)) {
        return fallback();
    }

    XPE peNew(&buffer);
    qint64 nCurrentOffset = 0;
    peNew.write_array(nCurrentOffset, (char *)&idh, sizeof(XMSDOS_DEF::IMAGE_DOS_HEADEREX));
    nCurrentOffset += sizeof(XMSDOS_DEF::IMAGE_DOS_HEADEREX);
    peNew.write_array(nCurrentOffset, baStub.data(), baStub.size());
    nCurrentOffset += baStub.size();

    if (!bIs64) {
        peNew.write_array(nCurrentOffset, (char *)&ih32, sizeof(XPE_DEF::IMAGE_NT_HEADERS32));
    } else {
        peNew.write_array(nCurrentOffset, (char *)&ih64, sizeof(XPE_DEF::IMAGE_NT_HEADERS64));
    }

    for (int i = 0; i < listSections.count(); i++) {
        XPE_DEF::IMAGE_SECTION_HEADER ish = listSections.at(i);
        peNew.setSectionHeader(i, reinterpret_cast<XPE_DEF::IMAGE_SECTION_HEADER *>(&ish));

        if (ish.PointerToRawData) {
            peNew.write_array(ish.PointerToRawData, pMemOut0 + ish.VirtualAddress, XBinary::align_up(ish.SizeOfRawData, nFileAlignment));
        }
    }

    XPE_DEF::IMAGE_DATA_DIRECTORY idd = {};
    peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_DEBUG, &idd);
    peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT, &idd);
    peNew.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &idd);
    peNew.setOptionalHeader_CheckSum(0);

    if (pe.isOverlayPresent(pPdStruct)) {
        const qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
        const qint64 nOverlaySize = pe.getOverlaySize(pPdStruct);

        if ((nOverlayOffset >= 0) && (nOverlaySize > 0)) {
            QByteArray baOverlay = read_array_process(nOverlayOffset, nOverlaySize, pPdStruct);

            if ((baOverlay.size() != nOverlaySize) || (!XBinary::isPdStructNotCanceled(pPdStruct))) {
                buffer.close();

                return fallback();
            }

            baResultFile.append(baOverlay);
        }
    }

    buffer.close();
    return _writeBufferToDevice(baResultFile, pDevice, pPdStruct);
}

bool XUPX::_unpackELF(QIODevice *pDevice, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    XELF elf(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!elf.isValid(pPdStruct)) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    bool bIsBE = (elf.getEndian() == ENDIAN_BIG);
    QByteArray baPInfo = read_array_process(info.nDataOffset, sizeof(p_info), pPdStruct);

    if (baPInfo.size() != (qint64)sizeof(p_info)) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    quint32 nOrigFileSize = XBinary::_read_uint32(baPInfo.data() + offsetof(p_info, p_filesize), bIsBE);
    quint32 nBlockSize = XBinary::_read_uint32(baPInfo.data() + offsetof(p_info, p_blocksize), bIsBE);

    if ((!nOrigFileSize) || (!nBlockSize) || (nBlockSize > nOrigFileSize)) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    qint64 nCurrentOffset = info.nDataOffset + sizeof(p_info);
    bool bReachedEnd = false;
    bool bStreamError = false;
    QByteArray baCurrentDecoded;
    qint64 nCurrentDecodedOffset = 0;

    auto loadNextBlock = [&]() -> bool {
        baCurrentDecoded.clear();
        nCurrentDecodedOffset = 0;

        QByteArray baBInfo = read_array_process(nCurrentOffset, sizeof(b_info), pPdStruct);

        if (baBInfo.size() != (qint64)sizeof(b_info)) {
            bStreamError = (baBInfo.size() != 0);
            return false;
        }

        b_info header = {};
        XBinary::_copyMemory((char *)&header, baBInfo.constData(), sizeof(b_info));

        quint32 nUncompressedSize = XBinary::_read_uint32((char *)&header.sz_unc, bIsBE);
        quint32 nCompressedSize = XBinary::_read_uint32((char *)&header.sz_cpr, bIsBE);
        nCurrentOffset += sizeof(b_info);

        if (nUncompressedSize == 0) {
            if (XBinary::_read_uint32((char *)&header.sz_cpr, false) == 0x21585055) {
                bReachedEnd = true;
            }

            return false;
        }

        if ((!nCompressedSize) || (nCompressedSize > nBlockSize) || (nUncompressedSize > nBlockSize)) {
            bStreamError = true;
            return false;
        }

        QByteArray baBlock = read_array_process(nCurrentOffset, nCompressedSize, pPdStruct);

        if ((quint32)baBlock.size() != nCompressedSize) {
            bStreamError = true;
            return false;
        }

        if (nCompressedSize < nUncompressedSize) {
            baCurrentDecoded.resize(nUncompressedSize);
            quint32 nDecodedSize = nUncompressedSize;

            if (!_upxDecompress((const unsigned char *)baBlock.constData(), nCompressedSize, (unsigned char *)baCurrentDecoded.data(), &nDecodedSize, header.b_method)) {
                baCurrentDecoded.clear();
                bStreamError = true;
                return false;
            }

            baCurrentDecoded.resize(nDecodedSize);

            if (header.b_ftid) {
                if (!applyUPXBlockFilter((unsigned char *)baCurrentDecoded.data(), baCurrentDecoded.size(), header.b_ftid, header.b_cto8)) {
                    baCurrentDecoded.clear();
                    bStreamError = true;
                    return false;
                }
            }
        } else if (nCompressedSize == nUncompressedSize) {
            baCurrentDecoded = baBlock;
        } else {
            bStreamError = true;
            return false;
        }

        nCurrentOffset += nCompressedSize;
        return true;
    };

    auto readDecodedBytes = [&](quint64 nWanted, QByteArray *pResult) -> bool {
        if ((!pResult) || (nWanted > (quint64)INT_MAX)) {
            return false;
        }

        pResult->clear();
        pResult->reserve((int)nWanted);

        while ((quint64)pResult->size() < nWanted && XBinary::isPdStructNotCanceled(pPdStruct)) {
            if (nCurrentDecodedOffset >= baCurrentDecoded.size()) {
                if (!loadNextBlock()) {
                    if (bStreamError) {
                        return false;
                    }

                    break;
                }
            }

            qint64 nChunkSize = qMin<qint64>((qint64)(nWanted - (quint64)pResult->size()), baCurrentDecoded.size() - nCurrentDecodedOffset);

            if (nChunkSize <= 0) {
                break;
            }

            pResult->append(baCurrentDecoded.constData() + nCurrentDecodedOffset, nChunkSize);
            nCurrentDecodedOffset += nChunkSize;
        }

        return ((quint64)pResult->size() == nWanted);
    };

    if (!loadNextBlock()) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    if (!baCurrentDecoded.startsWith("\x7f"
                                     "ELF")) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    QByteArray baHeaderBlock = baCurrentDecoded;
    QBuffer headerBuffer(&baHeaderBlock);

    if (!headerBuffer.open(QIODevice::ReadOnly)) {
        return false;
    }

    XELF unpackedElf(&headerBuffer, false, -1);

    if (!unpackedElf.isValid(pPdStruct)) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    QList<XELF_DEF::Elf_Phdr> listProgramHeaders = unpackedElf.getElf_PhdrList(0x1000);

    if (listProgramHeaders.isEmpty()) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    quint64 nHeaderSize = unpackedElf.is64() ? (unpackedElf.getHdr64_phoff() + (quint64)unpackedElf.getHdr64_phentsize() * unpackedElf.getHdr64_phnum())
                                             : (unpackedElf.getHdr32_phoff() + (quint64)unpackedElf.getHdr32_phentsize() * unpackedElf.getHdr32_phnum());

    if ((!nHeaderSize) || (nHeaderSize > (quint64)baHeaderBlock.size()) || (nHeaderSize > nOrigFileSize)) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    QByteArray baOutput(nOrigFileSize, 0);
    quint64 nPreviousSegmentEnd = 0;
    quint32 nLoadSegmentCount = 0;
    quint64 nDecodedLoadBytes = 0;

    for (qint32 i = 0; i < listProgramHeaders.count(); i++) {
        const XELF_DEF::Elf_Phdr &programHeader = listProgramHeaders.at(i);

        if (programHeader.p_type != XELF_DEF::S_PT_LOAD) {
            continue;
        }

        if ((!nLoadSegmentCount) && (programHeader.p_offset != 0)) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }

        if ((!programHeader.p_filesz) || (programHeader.p_offset > nOrigFileSize) || (programHeader.p_filesz > (quint64)nOrigFileSize) ||
            ((programHeader.p_offset + programHeader.p_filesz) > (quint64)nOrigFileSize)) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }

        if (programHeader.p_offset < nPreviousSegmentEnd) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }

        if ((!nLoadSegmentCount) && (programHeader.p_filesz < nHeaderSize)) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }

        QByteArray baSegmentData;

        if (!readDecodedBytes(programHeader.p_filesz, &baSegmentData)) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }

        XBinary::_copyMemory(baOutput.data() + programHeader.p_offset, baSegmentData.constData(), baSegmentData.size());
        nPreviousSegmentEnd = programHeader.p_offset + programHeader.p_filesz;
        nLoadSegmentCount++;
        nDecodedLoadBytes += programHeader.p_filesz;
    }

    if (!nLoadSegmentCount) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    auto decodeGapExtentsFromOffset = [&](qint64 nGapStreamOffset, QByteArray *pOutput) -> bool {
        if ((!pOutput) || (nGapStreamOffset < 0) || (nGapStreamOffset >= getSize())) {
            return false;
        }

        qint64 nSavedCurrentOffset = nCurrentOffset;
        bool bSavedReachedEnd = bReachedEnd;
        bool bSavedStreamError = bStreamError;
        QByteArray baSavedCurrentDecoded = baCurrentDecoded;
        qint64 nSavedCurrentDecodedOffset = nCurrentDecodedOffset;
        QByteArray baCandidateOutput = *pOutput;

        nCurrentOffset = nGapStreamOffset;
        baCurrentDecoded.clear();
        nCurrentDecodedOffset = 0;
        bReachedEnd = false;
        bStreamError = false;

        bool bResult = true;

        for (qint32 i = 0; i < listProgramHeaders.count(); i++) {
            const XELF_DEF::Elf_Phdr &programHeader = listProgramHeaders.at(i);

            if (programHeader.p_type != XELF_DEF::S_PT_LOAD) {
                continue;
            }

            quint64 nGapSize = findELFLoadGap(listProgramHeaders, i, nOrigFileSize);

            if (!nGapSize) {
                continue;
            }

            QByteArray baGapData;

            if (!readDecodedBytes(nGapSize, &baGapData)) {
                bResult = false;
                break;
            }

            XBinary::_copyMemory(baCandidateOutput.data() + programHeader.p_offset + programHeader.p_filesz, baGapData.constData(), baGapData.size());
        }

        if (bResult && (bStreamError || (nCurrentDecodedOffset < baCurrentDecoded.size()))) {
            bResult = false;
        }

        if (bResult) {
            *pOutput = baCandidateOutput;
        } else {
            nCurrentOffset = nSavedCurrentOffset;
            bReachedEnd = bSavedReachedEnd;
            bStreamError = bSavedStreamError;
            baCurrentDecoded = baSavedCurrentDecoded;
            nCurrentDecodedOffset = nSavedCurrentDecodedOffset;
        }

        return bResult;
    };

    auto seekToGapExtentStream = [&]() -> bool {
        qint64 nLInfoOffset = info.nDataOffset - (qint64)sizeof(l_info);

        if (nLInfoOffset < 0) {
            return false;
        }

        QByteArray baLInfo = read_array_process(nLInfoOffset, sizeof(l_info), pPdStruct);

        if (baLInfo.size() != (qint64)sizeof(l_info)) {
            return false;
        }

        quint32 nLMagic = XBinary::_read_uint32(baLInfo.data() + offsetof(l_info, l_magic), false);
        quint16 nLSize = XBinary::_read_uint16(baLInfo.data() + offsetof(l_info, l_lsize), bIsBE);

        if ((nLMagic != 0x21585055) || (nLSize < sizeof(l_info))) {
            return false;
        }

        QList<XELF_DEF::Elf_Phdr> listPackedProgramHeaders = elf.getElf_PhdrList(0x1000);

        if (listPackedProgramHeaders.isEmpty()) {
            return false;
        }

        quint64 nEntry = elf.is64() ? elf.getHdr64_entry() : elf.getHdr32_entry();
        quint16 nType = elf.is64() ? elf.getHdr64_type() : elf.getHdr32_type();
        quint16 nMachine = elf.is64() ? elf.getHdr64_machine() : elf.getHdr32_machine();

        quint64 nOffEntry = 0;

        for (qint32 i = 0; i < listPackedProgramHeaders.count(); i++) {
            const XELF_DEF::Elf_Phdr &programHeader = listPackedProgramHeaders.at(i);

            if ((programHeader.p_type == XELF_DEF::S_PT_LOAD) && (nEntry >= programHeader.p_vaddr) && ((nEntry - programHeader.p_vaddr) < programHeader.p_filesz)) {
                nOffEntry = (nEntry - programHeader.p_vaddr) + programHeader.p_offset;
                break;
            }
        }

        quint32 nDInfoSize = 0;

        if ((nType != XELF_DEF::S_ET_DYN) && (!listPackedProgramHeaders.isEmpty()) && (listPackedProgramHeaders.first().p_flags & 1)) {
            switch (nMachine) {
                case 183: nDInfoSize = 16; break;  // EM_AARCH64
                case 21: nDInfoSize = 12; break;   // EM_PPC64
                case 62: nDInfoSize = 8; break;    // EM_X86_64
                default: nDInfoSize = 0; break;
            }
        }

        QList<qint64> listCandidateOffsets;

        auto addCandidateOffset = [&](qint64 nOffset) {
            if ((0 <= nOffset) && (nOffset < getSize()) && (!listCandidateOffsets.contains(nOffset))) {
                listCandidateOffsets.append(nOffset);
            }
        };

        if ((listPackedProgramHeaders.count() >= 2) && (listPackedProgramHeaders.at(0).p_filesz == 0x1000) && (listPackedProgramHeaders.at(0).p_offset == 0) &&
            (listPackedProgramHeaders.at(1).p_offset == 0) && (listPackedProgramHeaders.at(1).p_filesz == listPackedProgramHeaders.at(1).p_memsz)) {
            addCandidateOffset((qint64)upxAlignUp(listPackedProgramHeaders.at(1).p_memsz, 4));
        }

        if ((nOffEntry) && ((nOffEntry + upxAlignUp(nLSize, 4) + info.nPackHeaderSize + sizeof(quint32)) < upxAlignUp(getSize(), 4))) {
            qint64 nLoaderOffset = (qint64)nOffEntry;

            if (nDInfoSize) {
                addCandidateOffset(nLoaderOffset - nDInfoSize + nLSize);
                addCandidateOffset(nLoaderOffset - nDInfoSize + upxAlignUp(nLSize, 4));
                addCandidateOffset(nLoaderOffset + nLSize);
            } else {
                addCandidateOffset((qint64)upxAlignUp(nLoaderOffset, 4) + nLSize);
                addCandidateOffset((qint64)upxAlignUp(nLoaderOffset, 4) + upxAlignUp(nLSize, 4));
                addCandidateOffset(nLoaderOffset + nLSize);
            }
        }

        if (listCandidateOffsets.isEmpty()) {
            return false;
        }

        QByteArray baCandidateOutput = baOutput;

        for (qint32 i = 0; i < listCandidateOffsets.count(); i++) {
            if (decodeGapExtentsFromOffset(listCandidateOffsets.at(i), &baCandidateOutput)) {
                baOutput = baCandidateOutput;
                return true;
            }
        }

        return false;
    };

    quint64 nGapTotal = nOrigFileSize - nDecodedLoadBytes;

    if (nGapTotal) {
        if (!seekToGapExtentStream()) {
            return _runUPXDecompress(pDevice, pPdStruct);
        }
    }

    if (bStreamError) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    if (nDecodedLoadBytes + nGapTotal != nOrigFileSize) {
        return _runUPXDecompress(pDevice, pPdStruct);
    }

    if (baOutput.startsWith("\x7f"
                            "ELF")) {
        return _writeBufferToDevice(baOutput, pDevice, pPdStruct);
    }

    return _runUPXDecompress(pDevice, pPdStruct);
}

bool XUPX::_unpackMach(QIODevice *pDevice, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    auto fallback = [&]() -> bool {
        return _runUPXDecompress(pDevice, pPdStruct);
    };

    XMACH mach(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!mach.isValid(pPdStruct)) {
        return fallback();
    }

    if ((mach.getFileType() == FT_MACHOFAT) || (mach.getType() == XMACH::TYPE_DYLIB)) {
        return fallback();
    }

    const bool bIsBE = (mach.getEndian() == ENDIAN_BIG);
    QByteArray baPInfo = read_array_process(info.nDataOffset, sizeof(p_info), pPdStruct);

    if (baPInfo.size() != (qint64)sizeof(p_info)) {
        return fallback();
    }

    const quint32 nOrigFileSize = XBinary::_read_uint32(baPInfo.data() + offsetof(p_info, p_filesize), bIsBE);
    const quint32 nBlockSize = XBinary::_read_uint32(baPInfo.data() + offsetof(p_info, p_blocksize), bIsBE);

    if ((!nOrigFileSize) || (!nBlockSize) || (nBlockSize > nOrigFileSize)) {
        return fallback();
    }

    qint64 nCurrentOffset = info.nDataOffset + sizeof(p_info);
    bool bReachedEnd = false;
    bool bStreamError = false;
    QByteArray baCurrentDecoded;
    qint64 nCurrentDecodedOffset = 0;

    auto loadNextBlock = [&]() -> bool {
        baCurrentDecoded.clear();
        nCurrentDecodedOffset = 0;

        QByteArray baBInfo = read_array_process(nCurrentOffset, sizeof(b_info), pPdStruct);

        if (baBInfo.size() != (qint64)sizeof(b_info)) {
            bStreamError = (baBInfo.size() != 0);
            return false;
        }

        b_info header = {};
        XBinary::_copyMemory((char *)&header, baBInfo.constData(), sizeof(b_info));

        const quint32 nUncompressedSize = XBinary::_read_uint32((char *)&header.sz_unc, bIsBE);
        const quint32 nCompressedSize = XBinary::_read_uint32((char *)&header.sz_cpr, bIsBE);
        nCurrentOffset += sizeof(b_info);

        if (nUncompressedSize == 0) {
            if (XBinary::_read_uint32((char *)&header.sz_cpr, false) == 0x21585055) {
                bReachedEnd = true;
            }

            return false;
        }

        if ((!nCompressedSize) || (nCompressedSize > nBlockSize) || (nUncompressedSize > nBlockSize)) {
            bStreamError = true;
            return false;
        }

        QByteArray baBlock = read_array_process(nCurrentOffset, nCompressedSize, pPdStruct);

        if ((quint32)baBlock.size() != nCompressedSize) {
            bStreamError = true;
            return false;
        }

        if (nCompressedSize < nUncompressedSize) {
            baCurrentDecoded.resize(nUncompressedSize);
            quint32 nDecodedSize = nUncompressedSize;

            if (!_upxDecompress((const unsigned char *)baBlock.constData(), nCompressedSize, (unsigned char *)baCurrentDecoded.data(), &nDecodedSize, header.b_method)) {
                baCurrentDecoded.clear();
                bStreamError = true;
                return false;
            }

            baCurrentDecoded.resize(nDecodedSize);

            if (header.b_ftid) {
                if (!applyUPXBlockFilter((unsigned char *)baCurrentDecoded.data(), baCurrentDecoded.size(), header.b_ftid, header.b_cto8)) {
                    baCurrentDecoded.clear();
                    bStreamError = true;
                    return false;
                }
            }
        } else if (nCompressedSize == nUncompressedSize) {
            baCurrentDecoded = baBlock;
        } else {
            bStreamError = true;
            return false;
        }

        nCurrentOffset += nCompressedSize;
        return true;
    };

    auto readDecodedBytes = [&](quint64 nWanted, QByteArray *pResult) -> bool {
        if ((!pResult) || (nWanted > (quint64)INT_MAX)) {
            return false;
        }

        pResult->clear();
        pResult->reserve((int)nWanted);

        while ((quint64)pResult->size() < nWanted && XBinary::isPdStructNotCanceled(pPdStruct)) {
            if (nCurrentDecodedOffset >= baCurrentDecoded.size()) {
                if (!loadNextBlock()) {
                    if (bStreamError) {
                        return false;
                    }

                    break;
                }
            }

            const qint64 nChunkSize = qMin<qint64>((qint64)(nWanted - (quint64)pResult->size()), baCurrentDecoded.size() - nCurrentDecodedOffset);

            if (nChunkSize <= 0) {
                break;
            }

            pResult->append(baCurrentDecoded.constData() + nCurrentDecodedOffset, nChunkSize);
            nCurrentDecodedOffset += nChunkSize;
        }

        return ((quint64)pResult->size() == nWanted);
    };

    if (!loadNextBlock()) {
        return fallback();
    }

    QBuffer previewBuffer(&baCurrentDecoded);

    if (!previewBuffer.open(QIODevice::ReadOnly)) {
        return fallback();
    }

    XMACH unpackedMach(&previewBuffer, false, -1);

    if (!unpackedMach.isValid(pPdStruct)) {
        return fallback();
    }

    if ((mach.getHeader_cputype() != unpackedMach.getHeader_cputype()) || (mach.getHeader_cpusubtype() != unpackedMach.getHeader_cpusubtype()) ||
        (mach.getHeader_filetype() != unpackedMach.getHeader_filetype())) {
        return fallback();
    }

    const quint64 nHeaderSize = unpackedMach.getHeaderSize() + unpackedMach.getHeader_sizeofcmds();

    if ((!nHeaderSize) || (nHeaderSize > (quint64)baCurrentDecoded.size()) || (nHeaderSize > nOrigFileSize)) {
        return fallback();
    }

    QList<XMACH::SEGMENT_RECORD> listSegments = unpackedMach.getSegmentRecords();

    if (listSegments.isEmpty()) {
        return fallback();
    }

    std::sort(listSegments.begin(), listSegments.end(), [](const XMACH::SEGMENT_RECORD &a, const XMACH::SEGMENT_RECORD &b) -> bool {
        const quint64 nAFileOffset = a.bIs64 ? a.s.segment64.fileoff : a.s.segment32.fileoff;
        const quint64 nBFileOffset = b.bIs64 ? b.s.segment64.fileoff : b.s.segment32.fileoff;

        if (nAFileOffset != nBFileOffset) {
            return nAFileOffset < nBFileOffset;
        }

        return a.nStructOffset < b.nStructOffset;
    });

    auto getSegmentFileOffset = [](const XMACH::SEGMENT_RECORD &record) -> quint64 {
        return record.bIs64 ? record.s.segment64.fileoff : record.s.segment32.fileoff;
    };

    auto getSegmentFileSize = [](const XMACH::SEGMENT_RECORD &record) -> quint64 {
        return record.bIs64 ? record.s.segment64.filesize : record.s.segment32.filesize;
    };

    auto findSegmentGap = [&](qint32 nIndex) -> quint64 {
        const quint64 nHigh = getSegmentFileOffset(listSegments.at(nIndex)) + getSegmentFileSize(listSegments.at(nIndex));
        quint64 nLow = nOrigFileSize;

        for (qint32 i = 0; i < listSegments.count(); i++) {
            if (i == nIndex) {
                continue;
            }

            const quint64 nOtherFileSize = getSegmentFileSize(listSegments.at(i));

            if (!nOtherFileSize) {
                continue;
            }

            const quint64 nOtherOffset = getSegmentFileOffset(listSegments.at(i));

            if ((nOtherOffset >= nHigh) && (nOtherOffset < nLow)) {
                nLow = nOtherOffset;
            }
        }

        return (nLow >= nHigh) ? (nLow - nHigh) : 0;
    };

    QByteArray baOutput(nOrigFileSize, 0);
    quint64 nPreviousEnd = 0;
    quint64 nDecodedTotal = 0;
    bool bHasFileBackedSegment = false;

    nCurrentOffset = info.nDataOffset + sizeof(p_info);
    baCurrentDecoded.clear();
    nCurrentDecodedOffset = 0;
    bReachedEnd = false;
    bStreamError = false;

    for (qint32 i = 0; i < listSegments.count(); i++) {
        const quint64 nFileOffset = getSegmentFileOffset(listSegments.at(i));
        const quint64 nFileSize = getSegmentFileSize(listSegments.at(i));

        if (!nFileSize) {
            continue;
        }

        if ((!bHasFileBackedSegment) && (nFileOffset != 0)) {
            return fallback();
        }

        if ((nFileOffset > nOrigFileSize) || (nFileSize > nOrigFileSize) || ((nFileOffset + nFileSize) > nOrigFileSize) || (nFileOffset < nPreviousEnd)) {
            return fallback();
        }

        if ((!bHasFileBackedSegment) && (nFileSize < nHeaderSize)) {
            return fallback();
        }

        QByteArray baSegmentData;

        if (!readDecodedBytes(nFileSize, &baSegmentData)) {
            return fallback();
        }

        XBinary::_copyMemory(baOutput.data() + nFileOffset, baSegmentData.constData(), baSegmentData.size());
        nDecodedTotal += nFileSize;

        const quint64 nGapSize = findSegmentGap(i);

        if (nGapSize) {
            QByteArray baGapData;

            if (!readDecodedBytes(nGapSize, &baGapData)) {
                return fallback();
            }

            XBinary::_copyMemory(baOutput.data() + nFileOffset + nFileSize, baGapData.constData(), baGapData.size());
            nDecodedTotal += nGapSize;
        }

        nPreviousEnd = nFileOffset + nFileSize;
        bHasFileBackedSegment = true;
    }

    if ((!bHasFileBackedSegment) || bStreamError || (nDecodedTotal != nOrigFileSize)) {
        return fallback();
    }

    if (nCurrentDecodedOffset < baCurrentDecoded.size()) {
        return fallback();
    }

    if (loadNextBlock() || bStreamError || (!bReachedEnd)) {
        return fallback();
    }

    QBuffer verifyBuffer(&baOutput);

    if (!verifyBuffer.open(QIODevice::ReadOnly)) {
        return fallback();
    }

    XMACH outputMach(&verifyBuffer, false, -1);

    if (!outputMach.isValid(pPdStruct)) {
        return fallback();
    }

    if ((outputMach.getHeader_cputype() != mach.getHeader_cputype()) || (outputMach.getHeader_cpusubtype() != mach.getHeader_cpusubtype()) ||
        (outputMach.getHeader_filetype() != mach.getHeader_filetype())) {
        return fallback();
    }

    return _writeBufferToDevice(baOutput, pDevice, pPdStruct);
}

bool XUPX::_unpackDOS(QIODevice *pDevice, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    auto fallback = [&]() -> bool {
        return _runUPXDecompress(pDevice, pPdStruct);
    };

    if ((!getDevice()) || (!pDevice) || (!info.c_len) || (!info.u_len)) {
        return false;
    }

    if ((info.format == UPX_F_DOS_COM) || (info.format == UPX_F_DOS_SYS)) {
        QByteArray baCompressed = read_array_process(info.nDataOffset, info.c_len, pPdStruct);

        if ((quint32)baCompressed.size() != info.c_len) {
            return fallback();
        }

        QByteArray baOutput(info.u_len, 0);
        quint32 nOutputSize = info.u_len;

        if (!_upxDecompress((const unsigned char *)baCompressed.constData(), info.c_len, (unsigned char *)baOutput.data(), &nOutputSize, info.method)) {
            return fallback();
        }

        baOutput.resize(nOutputSize);

        if (info.filter) {
            if (!applyPEFilter((unsigned char *)baOutput.data(), baOutput.size(), info.filter, info.filter_cto, 0x100)) {
                return fallback();
            }
        }

        if ((quint32)baOutput.size() != info.u_len) {
            return fallback();
        }

        return _writeBufferToDevice(baOutput, pDevice, pPdStruct);
    }

    if (!((info.format == UPX_F_DOS_EXE) || (info.format == UPX_F_DOS_EXEH))) {
        return fallback();
    }

    XMSDOS msdos(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!msdos.isValid(pPdStruct)) {
        return fallback();
    }

    QByteArray baExeHeader = read_array_process(0, sizeof(XMSDOS_DEF::EXE_file), pPdStruct);

    if (baExeHeader.size() != (qint64)sizeof(XMSDOS_DEF::EXE_file)) {
        return fallback();
    }

    XMSDOS_DEF::EXE_file ih = {};
    XBinary::_copyMemory((char *)&ih, baExeHeader.constData(), sizeof(ih));

    const quint32 nHeaderSize = (quint32)ih.exe_par_dir * 16;
    quint32 nExeSize = ih.exe_len_mod_512 + (quint32)ih.exe_pages * 512 - (ih.exe_len_mod_512 ? 512 : 0);

    if (nExeSize == 0) {
        nExeSize = (quint32)getSize();
    }

    if ((nExeSize < nHeaderSize) || (nExeSize > (quint32)getSize())) {
        return fallback();
    }

    const quint32 nImageSize = nExeSize - nHeaderSize;

    if (nImageSize < 4) {
        return fallback();
    }

    QByteArray baPackedImage = read_array_process(nHeaderSize, nImageSize, pPdStruct);

    if ((quint32)baPackedImage.size() != nImageSize) {
        return fallback();
    }

    const quint32 nPackedDataOffset = (quint32)(info.nDataOffset - nHeaderSize);

    if ((nPackedDataOffset >= (quint32)baPackedImage.size()) || (((quint64)nPackedDataOffset + info.c_len) > (quint64)baPackedImage.size())) {
        return fallback();
    }

    QByteArray baUnpacked(info.u_len, 0);
    quint32 nUnpackedSize = info.u_len;

    if (!_upxDecompress((const unsigned char *)baPackedImage.constData() + nPackedDataOffset, info.c_len, (unsigned char *)baUnpacked.data(), &nUnpackedSize, info.method)) {
        return fallback();
    }

    baUnpacked.resize(nUnpackedSize);

    if ((quint32)baUnpacked.size() != info.u_len) {
        return fallback();
    }

    quint32 nImageTail = nImageSize - 1;
    const quint8 nFlag = (quint8)baPackedImage.at(nImageTail);
    quint32 nPayloadSize = (quint32)baUnpacked.size();
    quint32 nRelocNum = 0;
    QByteArray baRelocs;

    if (!(nFlag & DOS_EXE_FLAG_NORELOC)) {
        if (nPayloadSize < 2) {
            return fallback();
        }

        quint16 nRelocSize = XBinary::_read_uint16((char *)baUnpacked.data() + nPayloadSize - 2, false);
        nPayloadSize -= 2;

        if ((nRelocSize < 11) || (nRelocSize > 0x6000) || (nRelocSize >= nImageTail) || (nRelocSize > nPayloadSize)) {
            return fallback();
        }

        const quint32 nRelocStart = nPayloadSize - nRelocSize;
        quint16 nOnes = XBinary::_read_uint16((char *)baUnpacked.data() + nRelocStart, false);
        quint16 nSegHigh = XBinary::_read_uint16((char *)baUnpacked.data() + nRelocStart + 2, false);
        quint32 nCursor = nRelocStart + 4;
        quint32 nES = 0;

        baRelocs.reserve(0x10000);

        while (nOnes) {
            if ((nCursor + 4) > nPayloadSize) {
                return fallback();
            }

            quint32 nDI = XBinary::_read_uint16((char *)baUnpacked.data() + nCursor, false);
            nES += XBinary::_read_uint16((char *)baUnpacked.data() + nCursor + 2, false);
            nCursor += 4;
            bool bDoRel = true;

            while (nOnes && (nDI < 0x10000) && (nCursor < nPayloadSize)) {
                if (bDoRel) {
                    char relocEntry[4] = {};
                    XBinary::_write_uint16(relocEntry, (quint16)nDI, false);
                    XBinary::_write_uint16(relocEntry + 2, (quint16)nES, false);
                    baRelocs.append(relocEntry, sizeof(relocEntry));
                    nRelocNum++;
                }

                bDoRel = true;
                quint8 nCode = (quint8)baUnpacked.at(nCursor);

                if (nCode == 0) {
                    quint32 nSearchOffset = nES * 16 + nDI;

                    while ((nSearchOffset + 4) < nPayloadSize) {
                        if (((quint8)baUnpacked.at(nSearchOffset) == 0x9a) && (XBinary::_read_uint16((char *)baUnpacked.data() + nSearchOffset + 3, false) <= nSegHigh)) {
                            break;
                        }

                        nSearchOffset++;
                    }

                    if ((nSearchOffset + 4) >= nPayloadSize) {
                        return fallback();
                    }

                    nDI = nSearchOffset - (nES * 16) + 3;
                } else if (nCode == 1) {
                    nDI += 254;

                    if (nDI < 0x10000) {
                        nOnes--;
                    }

                    bDoRel = false;
                } else {
                    nDI += nCode;
                }

                nCursor++;
            }
        }
    }

    XMSDOS_DEF::EXE_file oh = {};
    oh.exe_signature = XMSDOS_DEF::S_IMAGE_DOS_SIGNATURE_MZ;

    quint32 nRelocTableSize = baRelocs.size();

    if (nRelocNum) {
        oh.exe_rle_count = (quint16)nRelocNum;

        while (nRelocNum & 3) {
            baRelocs.append(4, 0);
            nRelocNum++;
        }

        nRelocTableSize = baRelocs.size();
    }

    quint32 nOutputLen = sizeof(XMSDOS_DEF::EXE_file) + nRelocTableSize + nPayloadSize;
    oh.exe_len_mod_512 = nOutputLen & 0x1ff;
    oh.exe_pages = (nOutputLen + 0x1ff) >> 9;
    oh.exe_par_dir = 2 + (nRelocNum / 4);
    oh.exe_max_BSS = ih.exe_max_BSS;
    oh.exe_min_BSS = ih.exe_min_BSS;
    oh.exe_SP = ih.exe_SP;
    oh.exe_SS = ih.exe_SS;

    if (nFlag & DOS_EXE_FLAG_MAXMEM) {
        if (nImageTail < 2) {
            return fallback();
        }

        nImageTail -= 2;
        oh.exe_max_BSS = XBinary::_read_uint16((char *)baPackedImage.data() + nImageTail, false);
    }

    if (nFlag & DOS_EXE_FLAG_MINMEM) {
        if (nImageTail < 2) {
            return fallback();
        }

        nImageTail -= 2;
        oh.exe_min_BSS = XBinary::_read_uint16((char *)baPackedImage.data() + nImageTail, false);
    }

    if (nFlag & DOS_EXE_FLAG_SP) {
        if (nImageTail < 2) {
            return fallback();
        }

        nImageTail -= 2;
        oh.exe_SP = XBinary::_read_uint16((char *)baPackedImage.data() + nImageTail, false);
    }

    if (nFlag & DOS_EXE_FLAG_SS) {
        if (nImageTail < 2) {
            return fallback();
        }

        nImageTail -= 2;
        oh.exe_SS = XBinary::_read_uint16((char *)baPackedImage.data() + nImageTail, false);
    }

    quint32 nIP = (nFlag & DOS_EXE_FLAG_USEJUMP) ? 0 : ih.exe_sym_tab;

    if (nFlag & DOS_EXE_FLAG_USEJUMP) {
        if (nImageTail < 4) {
            return fallback();
        }

        nIP = XBinary::_read_uint32((char *)baPackedImage.data() + nImageTail - 4, false);
    }

    oh.exe_IP = nIP & 0xffff;
    oh.exe_CS = (nIP >> 16) & 0xffff;
    oh.exe_rle_table = sizeof(XMSDOS_DEF::EXE_file);
    oh.exe_iov = 0;
    oh.exe_sym_tab = 0;

    QByteArray baResult;
    baResult.reserve(nOutputLen + qMax<qint64>(0, getSize() - nExeSize));
    baResult.append((const char *)&oh, sizeof(oh));

    if (!baRelocs.isEmpty()) {
        baResult.append(baRelocs);
    }

    baResult.append(baUnpacked.constData(), nPayloadSize);

    if ((quint32)getSize() > nExeSize) {
        QByteArray baOverlay = read_array_process(nExeSize, getSize() - nExeSize, pPdStruct);

        if (baOverlay.size() != (getSize() - nExeSize)) {
            return fallback();
        }

        baResult.append(baOverlay);
    }

    return _writeBufferToDevice(baResult, pDevice, pPdStruct);
}

bool XUPX::_runUPXDecompress(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pPdStruct)

    // Keep the shared fallback hook, but do not shell out to the system "upx".
    // XUPX now relies exclusively on its in-process unpackers.
    return false;
}

QList<XBinary::FPART> XUPX::getFileParts(quint32 nFileParts, qint32 nLimit, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(nLimit)

    QList<FPART> listResult;

    if (nFileParts & FILEPART_HEADER) {
        FPART record = {};

        record.filePart = FILEPART_HEADER;
        record.nFileOffset = 0;
        record.nFileSize = 0;  // TODO
        record.nVirtualAddress = -1;
        record.sName = tr("Header");

        listResult.append(record);
    }

    if (nFileParts & FILEPART_DATA) {
        FPART record = {};

        record.filePart = FILEPART_DATA;
        record.nFileOffset = 0;        // TODO
        record.nFileSize = getSize();  // TODO
        record.nVirtualAddress = -1;
        record.sName = tr("Data");

        listResult.append(record);
    }

    if (nFileParts & FILEPART_OVERLAY) {
        qint64 nOverlayOffset = getOverlayOffset();

        if (nOverlayOffset != -1) {
            FPART record = {};

            record.filePart = FILEPART_OVERLAY;
            record.nFileOffset = nOverlayOffset;
            record.nFileSize = getSize() - nOverlayOffset;
            record.nVirtualAddress = -1;
            record.sName = tr("Overlay");

            listResult.append(record);
        }
    }

    return listResult;
}

