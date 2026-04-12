/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xupx.h"

#include "Algos/xucldecoder.h"
#include "LzmaDec.h"

#include <QDir>
#include <QBuffer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
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

namespace {
using IMAGE_DOS_HEADEREX = XMSDOS_DEF::IMAGE_DOS_HEADEREX;
using IMAGE_NT_HEADERS32 = XPE_DEF::IMAGE_NT_HEADERS32;
using IMAGE_NT_HEADERS64 = XPE_DEF::IMAGE_NT_HEADERS64;
using IMAGE_SECTION_HEADER = XPE_DEF::IMAGE_SECTION_HEADER;
using IMAGE_IMPORT_DESCRIPTOR = XPE_DEF::IMAGE_IMPORT_DESCRIPTOR;
using IMAGE_EXPORT_DIRECTORY = XPE_DEF::IMAGE_EXPORT_DIRECTORY;
using IMAGE_RESOURCE_DATA_ENTRY = XPE_DEF::IMAGE_RESOURCE_DATA_ENTRY;

const qint64 XUPX_TRAILER_READ_SIZE = 0x3000;
const qint64 XUPX_HEADER_SEARCH_SIZE = 0x1000;
const qint64 XUPX_PACK_HEADER_SIZE = 36;
const qint64 XUPX_MIN_PACK_HEADER_SIZE = 20;

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
}  // namespace

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

bool XUPX::_copyFileToDevice(const QString &sInputFileName, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if ((!pDevice) || (sInputFileName.isEmpty())) {
        return false;
    }

    bool bCloseOutputDevice = false;

    if (!_prepareOutputDevice(pDevice, &bCloseOutputDevice)) {
        return false;
    }

    QFile fileUnpacked(sInputFileName);

    if (!fileUnpacked.open(QIODevice::ReadOnly)) {
        if (bCloseOutputDevice) {
            pDevice->close();
        }

        return false;
    }

    const qint64 nChunkSize = 0x100000;
    bool bResult = true;

    while (!fileUnpacked.atEnd() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        QByteArray baData = fileUnpacked.read(nChunkSize);

        if (baData.isEmpty() && !fileUnpacked.atEnd()) {
            bResult = false;
            break;
        }

        if ((!baData.isEmpty()) && (pDevice->write(baData) != baData.size())) {
            bResult = false;
            break;
        }
    }

    fileUnpacked.close();

    if (bCloseOutputDevice) {
        pDevice->close();
    }

    return bResult && XBinary::isPdStructNotCanceled(pPdStruct);
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
        } else if (_isDOSFileType(info.fileType) || _isDOSFormat(info.format)) {
            bResult = _runUPXDecompress(pDevice, pPdStruct);
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
    if ((!getDevice()) || (!pDevice) || (!info.c_len) || (!info.u_len)) {
        return false;
    }

    QByteArray baCompressed = read_array_process(info.nDataOffset, info.c_len, pPdStruct);

    if ((quint32)baCompressed.size() != info.c_len) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    QByteArray baPayload(info.u_len, 0);
    quint32 nPayloadSize = info.u_len;

    if (!_upxDecompress((const unsigned char *)baCompressed.constData(), (quint32)baCompressed.size(), (unsigned char *)baPayload.data(), &nPayloadSize, info.method)) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    baPayload.resize(nPayloadSize);

    XPE pe(this->getDevice(), this->isImage(), this->getModuleAddress());

    if (!pe.isValid(pPdStruct)) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    bool bIs64 = pe.is64();
    IMAGE_DOS_HEADEREX idh = pe.getDosHeaderEx();
    QByteArray baStub = pe.getDosStub();
    qint64 nBaseAddress = pe.getBaseAddress();

    if (baPayload.size() < 4) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    quint32 nExtraInfoOffset = XBinary::_read_uint32(baPayload.data() + baPayload.size() - 4, false);

    if ((!bIs64) && ((quint64)nExtraInfoOffset + sizeof(IMAGE_NT_HEADERS32) > (quint64)baPayload.size())) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    if ((bIs64) && ((quint64)nExtraInfoOffset + sizeof(IMAGE_NT_HEADERS64) > (quint64)baPayload.size())) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    char *pExtraInfo = baPayload.data() + nExtraInfoOffset;
    IMAGE_NT_HEADERS32 ih32 = {};
    IMAGE_NT_HEADERS64 ih64 = {};
    quint32 nFileAlignment = 0;
    quint32 nSectionAlignment = 0;
    qint64 nRVAmin = 0;
    QList<IMAGE_SECTION_HEADER> listSections;
    int nNumberOfSections = 0;
    quint32 nBaseOfCode = 0;
    quint32 nSizeOfCode = 0;

    if (!bIs64) {
        XBinary::_copyMemory((char *)&ih32, pExtraInfo, sizeof(IMAGE_NT_HEADERS32));
        nFileAlignment = ih32.OptionalHeader.FileAlignment;
        nSectionAlignment = ih32.OptionalHeader.SectionAlignment;
        nRVAmin = XBinary::align_up(ih32.OptionalHeader.SizeOfHeaders, nSectionAlignment);
        nNumberOfSections = ih32.FileHeader.NumberOfSections;
        nBaseOfCode = ih32.OptionalHeader.BaseOfCode;
        nSizeOfCode = ih32.OptionalHeader.SizeOfCode;
        pExtraInfo += sizeof(IMAGE_NT_HEADERS32);
    } else {
        XBinary::_copyMemory((char *)&ih64, pExtraInfo, sizeof(IMAGE_NT_HEADERS64));
        nFileAlignment = ih64.OptionalHeader.FileAlignment;
        nSectionAlignment = ih64.OptionalHeader.SectionAlignment;
        nRVAmin = XBinary::align_up(ih64.OptionalHeader.SizeOfHeaders, nSectionAlignment);
        nNumberOfSections = ih64.FileHeader.NumberOfSections;
        nBaseOfCode = ih64.OptionalHeader.BaseOfCode;
        nSizeOfCode = ih64.OptionalHeader.SizeOfCode;
        pExtraInfo += sizeof(IMAGE_NT_HEADERS64);
    }

    if (((!bIs64) && (ih32.Signature != XPE_DEF::S_IMAGE_NT_SIGNATURE)) || ((bIs64) && (ih64.Signature != XPE_DEF::S_IMAGE_NT_SIGNATURE))) {
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    for (int i = 0; i < nNumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader = {};
        XBinary::_copyMemory((char *)&sectionHeader, pExtraInfo, sizeof(IMAGE_SECTION_HEADER));
        listSections.append(sectionHeader);
        pExtraInfo += sizeof(IMAGE_SECTION_HEADER);
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
            return _fallbackUnpack(pDevice, pPdStruct);
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
                return _fallbackUnpack(pDevice, pPdStruct);
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
                XBinary::_write_uint32(pIID + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name), (quint32)(pDllNames - pMemOut0), false);
                pDllNames += nNameSize + 1;
            } else {
                strcpy(pMemOut0 + XBinary::_read_uint32(pIID + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name), false), pDName);
            }

            XBinary::_write_uint32(pIID + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk), nIAT, false);
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
                        return _fallbackUnpack(pDevice, pPdStruct);
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

            pIID += sizeof(IMAGE_IMPORT_DESCRIPTOR);
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

        XBinary::_write_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, Name), XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, Name), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions),
                               XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames),
                               XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames), false) - nDelta, false);
        XBinary::_write_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals),
                               XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals), false) - nDelta, false);

        quint32 nNumberOfNames = XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames), false);
        quint32 nAddressOfNames = XBinary::_read_uint32(pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames), false);
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
            nMaxOffset = qMax((quint32)(listResources.at(i).nIRDEOffset + sizeof(IMAGE_RESOURCE_DATA_ENTRY)), nMaxOffset);

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
        IMAGE_SECTION_HEADER ish = listSections.at(i);

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
        return _fallbackUnpack(pDevice, pPdStruct);
    }

    XPE peNew(&buffer);
    qint64 nCurrentOffset = 0;
    peNew.write_array(nCurrentOffset, (char *)&idh, sizeof(IMAGE_DOS_HEADEREX));
    nCurrentOffset += sizeof(IMAGE_DOS_HEADEREX);
    peNew.write_array(nCurrentOffset, baStub.data(), baStub.size());
    nCurrentOffset += baStub.size();

    if (!bIs64) {
        peNew.write_array(nCurrentOffset, (char *)&ih32, sizeof(IMAGE_NT_HEADERS32));
    } else {
        peNew.write_array(nCurrentOffset, (char *)&ih64, sizeof(IMAGE_NT_HEADERS64));
    }

    for (int i = 0; i < listSections.count(); i++) {
        IMAGE_SECTION_HEADER ish = listSections.at(i);
        peNew.setSectionHeader(i, &ish);

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

                return _fallbackUnpack(pDevice, pPdStruct);
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

    QByteArray baOutput;
    QBuffer buffer(&baOutput);

    if (!buffer.open(QIODevice::WriteOnly)) {
        return false;
    }

    qint64 nCurrentOffset = info.nDataOffset + sizeof(p_info);
    quint32 nTotalOut = 0;
    bool bReachedEnd = false;

    while (XBinary::isPdStructNotCanceled(pPdStruct)) {
        QByteArray baBInfo = read_array_process(nCurrentOffset, sizeof(b_info), pPdStruct);

        if (baBInfo.size() != (qint64)sizeof(b_info)) {
            break;
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

            break;
        }

        if ((!nCompressedSize) || (nCompressedSize > nBlockSize) || (nUncompressedSize > nBlockSize)) {
            break;
        }

        QByteArray baBlock = read_array_process(nCurrentOffset, nCompressedSize, pPdStruct);

        if ((quint32)baBlock.size() != nCompressedSize) {
            break;
        }

        QByteArray baDecoded;

        if (nCompressedSize < nUncompressedSize) {
            baDecoded.resize(nUncompressedSize);
            quint32 nDecodedSize = nUncompressedSize;

            if (!_upxDecompress((const unsigned char *)baBlock.constData(), nCompressedSize, (unsigned char *)baDecoded.data(), &nDecodedSize, header.b_method)) {
                break;
            }

            baDecoded.resize(nDecodedSize);

            if (header.b_ftid) {
                if (!applyPEFilter((unsigned char *)baDecoded.data(), baDecoded.size(), header.b_ftid, header.b_cto8, 0)) {
                    break;
                }
            }
        } else if (nCompressedSize == nUncompressedSize) {
            baDecoded = baBlock;
        } else {
            break;
        }

        if (buffer.write(baDecoded) != baDecoded.size()) {
            return false;
        }

        nTotalOut += baDecoded.size();
        nCurrentOffset += nCompressedSize;
    }

    buffer.close();

    if (bReachedEnd && (nTotalOut == nOrigFileSize) && baOutput.startsWith("\x7f"
                                                                           "ELF")) {
        return _writeBufferToDevice(baOutput, pDevice, pPdStruct);
    }

    return _runUPXDecompress(pDevice, pPdStruct);
}

bool XUPX::_runUPXDecompress(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if ((!getDevice()) || (!pDevice)) {
        return false;
    }

    QString sUPX = QStandardPaths::findExecutable("upx");

    if (sUPX.isEmpty()) {
        return false;
    }

    QTemporaryDir tempDir;

    if (!tempDir.isValid()) {
        return false;
    }

    QString sTempInputFileName = tempDir.filePath("packed_input.bin");
    QString sTempOutputFileName = tempDir.filePath("unpacked_output.bin");

    if (!XBinary::dumpToFile(sTempInputFileName, getDevice(), pPdStruct)) {
        return false;
    }

    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);

    QStringList listArgs;
    listArgs << "-d" << "-q" << "--no-color" << "--no-backup" << "--force-overwrite" << QString("-o%1").arg(sTempOutputFileName) << sTempInputFileName;

    process.start(sUPX, listArgs);

    if (!process.waitForStarted()) {
        return false;
    }

    while (process.state() != QProcess::NotRunning) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            process.kill();
            process.waitForFinished();

            return false;
        }

        process.waitForFinished(100);
    }

    if ((process.exitStatus() != QProcess::NormalExit) || (process.exitCode() != 0)) {
        return false;
    }

    QFileInfo fiResult(sTempOutputFileName);

    return fiResult.exists() && fiResult.isFile() && (fiResult.size() >= 0) && _copyFileToDevice(sTempOutputFileName, pDevice, pPdStruct);
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

