/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xupx.h"

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

XUPX::XUPX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XUPX::~XUPX()
{
}

bool XUPX::isValid(PDSTRUCT *pPdStruct)
{
    return getUPXInfo(pPdStruct).bIsValid;
}

XUPX::UPX_INFO XUPX::_read_packheader(char *pInfoData, qint32 nDataSize, bool bIsBigEndian)
{
    XUPX::UPX_INFO result = {};

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

    return result;
}

XUPX::UPX_INFO XUPX::getUPXInfo(PDSTRUCT *pPdStruct)
{
    XUPX::UPX_INFO result = {};

    bool bFound = false;

    if (!bFound) {
        XELF elf(this->getDevice(), this->isImage(), this->getModuleAddress());
        if (elf.isValid(pPdStruct)) {
            bool bIsBE = (getEndian() == ENDIAN_BIG);
            result.fileType = elf.getFileType();

            qint64 nBufferSize = 0x3000;

            nBufferSize = qMin(nBufferSize, this->getSize());

            char *pBuffer = new char[nBufferSize];

            elf.read_array(this->getSize() - nBufferSize, pBuffer, nBufferSize, pPdStruct);

            nBufferSize = getPhysSize(pBuffer, nBufferSize);
            nBufferSize = align_up(nBufferSize, 4);

            if (nBufferSize >= 36) {
                result = _read_packheader(pBuffer + nBufferSize - 36, 36, bIsBE);
                qint64 nDataOffset = XBinary::_read_uint32_safe(pBuffer, nBufferSize, nBufferSize - 36 + result.nPackHeaderSize, bIsBE);
                // TODO
            }

            delete[] pBuffer;

            // TODO
            bFound = true;
        }
    }

    if (!bFound) {
        XPE pe(this->getDevice(), this->isImage(), this->getModuleAddress());
        if (pe.isValid(pPdStruct)) {
            result.fileType = pe.getFileType();

            // TODO
            bFound = true;
        }
    }

    // TODO

    return result;
}
