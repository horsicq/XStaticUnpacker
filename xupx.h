/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XUPX_H
#define XUPX_H

#include "xbinary.h"
#include "xpe.h"
#include "xelf.h"

class XUPX : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        FT fileType;
        char magic[4];
        quint8 version;
        quint8 format;
        quint8 method;
        quint8 level;
        quint8 filter_cto;
        quint32 u_len;
        quint32 c_len;
        quint32 u_adler;
        quint32 c_adler;
        quint32 u_file_size;
        quint8 n_mru;
        quint32 off_filter;
        quint32 nPackHeaderSize;
    };
#pragma pack(push)
#pragma pack(1)
    struct l_info { // 12-byte trailer in header for loader
        quint32 l_checksum; // adler32 checksum of unpacked data LE
        quint32 l_magic; // 'UPX!' LE
        quint16 l_lsize; // length of this structure LE
        quint8 l_version;
        quint8 l_format;
    };
    struct p_info { // 12-byte packed program header
        quint32 p_progid; // 'UPX!' BE
        quint32 p_filesize; // original file size BE
        quint32 p_blocksize; // block size BE
    };
    struct b_info { // 12-byte header before each compressed block
        quint32 sz_unc;  // uncompressed_size BE
        quint32 sz_cpr;  // compressed_size BE
        unsigned char b_method;  // compression algorithm
        unsigned char b_ftid;  // filter id
        unsigned char b_cto8;  // filter parameter
        unsigned char b_extra; // reserved
    };
#pragma pack(pop)
    // Executable formats (info: big endian types are >= 128); DO NOT CHANGE
    enum UPX_F {
        UPX_F_DOS_COM = 1,
        UPX_F_DOS_SYS = 2,
        UPX_F_DOS_EXE = 3,
        UPX_F_DJGPP2_COFF = 4,
        UPX_F_WATCOM_LE = 5,
        // 6 reserved (VXD_LE) // NOT IMPLEMENTED
        UPX_F_DOS_EXEH = 7,  // OBSOLETE
        UPX_F_TMT_ADAM = 8,
        UPX_F_W32PE_I386 = 9,
        UPX_F_LINUX_i386 = 10,
        // 11 reserved (WIN16_NE) // NOT IMPLEMENTED
        UPX_F_LINUX_ELF_i386 = 12,
        // 13 reserved (LINUX_SEP_i386) // NOT IMPLEMENTED
        UPX_F_LINUX_SH_i386 = 14,
        UPX_F_VMLINUZ_i386 = 15,
        UPX_F_BVMLINUZ_i386 = 16,
        UPX_F_ELKS_8086 = 17,  // NOT IMPLEMENTED
        UPX_F_PS1_EXE = 18,
        UPX_F_VMLINUX_i386 = 19,
        UPX_F_LINUX_ELFI_i386 = 20,
        UPX_F_WINCE_ARM = 21,  // Windows CE
        UPX_F_LINUX_ELF64_AMD64 = 22,
        UPX_F_LINUX_ELF32_ARM = 23,
        UPX_F_BSD_i386 = 24,
        UPX_F_BSD_ELF_i386 = 25,
        UPX_F_BSD_SH_i386 = 26,
        UPX_F_VMLINUX_AMD64 = 27,
        UPX_F_VMLINUX_ARM = 28,
        UPX_F_MACH_i386 = 29,
        UPX_F_LINUX_ELF32_MIPSEL = 30,
        UPX_F_VMLINUZ_ARM = 31,
        UPX_F_MACH_ARM = 32,
        UPX_F_DYLIB_i386 = 33,
        UPX_F_MACH_AMD64 = 34,
        UPX_F_DYLIB_AMD64 = 35,
        UPX_F_W64PE_AMD64 = 36,
        UPX_F_MACH_ARM64 = 37,
        // 38 reserved (MACH_PPC64LE) // DOES NOT EXIST
        UPX_F_LINUX_ELF64_PPC64LE = 39,
        UPX_F_VMLINUX_PPC64LE = 40,
        // 41 reserved (DYLIB_PPC64LE) // DOES NOT EXIST
        UPX_F_LINUX_ELF64_ARM64 = 42,
        UPX_F_W64PE_ARM64 = 43,    // NOT YET IMPLEMENTED
        UPX_F_W64PE_ARM64EC = 44,  // NOT YET IMPLEMENTED

        UPX_F_ATARI_TOS = 129,
        // 130 reserved (SOLARIS_SPARC) // NOT IMPLEMENTED
        UPX_F_MACH_PPC32 = 131,
        UPX_F_LINUX_ELF32_PPC32 = 132,
        UPX_F_LINUX_ELF32_ARMEB = 133,
        UPX_F_MACH_FAT = 134,
        UPX_F_VMLINUX_ARMEB = 135,
        UPX_F_VMLINUX_PPC32 = 136,
        UPX_F_LINUX_ELF32_MIPS = 137,
        UPX_F_DYLIB_PPC32 = 138,
        UPX_F_MACH_PPC64 = 139,
        UPX_F_LINUX_ELF64_PPC64 = 140,
        UPX_F_VMLINUX_PPC64 = 141,
        UPX_F_DYLIB_PPC64 = 142
    };

    explicit XUPX(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XUPX() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

private:
    INTERNAL_INFO _read_packheader(char *pInfoData, qint32 nDataSize, bool bIsBigEndian);
};

#endif  // XUPX_H
