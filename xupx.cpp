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

XBinary::XCONVERT _TABLE_XUPX_STRUCTID[] = {
    {XUPX::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XUPX::STRUCTID_HEADER, "HEADER", QString("Header")},
};

XUPX::XUPX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
}

XUPX::~XUPX()
{
}

QString XUPX::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_XUPX_STRUCTID, sizeof(_TABLE_XUPX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

bool XUPX::isValid(PDSTRUCT *pPdStruct)
{
    return getInternalInfo(pPdStruct).bIsValid;
}

bool XUPX::isValid(QIODevice *pDevice)
{
    XUPX upx(pDevice);

    return upx.isValid();
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

    return result;
}

XUPX::INTERNAL_INFO XUPX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    XUPX::INTERNAL_INFO result = {};

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

                if ((result.magic[0] == 'U') && (result.magic[1] == 'P') && (result.magic[2] == 'X') && (result.magic[3] == '!')) {
                    result.bIsValid = true;
                    result.fileType = elf.getFileType();

                    qint64 nDataOffset = XBinary::_read_uint32_safe(pBuffer, nBufferSize, nBufferSize - 36 + result.nPackHeaderSize, bIsBE);
                    l_info linfo = {};
                    read_array(nDataOffset - sizeof(l_info), (char *)(&linfo), sizeof(l_info), pPdStruct);
                    p_info pinfo = {};
                    read_array(nDataOffset, (char *)(&pinfo), sizeof(p_info), pPdStruct);
                    b_info binfo = {};
                    read_array(nDataOffset + sizeof(p_info), (char *)(&binfo), sizeof(b_info), pPdStruct);

                    result.u_len = qFromBigEndian(pinfo.p_filesize);
                    result.c_len = qFromBigEndian(binfo.sz_cpr);

                    bFound = true;
                }
            }

            delete[] pBuffer;
        }
    }

    if (!bFound) {
        XPE pe(this->getDevice(), this->isImage(), this->getModuleAddress());
        if (pe.isValid(pPdStruct)) {
            result.fileType = pe.getFileType();

            // Check for UPX signature in the file
            qint64 nFileSize = this->getSize();
            if (nFileSize >= 0x1000) {
                qint64 nOffset = find_ansiString(0, 0x1000, "UPX!");
                
                if (nOffset != -1) {
                    // Read UPX header
                    char headerData[36];
                    if (read_array(nOffset, headerData, 36, pPdStruct)) {
                        result = _read_packheader(headerData, 36, false);
                        
                        if ((result.magic[0] == 'U') && (result.magic[1] == 'P') &&
                            (result.magic[2] == 'X') && (result.magic[3] == '!')) {
                            result.bIsValid = true;
                            result.fileType = pe.getFileType();
                            bFound = true;
                        }
                    }
                }
            }
            
            // Alternative detection: Check for UPX sections
            if (!bFound) {
                // QList<XPE::SECTION_RECORD> listSections = pe.getSectionRecords();
                // bool bHasUPX0 = false;
                // bool bHasUPX1 = false;
                
                // for (int i = 0; i < listSections.count(); i++) {
                //     QString sSectionName = listSections.at(i).sName;
                //     if (sSectionName.contains("UPX0")) {
                //         bHasUPX0 = true;
                //     } else if (sSectionName.contains("UPX1")) {
                //         bHasUPX1 = true;
                //     }
                // }
                
                // if (bHasUPX0 && bHasUPX1) {
                //     // This looks like a UPX packed PE file
                //     result.bIsValid = true;
                //     result.fileType = pe.getFileType();
                    
                //     // Try to find UPX signature in the last section
                //     if (listSections.count() > 0) {
                //         XPE::SECTION_RECORD lastSection = listSections.last();
                //         qint64 nSectionOffset = lastSection.nOffset;
                //         qint64 nSectionSize = lastSection.nSize;
                        
                //         if (nSectionSize > 36) {
                //             char *pSectionData = new char[nSectionSize];
                //             if (read_array(nSectionOffset, pSectionData, nSectionSize, pPdStruct)) {
                //                 // Look for UPX signature near the end of the section
                //                 for (qint64 i = nSectionSize - 36; i >= 0; i--) {
                //                     if ((pSectionData[i] == 'U') && (pSectionData[i+1] == 'P') &&
                //                         (pSectionData[i+2] == 'X') && (pSectionData[i+3] == '!')) {
                //                         result = _read_packheader(pSectionData + i, 36, false);
                //                         break;
                //                     }
                //                 }
                //             }
                //             delete[] pSectionData;
                //         }
                //     }
                    
                //     bFound = true;
                // }
            }
        }
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
    return QString::number(info.version);
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

bool XUPX::unpack(const QString &sOutputFileName, PDSTRUCT *pPdStruct)
{
    bool bResult = false;
    
    INTERNAL_INFO info = getInternalInfo(pPdStruct);
    
    if (info.bIsValid) {
        if ((info.fileType == FT_PE32) || (info.fileType == FT_PE64)) {
            bResult = _unpackPE(sOutputFileName, info, pPdStruct);
        } else if ((info.fileType == FT_ELF32) || (info.fileType == FT_ELF64)) {
            bResult = _unpackELF(sOutputFileName, info, pPdStruct);
        }
    }
    
    return bResult;
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
        switch (info.method) {
            case 2: return "NRV2B_LE32";
            case 3: return "NRV2B_8";
            case 4: return "NRV2B_LE16";
            case 5: return "NRV2D_LE32";
            case 6: return "NRV2D_8";
            case 7: return "NRV2D_LE16";
            case 8: return "NRV2E_LE32";
            case 9: return "NRV2E_8";
            case 10: return "NRV2E_LE16";
            case 14: return "LZMA";
            case 15: return "DEFLATE";
            default: return QString("Unknown (%1)").arg(info.method);
        }
    }
    return QString();
}

bool XUPX::_unpackPE(const QString &sOutputFileName, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(sOutputFileName)
    Q_UNUSED(info)
    Q_UNUSED(pPdStruct)
    
    // TODO: Implement PE unpacking
    // This would require:
    // 1. Reading compressed data
    // 2. Decompressing using the appropriate algorithm
    // 3. Reconstructing the PE file structure
    // 4. Handling import table reconstruction
    // 5. Handling relocations
    // 6. Applying filters
    
    return false;
}

bool XUPX::_unpackELF(const QString &sOutputFileName, const INTERNAL_INFO &info, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(sOutputFileName)
    Q_UNUSED(info)
    Q_UNUSED(pPdStruct)
    
    // TODO: Implement ELF unpacking
    // This would require:
    // 1. Reading compressed data
    // 2. Decompressing using the appropriate algorithm
    // 3. Reconstructing the ELF file structure
    
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
