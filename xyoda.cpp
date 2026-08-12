/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xyoda.h"

#include <cstring>

static inline quint8 yodaRol8(quint8 v, quint8 n)
{
    return (quint8)((v << (n & 7)) | (v >> ((8 - n) & 7)));
}

static inline quint8 yodaRor8(quint8 v, quint8 n)
{
    return (quint8)((v >> (n & 7)) | (v << ((8 - n) & 7)));
}

// bounds test for the poly-decryptor emulator's file accesses
static inline bool yodaOob(qint64 nOff, qint64 nFileSize)
{
    return (nOff < 0) || (nOff >= nFileSize);
}

XYODA::XYODA(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XYODA::~XYODA()
{
}

bool XYODA::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XYODA::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XYODA yoda(pDevice);
    return yoda.isValid(pPdStruct);
}

XBinary::FT XYODA::getFileType()
{
    return FT_BINARY;
}

QString XYODA::getVersion()
{
    INTERNAL_INFO info = *static_cast<INTERNAL_INFO *>(getInternalInfo());
    return info.bIsValid ? info.sVersion : QString();
}

XYODA::INTERNAL_INFO XYODA::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XYODA::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = _getInternalInfo(pPdStruct);
        setIsInternalInfoHandled(true);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XYODA::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XYODA::setInternalInfo(void *pInternalInfo)
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
// poly byte-decryptor emulator
// ---------------------------------------------------------------------------

int XYODA::_polyEmulate(quint8 *pBase, qint64 nFileSize, qint64 nDecOff, qint64 nCodeOff, quint32 nEcx, quint32 nMaxEmu)
{
    quint8 cl = (quint8)(nEcx & 0xff);
    quint32 nMaxJmp = 100000000;

    for (quint32 i = 0; (i < nEcx) && (i < nMaxEmu); i++) {
        if (yodaOob(nCodeOff + i, nFileSize)) return 2;
        quint8 al = pBase[nCodeOff + i];

        for (int j = 0; j < 0x30; j++) {
            if (yodaOob(nDecOff + j, nFileSize)) return 2;
            quint8 op = pBase[nDecOff + j];

            switch (op) {
                case 0xEB:  // JMP short
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (!nMaxJmp) return 2;
                    nMaxJmp--;
                    j = j + (qint8)pBase[nDecOff + j];
                    break;
                case 0xFE:  // DEC AL
                    al--;
                    j++;
                    break;
                case 0x2A:  // SUB AL,CL
                    al = (quint8)(al - cl);
                    j++;
                    break;
                case 0x02:  // ADD AL,CL
                    al = (quint8)(al + cl);
                    j++;
                    break;
                case 0x32:  // XOR AL,CL
                    al ^= cl;
                    j++;
                    break;
                case 0x04:  // ADD AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al = (quint8)(al + pBase[nDecOff + j]);
                    break;
                case 0x34:  // XOR AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al ^= pBase[nDecOff + j];
                    break;
                case 0x2C:  // SUB AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    al = (quint8)(al - pBase[nDecOff + j]);
                    break;
                case 0xC0:  // ROL/ROR AL,imm
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (pBase[nDecOff + j] == 0xC0) {
                        j++;
                        if (yodaOob(nDecOff + j, nFileSize)) return 2;
                        al = yodaRol8(al, pBase[nDecOff + j]);
                    } else {
                        j++;
                        if (yodaOob(nDecOff + j, nFileSize)) return 2;
                        al = yodaRor8(al, pBase[nDecOff + j]);
                    }
                    break;
                case 0xD2:  // ROL/ROR AL,CL
                    j++;
                    if (yodaOob(nDecOff + j, nFileSize)) return 2;
                    if (pBase[nDecOff + j] == 0xC8) {
                        j++;
                        al = yodaRor8(al, cl);
                    } else {
                        j++;
                        al = yodaRol8(al, cl);
                    }
                    break;
                case 0x90:
                case 0xf8:
                case 0xf9:
                    break;
                default:
                    return 1;
            }
        }

        cl--;
        if (yodaOob(nCodeOff + i, nFileSize)) return 2;
        pBase[nCodeOff + i] = al;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

XYODA::INTERNAL_INFO XYODA::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) {
        return result;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) {
        return result;
    }

    const quint32 nEpRva = pe.getOptionalHeader_AddressOfEntryPoint();
    if (nEpRva != listSections.at(n - 1).VirtualAddress + 0x60) {
        return result;
    }

    qint64 nEpOffset = pe.relAddressToOffset(nEpRva);
    if (nEpOffset == -1) {
        return result;
    }

    QByteArray baEp = read_array_process(nEpOffset, 0x80, pPdStruct);
    if (baEp.size() < 0x80) {
        return result;
    }
    const char *ep = baEp.constData();

    qint32 nOffset = 0;
    quint32 nEcx = 0;
    QString sVersion;

    // yC 1.3
    if ((memcmp(ep, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED", 15) == 0) &&
        (memcmp(ep + 0x26, "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) == 0) && ((quint8)ep[0x13] == 0xB9) &&
        (_read_uint16((char *)ep + 0x18) == 0xE981) && (memcmp(ep + 0x1e, "\x8B\xD5\x81\xC2", 4) == 0)) {
        nOffset = 0;
        if (0x6c - _read_uint32((char *)ep + 0xf) + _read_uint32((char *)ep + 0x22) == 0xC6) {
            nEcx = _read_uint32((char *)ep + 0x14) - _read_uint32((char *)ep + 0x1a);
            sVersion = "1.3";
        }
    }

    // yC 1.3 variant
    if (!nEcx && (memcmp(ep, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) == 0) && (memcmp(ep + 0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) == 0) &&
        ((quint8)ep[0x23] == 0xB9)) {
        nOffset = 0x10;
        if (0x6c - _read_uint32((char *)ep + 0x1f) + _read_uint32((char *)ep + 0x32) == 0xC6) {
            nEcx = _read_uint32((char *)ep + 0x24) - _read_uint32((char *)ep + 0x2a);
            sVersion = "1.3 (variant)";
        }
    }

    // yC 1.x / modified
    if (!nEcx && (memcmp(ep, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", 9) == 0) && ((quint8)ep[0xd] == 0xb9) && (_read_uint16((char *)ep + 0x12) == 0xbd8d) &&
        (memcmp(ep + 0x18, "\x8b\xf7\xac", 3) == 0)) {
        nOffset = -0x18;
        if (0x66 - _read_uint32((char *)ep + 0x9) + _read_uint32((char *)ep + 0x14) == 0xae) {
            nEcx = _read_uint32((char *)ep + 0xe);
            sVersion = "1.x (modified)";
        }
    }

    if ((nEcx <= 0x800) || (nEcx >= 0x2000)) {
        return result;
    }

    qint64 nMarkerIdx = 0x63 + nOffset;
    if ((nMarkerIdx < 0) || (nMarkerIdx + 3 > baEp.size()) || (memcmp(ep + nMarkerIdx, "\xaa\xe2\xcc", 3) != 0)) {
        return result;
    }

    const quint64 nLastRaw = listSections.at(n - 1).PointerToRawData;
    if ((quint64)getSize() < nLastRaw + 0xC6 + nEcx + nOffset) {
        return result;
    }

    result.bIsValid = true;
    result.sVersion = sVersion;
    result.nOffset = nOffset;
    result.nEcx = nEcx;

    return result;
}

// ---------------------------------------------------------------------------
// streaming API
// ---------------------------------------------------------------------------

QMap<XBinary::UNPACK_PROP, QVariant> XYODA::getDefaultUnpackProperties()
{
    QMap<XBinary::UNPACK_PROP, QVariant> result = XBinary::getDefaultUnpackProperties();

    return result;
}

bool XYODA::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
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

    if (!_detect(pPdStruct).bIsValid) {
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

XBinary::ARCHIVERECORD XYODA::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
    result.mapProperties.insert(FPART_PROP_INFO, QString("Yoda %1").arg(getVersion()));

    return result;
}

bool XYODA::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if ((!pState) || (!pState->pContext) || !isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;

    return (pState->nCurrentIndex < pState->nNumberOfRecords);
}

bool XYODA::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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

bool XYODA::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
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

bool XYODA::_unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct)
{
    baOut.clear();

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct) || pe.is64()) return false;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    const int n = listSections.size();
    if (n <= 1) return false;
    const int nSectCount = n - 1;  // yC section is the last one

    const qint64 nFileSize = getSize();
    QByteArray baFile = read_array_process(0, nFileSize, pPdStruct);
    if (baFile.size() != nFileSize) return false;
    quint8 *pBase = (quint8 *)baFile.data();

    const qint64 nLastRaw = listSections.at(nSectCount).PointerToRawData;
    const qint64 nYcSect = nLastRaw + info.nOffset;

    // layer 1: decrypt the section-decryptor code
    if (_polyEmulate(pBase, nFileSize, nYcSect + 0x93, nYcSect + 0xc6, info.nEcx, info.nEcx) != 0) {
        return false;
    }

    const qint64 nCurFileSize = nFileSize - (qint64)listSections.at(nSectCount).SizeOfRawData;
    if (nCurFileSize <= 0) return false;
    if (nCurFileSize > 0x7fffffff) return false;

    // layer 2: decrypt each original section
    const qint64 nDecOff = nYcSect + ((info.nOffset == -0x18) ? 0x3ea : 0x457);

    for (int i = 0; i < nSectCount; i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &sec = listSections.at(i);
        const quint32 nName = _read_uint32((char *)sec.Name);

        if ((sec.PointerToRawData == 0) || (sec.SizeOfRawData == 0) || (nName == 0x63727372) || (nName == 0x7273722E) || (nName == 0x6F6C6572) ||
            (nName == 0x6C65722E) || (nName == 0x6164652E) || (nName == 0x6164722E) || (nName == 0x6164692E) || (nName == 0x736C742E) ||
            ((nName & 0xffff) == 0x4379)) {
            continue;
        }

        if ((qint64)sec.PointerToRawData >= nCurFileSize) {
            continue;
        }
        quint32 nMaxEmu = (quint32)(nCurFileSize - sec.PointerToRawData);

        if (_polyEmulate(pBase, nFileSize, nDecOff, sec.PointerToRawData, sec.SizeOfRawData, nMaxEmu) != 0) {
            return false;
        }

        if (!isPdStructNotCanceled(pPdStruct)) return false;
    }

    // header fixups
    const qint64 nPeOff = _read_uint32((char *)pBase + 0x3C);
    if ((nPeOff <= 0) || (nPeOff + 0x18 + 0x40 > nFileSize)) return false;

    _write_uint16((char *)pBase + nPeOff + 6, (quint16)nSectCount);           // NumberOfSections
    memset(pBase + nPeOff + 0x18 + 0x68, 0, 8);                               // clear import directory
    if ((nYcSect + 0xa0f + 4) <= nFileSize) {
        _write_uint32((char *)pBase + nPeOff + 0x18 + 16, _read_uint32((char *)pBase + nYcSect + 0xa0f));  // OEP
    }
    quint32 nSizeOfImage = _read_uint32((char *)pBase + nPeOff + 0x18 + 0x38);
    _write_uint32((char *)pBase + nPeOff + 0x18 + 0x38, nSizeOfImage - listSections.at(nSectCount).Misc.VirtualSize);  // SizeOfImage

    baOut = baFile.left((int)nCurFileSize);

    return true;
}


