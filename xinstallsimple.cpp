/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xinstallsimple.h"
#include "xmaterializedunpackguard.h"

#ifdef USE_XEMULATOR

#include <new>

#include <QBuffer>
#include <QScopedPointer>
#include <QScopedValueRollback>
#include <QSet>
#include <QUuid>

#include "../XEmulator/arch/xemux86.h"
#include "../XEmulator/xemumemorymanager.h"
#include "../XEmulator/xemuregisters.h"
#include "subdevice.h"
#include "xpe.h"
#include "xupx.h"

namespace {

const quint32 IS_IMAGE_BASE = 0x00400000;
const quint32 IS_INIT = 0x00401000;
const quint32 IS_DRIVER = 0x00401090;
const quint32 IS_TRAP = 0x00700000;
const quint32 IS_RETURN_TRAP = IS_TRAP + 0x100;
const quint32 IS_OUTER = 0x00900000;
const quint32 IS_HEAP = 0x01000000;
const quint32 IS_HEAP_SIZE = 0x02000000;
const quint32 IS_INPUT = 0x04000000;
const quint32 IS_OUTPUT = 0x08000000;
const quint32 IS_OUTPUT_SIZE = 0x04000000;
const quint32 IS_STACK = 0x00300000;
const quint32 IS_STACK_SIZE = 0x00100000;
const quint64 IS_MAX_EMULATOR_STEPS = Q_UINT64_C(100000000);
const qint64 IS_CANCEL_CHECK_STEPS = 100000;
const int IS_MAX_RECORD_COUNT = 1024;
const int IS_MAX_PAYLOAD_COUNT = 1023;
const quint64 IS_MAX_TOTAL_DECODED_SIZE = Q_UINT64_C(256) * 1024 * 1024;
const qint64 IS_MAX_PACKED_STUB_SIZE = Q_INT64_C(64) * 1024 * 1024;
const qint64 IS_MAX_UNPACKED_STUB_SIZE = Q_INT64_C(32) * 1024 * 1024;
const qint64 IS_MAX_ENCODED_ARCHIVE_SIZE = Q_INT64_C(256) * 1024 * 1024;
const qint64 IS_MAX_ENCODED_RECORD_SIZE = (qint64)IS_OUTPUT - IS_INPUT;

class ISBoundedBuffer : public QBuffer {
public:
    ISBoundedBuffer(QByteArray *pData, qint64 nLimit) : QBuffer(pData), m_nLimit(nLimit) {}

protected:
    qint64 writeData(const char *pData, qint64 nSize) override
    {
        if ((nSize < 0) || (pos() < 0) || (pos() > m_nLimit) || (nSize > m_nLimit - pos())) return -1;
        return QBuffer::writeData(pData, nSize);
    }

private:
    qint64 m_nLimit;
};

static quint32 isRd32(const quint8 *p)
{
    return (quint32)p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24);
}

static qint64 isInstallerDataEnd(XPE *pPe, qint64 nFileSize)
{
    if (!pPe || (nFileSize <= 0)) return -1;
    qint64 nResult = nFileSize;
    XBinary::OFFSETSIZE osSignature = pPe->getSignOffsetSize();
    if ((osSignature.nOffset > 0) && (osSignature.nSize > 0) &&
        (osSignature.nOffset <= nFileSize) && (osSignature.nSize == nFileSize - osSignature.nOffset)) {
        nResult = osSignature.nOffset;
    }
    return nResult;
}

static bool isMap(XEmuMemoryManager *pMemory, quint32 nAddress, quint64 nSize, bool bExec, const QString &sName)
{
    if ((!pMemory) || (!nSize)) return false;
    nSize = XEmuMemoryManager::alignUp(nSize, XEmuMemoryManager::N_PAGE_SIZE);
    return pMemory->mapFixed(nAddress, nSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, bExec, false), sName);
}

static bool isLoadDecoderImage(const QByteArray &baStub, XEmuMemoryManager *pMemory)
{
    QBuffer buffer;
    buffer.setData(baStub);
    if (!buffer.open(QIODevice::ReadOnly)) return false;

    XPE pe(&buffer);
    if (!pe.isValid() || pe.is64() || (pe.getOptionalHeader_ImageBase() != IS_IMAGE_BASE)) return false;

    quint32 nImageSize = pe.getOptionalHeader_SizeOfImage();
    if ((nImageSize < 0xB000) || (nImageSize > 0x01000000) || !isMap(pMemory, IS_IMAGE_BASE, nImageSize, true, QStringLiteral("InstallSimple stub"))) {
        return false;
    }

    const QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
    for (int i = 0; i < listSections.size(); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &section = listSections.at(i);
        quint64 nRawOffset = section.PointerToRawData;
        quint64 nRawSize = section.SizeOfRawData;
        quint64 nVirtualAddress = section.VirtualAddress;
        if (!nRawSize) continue;
        if ((nRawOffset + nRawSize > (quint64)baStub.size()) || (nVirtualAddress + nRawSize > nImageSize)) return false;
        if (!pMemory->write(IS_IMAGE_BASE + nVirtualAddress, baStub.constData() + nRawOffset, nRawSize)) return false;
    }

    // Both supported builders share this decoder. Refuse to execute an unknown
    // stub even though the VM is sandboxed and instruction-budgeted.
    static const char kInitSignature[] = "\x53\x55\x56\x57\x8b\x74\x24\x14\x33\xd2\x8b\x6c\x24\x18\x8b\x46";
    static const char kDriverSignature[] = "\x8b\x44\x24\x04\x56\x8b\x70\x20\x85\xf6\x75\x09\xb8\xfe\xff\xff";
    QByteArray baInit = pMemory->read(IS_INIT, sizeof(kInitSignature) - 1);
    QByteArray baDriver = pMemory->read(IS_DRIVER, sizeof(kDriverSignature) - 1);
    return (baInit == QByteArray(kInitSignature, sizeof(kInitSignature) - 1)) &&
           (baDriver == QByteArray(kDriverSignature, sizeof(kDriverSignature) - 1));
}

static bool isCallDecoder(XEmuMemoryManager *pMemory, XEmuX86 *pArch, XEmuRegisters *pRegisters, quint32 nFunction, const QList<quint32> &listArguments,
                          quint32 *pnHeapNext, quint32 *pnResult, quint64 *pnStepsRemaining, XBinary::PDSTRUCT *pPdStruct)
{
    if ((!pMemory) || (!pArch) || (!pRegisters) || (!pnHeapNext) || (!pnResult) || (!pnStepsRemaining)) return false;

    quint32 nStack = IS_STACK + IS_STACK_SIZE - 0x1000;
    for (int i = listArguments.size() - 1; i >= 0; i--) {
        nStack -= 4;
        if (!pMemory->writeDword(nStack, listArguments.at(i))) return false;
    }
    nStack -= 4;
    if (!pMemory->writeDword(nStack, IS_RETURN_TRAP)) return false;

    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, nStack);
    pRegisters->nRIP = nFunction;

    while (*pnStepsRemaining) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        qint64 nChunk = (qint64)qMin<quint64>(*pnStepsRemaining, (quint64)IS_CANCEL_CHECK_STEPS);
        XEmuArch::STEP_INFO stopInfo;
        qint64 nRan = pArch->run(pRegisters, nChunk, &stopInfo);
        if ((nRan <= 0) || (nRan > nChunk)) return false;
        *pnStepsRemaining -= (quint64)nRan;

        // A STEP_OK result means the bounded run slice completed normally.
        // Continue with the same register state after checking cancellation.
        if (stopInfo.result == XEmuArch::STEP_OK) {
            if (nRan != nChunk) return false;
            continue;
        }
        if ((stopInfo.result != XEmuArch::STEP_HALT) || ((stopInfo.nAddress != IS_TRAP) && (stopInfo.nAddress != IS_RETURN_TRAP))) return false;

        if (stopInfo.nAddress == IS_RETURN_TRAP) {
            *pnResult = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 4);
            return true;
        }

        // The decoder's sole callback is stdcall allocator(ctx,size,flag).
        // XEmuMemoryManager mappings are zero-filled, matching HeapAlloc(HEAP_ZERO_MEMORY).
        quint32 nEsp = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
        bool bOk = false;
        quint32 nReturn = pMemory->readDword(nEsp, &bOk);
        if (!bOk) return false;
        quint32 nAllocationSize = pMemory->readDword(nEsp + 8, &bOk);
        if (!bOk || !nAllocationSize) return false;

        quint64 nAllocationEnd = (quint64)(*pnHeapNext) + XEmuMemoryManager::alignUp(nAllocationSize, 16) + 16;
        if (nAllocationEnd > (quint64)IS_HEAP + IS_HEAP_SIZE) return false;

        quint32 nAllocation = *pnHeapNext;
        *pnHeapNext = (quint32)nAllocationEnd;
        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 4, nAllocation);
        pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, nEsp + 16);
        pRegisters->nRIP = nReturn;
    }

    return false;
}

static bool isDecodeStream(const QByteArray &baStub, const QByteArray &baStream, QByteArray *pbaOutput, bool *pbUsedExhaustionFallback,
                           quint64 *pnStepsRemaining, XBinary::PDSTRUCT *pPdStruct)
{
    if ((!pbaOutput) || (!pbUsedExhaustionFallback) || (!pnStepsRemaining) || (baStream.size() < 12) || (baStream.size() > 0x10000000)) return false;
    pbaOutput->clear();
    *pbUsedExhaustionFallback = false;

    XEmuMemoryManager memory;
    memory.setBits(32);
    if (!isLoadDecoderImage(baStub, &memory)) return false;
    if (!isMap(&memory, IS_STACK, IS_STACK_SIZE, false, QStringLiteral("InstallSimple stack")) ||
        !isMap(&memory, IS_TRAP, 0x1000, true, QStringLiteral("InstallSimple traps")) ||
        !isMap(&memory, IS_OUTER, 0x1000, false, QStringLiteral("InstallSimple context")) ||
        !isMap(&memory, IS_HEAP, IS_HEAP_SIZE, false, QStringLiteral("InstallSimple heap")) ||
        !isMap(&memory, IS_INPUT, (quint64)baStream.size(), false, QStringLiteral("InstallSimple input")) ||
        !isMap(&memory, IS_OUTPUT, IS_OUTPUT_SIZE, false, QStringLiteral("InstallSimple output"))) {
        return false;
    }

    if (!memory.writeByte(IS_TRAP, 0xF4) || !memory.writeByte(IS_RETURN_TRAP, 0xF4) || !memory.write(IS_INPUT, baStream)) return false;

    if (!memory.writeDword(IS_OUTER + 0x00, IS_INPUT) || !memory.writeDword(IS_OUTER + 0x04, (quint32)baStream.size()) ||
        !memory.writeDword(IS_OUTER + 0x10, IS_OUTPUT) || !memory.writeDword(IS_OUTER + 0x14, IS_OUTPUT_SIZE) ||
        !memory.writeDword(IS_OUTER + 0x24, IS_TRAP)) {
        return false;
    }

    XEmuX86 arch(&memory, 32);
    XEmuRegisters registers;
    quint32 nHeapNext = IS_HEAP + 0x1000;
    quint32 nResult = 0;

    QList<quint32> listInitArguments;
    listInitArguments << IS_OUTER << 0 << 0;
    if (!isCallDecoder(&memory, &arch, &registers, IS_INIT, listInitArguments, &nHeapNext, &nResult, pnStepsRemaining, pPdStruct)) return false;

    bool bFinished = false;
    quint32 nPreviousTotal = 0xFFFFFFFF;
    for (int i = 0; i < 500; i++) {
        QList<quint32> listDriverArguments;
        listDriverArguments << IS_OUTER;
        if (!isCallDecoder(&memory, &arch, &registers, IS_DRIVER, listDriverArguments, &nHeapNext, &nResult, pnStepsRemaining, pPdStruct)) return false;

        bool bOk = false;
        quint32 nRemaining = memory.readDword(IS_OUTER + 0x04, &bOk);
        if (!bOk) return false;
        quint32 nTotal = memory.readDword(IS_OUTER + 0x18, &bOk);
        if (!bOk || (nTotal > IS_OUTPUT_SIZE)) return false;

        // The decoder returns -1 only for the authenticated end marker.
        // The other negative statuses are malformed-stream errors, not
        // alternate successful terminators.
        if (nResult == 0xFFFFFFFF) {
            bFinished = true;
            break;
        }
        if ((nResult == 0xFFFFFFFE) || (nResult == 0xFFFFFFFD) || (nResult == 0xFFFFFFFC)) return false;
        if ((nRemaining == 0) && (nTotal == nPreviousTotal)) {
            // A few manifest/config records exhaust their range-coded input
            // without returning the normal -1 marker. The caller may accept
            // this fallback only after the decoded bytes pass the strict
            // InstallSimple manifest grammar; payload records must end at -1.
            bFinished = true;
            *pbUsedExhaustionFallback = true;
            break;
        }
        nPreviousTotal = nTotal;
    }

    bool bOk = false;
    quint32 nRemaining = memory.readDword(IS_OUTER + 0x04, &bOk);
    if (!bOk) return false;
    quint32 nTotal = memory.readDword(IS_OUTER + 0x18, &bOk);
    if (!bOk) return false;
    quint32 nOverflow = memory.readDword(IS_OUTER + 0x1C, &bOk);
    // A valid range-coded record consumes all input or leaves at most 15
    // framing/padding bytes. More remaining input means that an authenticated
    // prefix was followed by unvalidated data.
    if (!bOk || !bFinished || (nRemaining > 15) || (*pbUsedExhaustionFallback && nRemaining) || nOverflow || (nTotal > IS_OUTPUT_SIZE)) return false;

    *pbaOutput = memory.read(IS_OUTPUT, nTotal, &bOk);
    return bOk && ((quint32)pbaOutput->size() == nTotal);
}

static bool isParseManifest(const QByteArray &baData, int nPayloadCount, QStringList *pListNames)
{
    if ((!pListNames) || (nPayloadCount <= 0) || (baData.size() < 32)) return false;
    pListNames->clear();

    // The manifest begins with nineteen zero bytes. This keeps an arbitrary
    // packaged file containing the product string from being mistaken for it.
    for (int i = 0; i < 19; i++) {
        if (baData.at(i) != 0) return false;
    }

    QByteArray baMarker("InstallSimple", 13);
    baMarker.append('\0');
    baMarker.append('\0');
    int nPosition = baData.indexOf(baMarker);
    if (nPosition < 19) return false;
    nPosition += baMarker.size();

    QSet<QString> setNames;
    static const QString sForbidden = QStringLiteral("<>:\"/\\|?*");
    static const QSet<QString> setReserved = {
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),  QStringLiteral("NUL"),  QStringLiteral("COM1"),
        QStringLiteral("COM2"), QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"), QStringLiteral("COM6"),
        QStringLiteral("COM7"), QStringLiteral("COM8"), QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"), QStringLiteral("LPT6"), QStringLiteral("LPT7"),
        QStringLiteral("LPT8"), QStringLiteral("LPT9"), QStringLiteral("CONIN$"), QStringLiteral("CONOUT$"), QStringLiteral("CLOCK$")};

    for (int i = 0; i < nPayloadCount; i++) {
        int nEnd = baData.indexOf('\0', nPosition);
        if ((nEnd <= nPosition) || (nEnd - nPosition > 255)) return false;

        QByteArray baName = baData.mid(nPosition, nEnd - nPosition);
        for (int j = 0; j < baName.size(); j++) {
            quint8 nCharacter = (quint8)baName.at(j);
            if ((nCharacter < 0x20) || (nCharacter > 0x7E)) return false;
        }
        QString sName = QString::fromLatin1(baName);
        if ((sName == ".") || (sName == "..") || sName.endsWith(' ') || sName.endsWith('.')) return false;
        for (QChar character : sName) {
            if (sForbidden.contains(character)) return false;
        }
        QString sStem = sName.section('.', 0, 0).toUpper();
        sStem.replace(QChar(0x00B9), QLatin1Char('1'));
        sStem.replace(QChar(0x00B2), QLatin1Char('2'));
        sStem.replace(QChar(0x00B3), QLatin1Char('3'));
        QString sNameKey = sName.toCaseFolded();
        if (setReserved.contains(sStem) || setNames.contains(sNameKey)) return false;
        setNames.insert(sNameKey);
        pListNames->append(sName);

        // Each file name is followed by a fixed ten-byte descriptor.
        nPosition = nEnd + 1;
        if (nPosition + 10 > baData.size()) return false;
        nPosition += 10;
    }

    return pListNames->size() == nPayloadCount;
}

}  // namespace

XInstallSimple::XInstallSimple(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_pUnpackLifetimeState = QSharedPointer<LIFETIME_STATE>::create();
    setIsArchive(true);
}

XInstallSimple::UNPACK_CONTEXT::~UNPACK_CONTEXT()
{
    delete pSourceGuard;
}

XInstallSimple::~XInstallSimple()
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

XInstallSimple::LIFETIME_STATE::~LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> setContextsCopy = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : setContextsCopy) delete pContext;
}

bool XInstallSimple::isDeviceReplacementAllowed() const
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    return pLifetimeState && pLifetimeState->bOwnerAlive && !pLifetimeState->bOperationInProgress && pLifetimeState->setContexts.isEmpty();
}

bool XInstallSimple::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XInstallSimple> guardedThis(this);
    const INTERNAL_INFO *pInfo =
        static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XInstallSimple::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XInstallSimple x(pDevice);
    return x.isValid(pPdStruct);
}

XInstallSimple::INTERNAL_INFO XInstallSimple::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XInstallSimple::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XInstallSimple> guardedThis(this);
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

void *XInstallSimple::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XInstallSimple> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;

    return &guardedThis->m_internalInfo;
}

void XInstallSimple::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XInstallSimple::getFileType()
{
    XPE pe(getDevice());

    if (pe.isValid() && pe.is64()) {
        return FT_PE64_INSTALLSIMPLE;
    }

    return FT_PE32_INSTALLSIMPLE;
}

XInstallSimple::INTERNAL_INFO XInstallSimple::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    qint64 nDataEnd = isInstallerDataEnd(&pe, getSize());
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= nDataEnd)) return result;

    // The pre-built engine stub is fixed per builder revision -> AEP identifies it.
    quint32 nAEP = (quint32)pe.getOptionalHeader_AddressOfEntryPoint();
    if (nAEP == 0xE830) {
        result.sVersion = "3.5.2";
    } else if (nAEP == 0xE860) {
        result.sVersion = "3.5";
    } else {
        return result;
    }

    // UPX-packed stub layout. The bytes after the record's 0xFFFFFFFF word are
    // range-coded data and must not be treated as a fixed family signature.
    const QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);
    if (listSections.size() != 3) return result;
    static const char *const pszSectionNames[3] = {"UPX0", "UPX1", ".rsrc"};
    for (int i = 0; i < 3; i++) {
        QByteArray baName((const char *)listSections.at(i).Name, 8);
        int nZero = baName.indexOf('\0');
        if (nZero >= 0) baName.truncate(nZero);
        if (baName != pszSectionNames[i]) return result;
    }

    // Validate two independently-coded records. Every valid package contains
    // at least one payload record followed by its manifest (or another payload
    // and then the manifest).
    QByteArray baFirst = read_array_process(nOverlayOffset, qMin<qint64>(nDataEnd - nOverlayOffset, 12), pPdStruct);
    if (baFirst.size() != 12) return result;
    quint32 nFirstLength = isRd32((const quint8 *)baFirst.constData());
    if ((isRd32((const quint8 *)baFirst.constData() + 4) != 0xFFFFFFFF) || (nFirstLength < 12) ||
        ((qint64)nFirstLength - 6 > IS_MAX_ENCODED_RECORD_SIZE - 6)) {
        return result;
    }

    qint64 nSecondOffset = nOverlayOffset + (qint64)nFirstLength - 6;
    if ((nSecondOffset > nDataEnd - 12) || (nSecondOffset <= nOverlayOffset)) return result;
    QByteArray baSecond = read_array_process(nSecondOffset, 12, pPdStruct);
    if ((baSecond.size() != 12) || (isRd32((const quint8 *)baSecond.constData() + 4) != 0xFFFFFFFF)) return result;
    quint32 nSecondLength = isRd32((const quint8 *)baSecond.constData());
    if ((nSecondLength < 12) || ((qint64)nSecondLength - 6 > IS_MAX_ENCODED_RECORD_SIZE - 6) ||
        ((qint64)nSecondLength - 6 > nDataEnd - nSecondOffset)) {
        return result;
    }

    result.bIsValid = true;
    return result;
}

bool XInstallSimple::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;
    const PDSTRUCTLIFETIME progressLifetime = pPdStruct ? retainPdStructLifetime(pPdStruct) : PDSTRUCTLIFETIME();
    const auto isProgressAlive = [&]() -> bool {
        return !pPdStruct || isPdStructLifetimeAlive(progressLifetime);
    };
    if (!isProgressAlive()) return false;
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XInstallSimple> guardedThis(this);
    if (pState->pContext || !pState->baUnpackSourceToken.isEmpty()) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pOldContext || !pLifetimeState->setContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState) ||
            (pOldContext->baToken != pState->baUnpackSourceToken)) return false;
        pLifetimeState->setContexts.remove(pOldContext);
        *pState = UNPACK_STATE();
        delete pOldContext;
    } else {
        *pState = UNPACK_STATE();
    }
    if (!isProgressAlive() || !guardedThis || !isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<QIODevice> guardedSource(getDevice());
    const quint64 nGeneration = getDeviceGeneration();
    const bool bIsImage = isImage();
    const XADDR nModuleAddress = getModuleAddress();
    if (!guardedSource) return false;
    const qint64 nSourceSize = guardedSource->size();
    if (!isProgressAlive() || !guardedThis || !guardedSource || (nSourceSize < 0) || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;
    QScopedPointer<XMaterializedUnpackGuard> pSourceGuard(XMaterializedUnpackGuard::bind(guardedSource.data(), pPdStruct));
    if (!isProgressAlive() || !pSourceGuard || !guardedThis || !guardedSource || (getDeviceGeneration() != nGeneration) ||
        (getDevice() != guardedSource.data())) return false;
    if (!m_bTrustedSnapshot) {
        QScopedPointer<QIODevice> pSnapshot(createFileBuffer(nSourceSize, pPdStruct));
        if (!isProgressAlive() || !guardedThis || !guardedSource || !pSnapshot || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data())) return false;
        const bool bCopied = copyDeviceMemory(guardedSource.data(), 0, pSnapshot.data(), 0, nSourceSize, pPdStruct);
        if (!isProgressAlive() || !bCopied || !guardedThis || !guardedSource ||
            (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data())) return false;
        XInstallSimple worker(pSnapshot.data(), bIsImage, nModuleAddress);
        worker.m_bTrustedSnapshot = true;
        UNPACK_STATE materializedState = {};
        const bool bMaterialized = worker.initUnpack(&materializedState, mapProperties, pPdStruct);
        if (!isProgressAlive() || !guardedThis || !guardedSource || !bMaterialized || (getDeviceGeneration() != nGeneration) ||
            (getDevice() != guardedSource.data())) return false;
        UNPACK_CONTEXT *pMaterializedContext = static_cast<UNPACK_CONTEXT *>(materializedState.pContext);
        if (!pMaterializedContext) return false;
        QScopedPointer<UNPACK_CONTEXT> pContext(new (std::nothrow) UNPACK_CONTEXT);
        if (!pContext) return false;
        pContext->listEntries = pMaterializedContext->listEntries;
        if (!worker.finishUnpack(&materializedState, nullptr) || !isProgressAlive() || !guardedThis || !guardedSource ||
            (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
            !isPdStructNotCanceled(pPdStruct) || pContext->listEntries.isEmpty()) return false;
        pContext->pSourceDevice = guardedSource;
        pContext->pOwnerState = pState;
        pContext->baToken = QUuid::createUuid().toRfc4122();
        pContext->nDeviceGeneration = nGeneration;
        pContext->nSourceSize = nSourceSize;
        if (pContext->baToken.isEmpty()) return false;
        const bool bSourceFinal = pSourceGuard->validateAndFinalize(pPdStruct);
        if (!isProgressAlive() || !bSourceFinal || !guardedThis || !guardedSource ||
            (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
            !isPdStructNotCanceled(pPdStruct)) return false;
        pContext->pSourceGuard = pSourceGuard.take();
        pState->nTotalSize = nSourceSize;
        pState->nNumberOfRecords = pContext->listEntries.size();
        pState->mapUnpackProperties = mapProperties;
        pState->pContext = pContext.data();
        pState->baUnpackSourceToken = pContext->baToken;
        pLifetimeState->setContexts.insert(pContext.take());
        return guardedThis && pLifetimeState->bOwnerAlive;
    }
    pState->nTotalSize = nSourceSize;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO *pInfo = static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pInfo || !pInfo->bIsValid || pInfo->sVersion.isEmpty()) return false;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    const bool bPeValid = pe.isValid(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || !bPeValid) return false;
    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource) return false;
    qint64 nDataEnd = isInstallerDataEnd(&pe, getSize());
    if (!isProgressAlive() || !guardedThis || !guardedSource) return false;
    qint64 nOverlaySize = nDataEnd - nOverlayOffset;
    if ((nOverlayOffset <= 0) || (nOverlayOffset > IS_MAX_PACKED_STUB_SIZE) || (nOverlaySize < 12) ||
        (nOverlaySize > IS_MAX_ENCODED_ARCHIVE_SIZE)) {
        return false;
    }

    // Reconstruct only the fixed MASM32 host image. Passing the entire
    // installer to XUPX would duplicate an attacker-controlled overlay in the
    // unpacked QByteArray before the archive-size checks below could run.
    SubDevice stubInput(getDevice(), 0, nOverlayOffset);
    if (!stubInput.open(QIODevice::ReadOnly)) return false;
    QByteArray baStub;
    ISBoundedBuffer stubOutput(&baStub, IS_MAX_UNPACKED_STUB_SIZE);
    if (!stubOutput.open(QIODevice::ReadWrite)) {
        stubInput.close();
        return false;
    }
    XUPX upx(&stubInput);
    const XUPX::INTERNAL_INFO *pUpxInfo = static_cast<const XUPX::INTERNAL_INFO *>(upx.getInternalInfo(pPdStruct));
    if (!isProgressAlive() || !guardedThis || !guardedSource || !pUpxInfo || !pUpxInfo->bIsValid ||
        (pUpxInfo->u_len > (quint32)IS_MAX_UNPACKED_STUB_SIZE) ||
        (pUpxInfo->u_file_size > (quint32)IS_MAX_UNPACKED_STUB_SIZE)) {
        stubOutput.close();
        stubInput.close();
        return false;
    }
    bool bStubUnpacked = upx.unpack(&stubOutput, pPdStruct);
    stubOutput.close();
    stubInput.close();
    if (!isProgressAlive() || !guardedThis || !guardedSource || !bStubUnpacked ||
        (baStub.size() <= 0) || (baStub.size() > IS_MAX_UNPACKED_STUB_SIZE)) return false;

    QByteArray baOverlay = read_array_process(nOverlayOffset, nOverlaySize, pPdStruct);
    if (!isProgressAlive() || !guardedThis || !guardedSource || (baOverlay.size() != nOverlaySize) ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    QList<QByteArray> listPayloads;
    QStringList listNames;
    bool bManifestFound = false;
    qint64 nPosition = 0;
    quint64 nStepsRemaining = IS_MAX_EMULATOR_STEPS;
    quint64 nTotalDecodedSize = 0;

    for (int nRecord = 0; nRecord < IS_MAX_RECORD_COUNT; nRecord++) {
        if (!isProgressAlive() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        if (nPosition + 12 > baOverlay.size()) break;

        const quint8 *pRecord = (const quint8 *)baOverlay.constData() + nPosition;
        quint32 nLength = isRd32(pRecord);
        if (isRd32(pRecord + 4) != 0xFFFFFFFF) break;
        if (nLength < 12) return false;

        qint64 nBodySize = (qint64)nLength - 6;
        if ((nBodySize <= 0) || (nBodySize > IS_MAX_ENCODED_RECORD_SIZE - 6) ||
            (nBodySize > baOverlay.size() - nPosition)) {
            return false;
        }

        // The loader allocates a zeroed buffer and reads the on-disk record at
        // +6. The length dword is therefore part of the coded stream.
        QByteArray baStream(6, '\0');
        baStream.append(baOverlay.constData() + nPosition, (int)nBodySize);

        QByteArray baDecoded;
        bool bUsedExhaustionFallback = false;
        const bool bDecoded = isDecodeStream(baStub, baStream, &baDecoded, &bUsedExhaustionFallback,
                                             &nStepsRemaining, pPdStruct);
        if (!isProgressAlive() || !guardedThis || !guardedSource || !bDecoded) return false;
        quint64 nDecodedSize = (quint64)baDecoded.size();
        if (nDecodedSize > IS_MAX_TOTAL_DECODED_SIZE - nTotalDecodedSize) return false;
        nTotalDecodedSize += nDecodedSize;

        QStringList listManifestNames;
        if (isParseManifest(baDecoded, listPayloads.size(), &listManifestNames)) {
            listNames = listManifestNames;
            bManifestFound = true;
            break;  // generated uninstaller/runtime records follow on v3.5
        }
        if (bUsedExhaustionFallback) return false;

        if (listPayloads.size() >= IS_MAX_PAYLOAD_COUNT) return false;
        listPayloads.append(baDecoded);
        nPosition += nBodySize;
    }

    if (!bManifestFound || listPayloads.isEmpty() || (listPayloads.size() != listNames.size())) return false;

    UNPACK_CONTEXT *pContext = new (std::nothrow) UNPACK_CONTEXT;
    if (!pContext) return false;
    for (int i = 0; i < listPayloads.size(); i++) {
        FILE_ENTRY entry;
        entry.sName = listNames.at(i);
        entry.baData = listPayloads.at(i);
        pContext->listEntries.append(entry);
    }

    pContext->pSourceDevice = guardedSource;
    pContext->pOwnerState = pState;
    pContext->baToken = QUuid::createUuid().toRfc4122();
    pContext->nDeviceGeneration = nGeneration;
    pContext->nSourceSize = nSourceSize;
    if (pContext->baToken.isEmpty()) {
        delete pContext;
        return false;
    }
    const bool bSourceFinal = pSourceGuard->validateAndFinalize(pPdStruct);
    if (!isProgressAlive() || !bSourceFinal || !guardedThis || !guardedSource ||
        (getDeviceGeneration() != nGeneration) || (getDevice() != guardedSource.data()) ||
        !isPdStructNotCanceled(pPdStruct)) {
        delete pContext;
        return false;
    }
    pContext->pSourceGuard = pSourceGuard.take();
    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    pState->baUnpackSourceToken = pContext->baToken;
    pLifetimeState->setContexts.insert(pContext);
    return guardedThis && pLifetimeState->bOwnerAlive;
}

XBinary::ARCHIVERECORD XInstallSimple::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return result;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XInstallSimple> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !isPdStructNotCanceled(pPdStruct)) return result;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    qint32 nIndex = pState->nCurrentIndex;
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) || (pContext->nDeviceGeneration != getDeviceGeneration()) ||
        (pContext->pSourceDevice.data() != getDevice()) || (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (nIndex != pContext->nCurrentIndex) || (pState->nNumberOfRecords != pContext->listEntries.size()) ||
        (pState->nTotalSize != pContext->nSourceSize) || (nIndex < 0) || (nIndex >= pContext->listEntries.size())) return result;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) || (pState->nCurrentIndex != pContext->nCurrentIndex)) return result;

    const FILE_ENTRY &entry = pContext->listEntries.at(nIndex);
    result.nStreamSize = entry.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = entry.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)entry.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;
    return guardedThis ? result : ARCHIVERECORD();
}

bool XInstallSimple::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XInstallSimple> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !guardedOutput || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    const qint32 nIndex = pState->nCurrentIndex;
    const auto isAuthenticated = [&]() -> bool {
        return guardedThis && pLifetimeState->bOwnerAlive && pLifetimeState->setContexts.contains(pContext) &&
               (pState->pContext == pContext) && (pContext->pOwnerState == pState) && (pState->baUnpackSourceToken == pContext->baToken) &&
               (pContext->nDeviceGeneration == guardedThis->getDeviceGeneration()) && (pContext->pSourceDevice.data() == guardedThis->getDevice()) &&
               (pState->nCurrentIndex == pContext->nCurrentIndex) && (pState->nCurrentOffset == pContext->nCurrentOffset) &&
               (pState->nNumberOfRecords == pContext->listEntries.size()) && (pState->nTotalSize == pContext->nSourceSize) &&
               (nIndex >= 0) && (nIndex < pContext->listEntries.size());
    };
    if (!isAuthenticated()) return false;
    const bool bOpen = guardedOutput->isOpen();
    if (!isAuthenticated() || !guardedOutput || !bOpen) return false;
    const bool bWritable = guardedOutput->isWritable();
    if (!isAuthenticated() || !guardedOutput || !bWritable) return false;
    const bool bSequential = guardedOutput->isSequential();
    if (!isAuthenticated() || !guardedOutput || bSequential) return false;
    const QIODevice::OpenMode openMode = guardedOutput->openMode();
    if (!isAuthenticated() || !guardedOutput || (openMode & (QIODevice::Append | QIODevice::Text)) || !isResizeEnable(guardedOutput.data()) ||
        !guardedOutput || devicesAlias(pContext->pSourceDevice.data(), guardedOutput.data()) || !isAuthenticated() || !guardedOutput) return false;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedOutput || !isAuthenticated()) return false;
    const QByteArray baData = pContext->listEntries.at(nIndex).baData;
    QScopedPointer<QIODevice> pStage(createFileBuffer(baData.size(), pPdStruct));
    QPointer<QIODevice> guardedStage(pStage.data());
    if (!isAuthenticated() || !guardedOutput || !guardedStage) return false;
    UNPACK_STATE writeState = *pState;
    writeState.pContext = nullptr;
    writeState.baUnpackSourceToken.clear();
    if (!writeUnpackData(&writeState, guardedStage.data(), baData, pPdStruct) || !guardedStage || !guardedOutput || !isAuthenticated()) return false;
    writeState.nCurrentOffset = 0;
    const bool bPublished = writeUnpackData(&writeState, guardedOutput.data(), baData, pPdStruct);
    const bool bSourceCurrent = bPublished && pContext->pSourceGuard && pContext->pSourceGuard->isCurrent(pPdStruct);
    const bool bFinal = bSourceCurrent && guardedOutput && isAuthenticated() && isPdStructNotCanceled(pPdStruct);
    if (!bFinal) {
        if (bPublished && guardedOutput) {
            resize(guardedOutput.data(), 0);
            if (guardedOutput) guardedOutput->seek(0);
        }
        return false;
    }
    pContext->nCurrentOffset = writeState.nCurrentOffset;
    pState->nCurrentOffset = writeState.nCurrentOffset;
    return true;
}

bool XInstallSimple::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    const QSharedPointer<LIFETIME_STATE> pLifetimeState = m_pUnpackLifetimeState;
    if (!pLifetimeState || !pLifetimeState->bOwnerAlive || pLifetimeState->bOperationInProgress) return false;
    QScopedValueRollback<bool> operationGuard(pLifetimeState->bOperationInProgress, true);
    QPointer<XInstallSimple> guardedThis(this);
    if (!pState || !pState->pContext || pState->baUnpackSourceToken.isEmpty() || !isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) || (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nDeviceGeneration != getDeviceGeneration()) || (pContext->pSourceDevice.data() != getDevice()) ||
        (pState->nCurrentIndex != pContext->nCurrentIndex) || (pState->nCurrentOffset != pContext->nCurrentOffset) ||
        (pState->nNumberOfRecords != pContext->listEntries.size()) || (pState->nTotalSize != pContext->nSourceSize) ||
        (pContext->nCurrentIndex < 0) || (pContext->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    if (!pContext->pSourceGuard || !pContext->pSourceGuard->isCurrent(pPdStruct) || !guardedThis ||
        !pLifetimeState->bOwnerAlive || !pLifetimeState->setContexts.contains(pContext) ||
        (pState->pContext != pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken) ||
        (pContext->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    ++pContext->nCurrentIndex;
    pContext->nCurrentOffset = 0;
    pState->nCurrentIndex = pContext->nCurrentIndex;
    pState->nCurrentOffset = 0;
    return true;
}

bool XInstallSimple::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
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
    if (!pContext || !pLifetimeState->setContexts.contains(pContext) || (pContext->pOwnerState != pState) ||
        (pContext->baToken != pState->baUnpackSourceToken)) return false;
    pLifetimeState->setContexts.remove(pContext);
    *pState = UNPACK_STATE();
    delete pContext;
    return true;
}

#endif  // USE_XEMULATOR
