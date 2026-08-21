/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xburn.h"

#include <QBuffer>
#include <QCryptographicHash>
#include <QDir>
#include <QTemporaryFile>
#include <QXmlStreamReader>
#include <limits>

#include "subdevice.h"
#include "xpe.h"
#include "../XArchive/xarchive.h"
#include "../XArchive/xcab.h"

namespace {
const qint32 BURN_SECTION_SIZE = 56;
const quint32 BURN_SECTION_MAGIC = 0x00F14300U;
const quint32 BURN_SECTION_VERSION_V3 = 2U;
const quint32 BURN_CONTAINER_FORMAT_CAB = 1U;
const qint64 BURN_MAX_MANIFEST_SIZE = 16ll << 20;
const qint32 BURN_MAX_RECORDS = 100000;
const QString BURN_NAMESPACE = QStringLiteral("http://schemas.microsoft.com/wix/2008/Burn");

class BurnOperationGuard {
public:
    explicit BurnOperationGuard(const QSharedPointer<XBurn::UNPACK_LIFETIME_STATE> &pState)
        : m_pState(pState), m_bAcquired(false)
    {
        if (m_pState && m_pState->bOwnerAlive && !m_pState->bOperationInProgress) {
            m_pState->bOperationInProgress = true;
            m_bAcquired = true;
        }
    }

    ~BurnOperationGuard()
    {
        if (m_pState && m_bAcquired) m_pState->bOperationInProgress = false;
    }

    bool isAcquired() const { return m_bAcquired; }

private:
    QSharedPointer<XBurn::UNPACK_LIFETIME_STATE> m_pState;
    bool m_bAcquired;
};

class BurnPublisher : public XArchive {
public:
    explicit BurnPublisher(QIODevice *pDevice) : XArchive(pDevice) {}
    using XArchive::publishUnpackOutput;
};

struct BURN_CAB_ENTRY {
    qint32 nIndex;
    QString sName;
    qint64 nSize;
};

struct BURN_MANIFEST_CONTAINER {
    QString sId;
    bool bAttached;
    qint32 nAttachedIndex;
    qint64 nFileSize;
    QByteArray baSHA1;
};

struct BURN_PENDING_PAYLOAD {
    XBurn::PAYLOAD_RECORD payload;
    bool bUX;
    bool bEmbedded;
    QString sContainerId;
};

struct BURN_PACKAGE_INFO {
    QString sId;
    QString sType;
};

struct BURN_MANIFEST_INFO {
    QList<XBurn::PAYLOAD_RECORD> listUXPayloads;
    QList<XBurn::PAYLOAD_RECORD> listAttachedPayloads;
    bool bHasAttachedContainer;
    qint64 nAttachedContainerSize;
    QByteArray baAttachedContainerSHA1;
};

static quint32 burnReadLE32(const QByteArray &baData, qint32 nOffset)
{
    return (quint32)(quint8)baData.at(nOffset) |
           ((quint32)(quint8)baData.at(nOffset + 1) << 8) |
           ((quint32)(quint8)baData.at(nOffset + 2) << 16) |
           ((quint32)(quint8)baData.at(nOffset + 3) << 24);
}

static bool burnRangeIsValid(qint64 nOffset, qint64 nSize, qint64 nTotalSize)
{
    return (nOffset >= 0) && (nSize >= 0) && (nTotalSize >= 0) &&
           (nOffset <= nTotalSize) && (nSize <= (nTotalSize - nOffset));
}

static bool burnIsAllZero(const QByteArray &baData)
{
    for (char ch : baData) {
        if (ch != 0) return false;
    }
    return true;
}

static bool burnParseUnsignedDecimal(const QString &sValue, qint64 *pValue)
{
    if (!pValue || sValue.isEmpty() || (sValue.size() > 20)) return false;

    quint64 nValue = 0;
    const quint64 nMax = (quint64)(std::numeric_limits<qint64>::max)();
    for (QChar ch : sValue) {
        const ushort nUnicode = ch.unicode();
        if ((nUnicode < '0') || (nUnicode > '9')) return false;
        const quint64 nDigit = nUnicode - '0';
        if ((nValue > (nMax / 10)) || ((nValue == (nMax / 10)) && (nDigit > (nMax % 10)))) return false;
        nValue = nValue * 10 + nDigit;
    }

    *pValue = (qint64)nValue;
    return true;
}

static bool burnParseSHA1(const QString &sValue, QByteArray *pValue)
{
    if (!pValue || (sValue.size() != 40)) return false;
    QByteArray baHex = sValue.toLatin1();
    if (baHex.size() != 40) return false;

    for (char ch : baHex) {
        const bool bDigit = (ch >= '0') && (ch <= '9');
        const bool bLower = (ch >= 'a') && (ch <= 'f');
        const bool bUpper = (ch >= 'A') && (ch <= 'F');
        if (!bDigit && !bLower && !bUpper) return false;
    }

    QByteArray baResult = QByteArray::fromHex(baHex);
    if (baResult.size() != 20) return false;
    *pValue = baResult;
    return true;
}

static bool burnIsSafeRelativePath(const QString &sValue, QString *pNormalized)
{
    if (!pNormalized || sValue.isEmpty() || (sValue.size() > 32767) || sValue.contains(QChar(0))) return false;

    QString sPath = QDir::fromNativeSeparators(sValue);
    if (QDir::isAbsolutePath(sPath) || sPath.startsWith('/') || sPath.startsWith(QStringLiteral("//")) ||
        ((sPath.size() >= 2) && sPath.at(0).isLetter() && (sPath.at(1) == ':')) || sPath.contains(':')) {
        return false;
    }

    const QStringList listParts = sPath.split('/', Qt::KeepEmptyParts);
    if (listParts.isEmpty()) return false;
    for (const QString &sPart : listParts) {
        if (sPart.isEmpty() || (sPart == QStringLiteral(".")) || (sPart == QStringLiteral(".."))) return false;
        for (QChar ch : sPart) {
            if (ch.unicode() < 0x20) return false;
        }
    }

    const QString sClean = QDir::cleanPath(sPath);
    if (sClean.isEmpty() || (sClean == QStringLiteral(".")) || sClean.startsWith(QStringLiteral("../"))) return false;
    *pNormalized = sClean;
    return true;
}

static bool burnEmbeddedNameIndex(const QString &sName, QChar prefix, qint32 *pIndex)
{
    if (!pIndex || (sName.size() < 2) || (sName.at(0) != prefix)) return false;
    qint64 nIndex = 0;
    if (!burnParseUnsignedDecimal(sName.mid(1), &nIndex) ||
        (nIndex > (std::numeric_limits<qint32>::max)()) ||
        (QString::number(nIndex) != sName.mid(1))) {
        return false;
    }
    *pIndex = (qint32)nIndex;
    return true;
}

static bool burnHashDevice(QIODevice *pDevice, QByteArray *pHash, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pHash || !pDevice->isOpen() || !pDevice->isReadable() || pDevice->isSequential() ||
        !pDevice->seek(0)) {
        return false;
    }

    const qint64 nSize = pDevice->size();
    if (nSize < 0) return false;

    QCryptographicHash hash(QCryptographicHash::Sha1);
    QByteArray baBuffer;
    baBuffer.resize(0x10000);
    if (baBuffer.size() != 0x10000) return false;

    qint64 nReadTotal = 0;
    while (nReadTotal < nSize) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        const qint64 nRequest = qMin<qint64>(baBuffer.size(), nSize - nReadTotal);
        const qint64 nRead = pDevice->read(baBuffer.data(), nRequest);
        if ((nRead <= 0) || (nRead > nRequest)) return false;
        hash.addData(baBuffer.constData(), (int)nRead);
        nReadTotal += nRead;
    }

    if ((pDevice->pos() != nSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    *pHash = hash.result();
    return pHash->size() == 20;
}

static bool burnHashRange(QIODevice *pDevice, qint64 nOffset, qint64 nSize,
                          QByteArray *pHash, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pHash || !burnRangeIsValid(nOffset, nSize, pDevice->size())) return false;
    SubDevice subDevice(pDevice, nOffset, nSize);
    if (!subDevice.open(QIODevice::ReadOnly)) return false;
    const bool bResult = burnHashDevice(&subDevice, pHash, pPdStruct);
    subDevice.close();
    return bResult;
}

static bool burnScanCabinet(QIODevice *pDevice, qint64 nOffset, qint64 nSize, bool bUX,
                            QList<BURN_CAB_ENTRY> *pEntries, QByteArray *pManifest,
                            XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pEntries || (bUX && !pManifest) ||
        !burnRangeIsValid(nOffset, nSize, pDevice->size()) ||
        (nSize < (qint64)sizeof(XCab::CFHEADER))) {
        return false;
    }

    pEntries->clear();
    if (pManifest) pManifest->clear();

    SubDevice subDevice(pDevice, nOffset, nSize);
    if (!subDevice.open(QIODevice::ReadOnly)) return false;

    XCab cabinet(&subDevice);
    XBinary::UNPACK_STATE state = {};
    bool bInitialized = cabinet.initUnpack(&state, cabinet.getDefaultUnpackProperties(), pPdStruct);
    bool bResult = bInitialized;

    if (bResult) {
        const qint64 nCabinetSize = cabinet.getFileFormatSize(pPdStruct);
        bResult = (nCabinetSize == nSize) && (state.nNumberOfRecords >= (bUX ? 1 : 0)) &&
                  (state.nNumberOfRecords <= BURN_MAX_RECORDS);
    }

    QSet<QString> setNames;
    for (qint32 i = 0; bResult && (i < state.nNumberOfRecords); i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            bResult = false;
            break;
        }

        const XBinary::ARCHIVERECORD record = cabinet.infoCurrent(&state, pPdStruct);
        const QString sName = record.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
        bool bSizeOK = false;
        const qint64 nFileSize = record.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(&bSizeOK);
        const QString sNameKey = sName.toCaseFolded();
        if (sName.isEmpty() || sName.contains(QChar(0)) || !bSizeOK || (nFileSize < 0) ||
            setNames.contains(sNameKey) || (bUX && (i == 0) && (sName != QStringLiteral("0")))) {
            bResult = false;
            break;
        }
        setNames.insert(sNameKey);

        BURN_CAB_ENTRY entry = {};
        entry.nIndex = i;
        entry.sName = sName;
        entry.nSize = nFileSize;
        pEntries->append(entry);

        if (bUX && (i == 0)) {
            if ((nFileSize <= 0) || (nFileSize > BURN_MAX_MANIFEST_SIZE)) {
                bResult = false;
                break;
            }
            QBuffer manifestBuffer(pManifest);
            if (!manifestBuffer.open(QIODevice::ReadWrite) ||
                !cabinet.unpackCurrent(&state, &manifestBuffer, pPdStruct) ||
                (pManifest->size() != nFileSize)) {
                bResult = false;
                break;
            }
        }

        if (((i + 1) < state.nNumberOfRecords) && !cabinet.moveToNext(&state, pPdStruct)) {
            bResult = false;
            break;
        }
    }

    if (bInitialized && !cabinet.finishUnpack(&state, pPdStruct)) {
        bResult = false;
    }
    subDevice.close();
    return bResult && XBinary::isPdStructNotCanceled(pPdStruct);
}

static bool burnIsPackageElement(const QString &sName)
{
    return (sName == QStringLiteral("MsiPackage")) || (sName == QStringLiteral("ExePackage")) ||
           (sName == QStringLiteral("MsuPackage")) || (sName == QStringLiteral("MspPackage"));
}

static bool burnReadPayloadAttributes(const QXmlStreamAttributes &attributes, bool bUX,
                                      BURN_PENDING_PAYLOAD *pPayload)
{
    if (!pPayload) return false;

    const QString sId = attributes.value(QStringLiteral("Id")).toString();
    const QString sFilePath = attributes.value(QStringLiteral("FilePath")).toString();
    const QString sFileSize = attributes.value(QStringLiteral("FileSize")).toString();
    const QString sHash = attributes.value(QStringLiteral("Hash")).toString();
    const QString sPackaging = attributes.value(QStringLiteral("Packaging")).toString();
    const QString sSourcePath = attributes.value(QStringLiteral("SourcePath")).toString();
    const QString sContainer = attributes.value(QStringLiteral("Container")).toString();

    qint64 nFileSize = 0;
    QByteArray baSHA1;
    QString sNormalizedPath;
    if (sId.isEmpty() || (sId.size() > 32767) || sId.contains(QChar(0)) ||
        !burnIsSafeRelativePath(sFilePath, &sNormalizedPath) ||
        !burnParseUnsignedDecimal(sFileSize, &nFileSize) || !burnParseSHA1(sHash, &baSHA1) ||
        sSourcePath.isEmpty() || (sSourcePath.size() > 32767) || sSourcePath.contains(QChar(0))) {
        return false;
    }

    const bool bEmbedded = (sPackaging.compare(QStringLiteral("embedded"), Qt::CaseInsensitive) == 0);
    const bool bExternal = (sPackaging.compare(QStringLiteral("external"), Qt::CaseInsensitive) == 0);
    if ((!bEmbedded && !bExternal) || (bUX && (!bEmbedded || !sContainer.isEmpty()))) return false;

    pPayload->payload = XBurn::PAYLOAD_RECORD();
    pPayload->payload.containerType = bUX ? XBurn::CONTAINER_TYPE_UX : XBurn::CONTAINER_TYPE_UNKNOWN;
    pPayload->payload.nInnerIndex = -1;
    pPayload->payload.sSourcePath = sSourcePath;
    pPayload->payload.sFilePath = sNormalizedPath;
    pPayload->payload.sPayloadId = sId;
    pPayload->payload.nFileSize = nFileSize;
    pPayload->payload.baSHA1 = baSHA1;
    pPayload->bUX = bUX;
    pPayload->bEmbedded = bEmbedded;
    pPayload->sContainerId = sContainer;

    // External records are represented by UNKNOWN and intentionally never
    // enter the physical record list.
    if (!bEmbedded) pPayload->payload.containerType = XBurn::CONTAINER_TYPE_UNKNOWN;
    return true;
}

static bool burnParseManifest(const QByteArray &baManifest, BURN_MANIFEST_INFO *pInfo,
                              XBinary::PDSTRUCT *pPdStruct)
{
    if (!pInfo || baManifest.isEmpty() || (baManifest.size() > BURN_MAX_MANIFEST_SIZE)) return false;
    *pInfo = BURN_MANIFEST_INFO();

    QXmlStreamReader xml(baManifest);
    QList<QString> listElements;
    QList<BURN_PENDING_PAYLOAD> listPayloads;
    QMap<QString, BURN_MANIFEST_CONTAINER> mapContainers;
    QMap<QString, BURN_PACKAGE_INFO> mapPayloadPackages;
    QSet<QString> setPayloadIds;
    QSet<QString> setPayloadRefs;
    QSet<QString> setPackageIds;
    BURN_PACKAGE_INFO currentPackage;
    QString sCurrentPackageElement;
    bool bRootSeen = false;
    bool bUXSeen = false;
    bool bChainSeen = false;
    qint32 nElements = 0;

    while (!xml.atEnd()) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        xml.readNext();

        if (xml.isDTD() || xml.isEntityReference()) return false;
        if (xml.isStartElement()) {
            if (++nElements > BURN_MAX_RECORDS * 8) return false;
            const QString sName = xml.name().toString();
            const QString sNamespace = xml.namespaceUri().toString();
            if ((sNamespace != BURN_NAMESPACE) || (listElements.size() >= 64)) return false;

            if (listElements.isEmpty()) {
                if (bRootSeen || (sName != QStringLiteral("BurnManifest"))) return false;
                bRootSeen = true;
            } else if ((listElements.size() == 1) && (listElements.at(0) == QStringLiteral("BurnManifest"))) {
                if (sName == QStringLiteral("UX")) {
                    if (bUXSeen) return false;
                    bUXSeen = true;
                } else if (sName == QStringLiteral("Chain")) {
                    if (bChainSeen) return false;
                    bChainSeen = true;
                } else if (sName == QStringLiteral("Container")) {
                    BURN_MANIFEST_CONTAINER container = {};
                    container.sId = xml.attributes().value(QStringLiteral("Id")).toString();
                    const QString sFileSize = xml.attributes().value(QStringLiteral("FileSize")).toString();
                    const QString sHash = xml.attributes().value(QStringLiteral("Hash")).toString();
                    const QString sAttached = xml.attributes().value(QStringLiteral("Attached")).toString();
                    const QString sAttachedIndex = xml.attributes().value(QStringLiteral("AttachedIndex")).toString();
                    container.bAttached = (sAttached.compare(QStringLiteral("yes"), Qt::CaseInsensitive) == 0);
                    container.nAttachedIndex = -1;
                    if (container.sId.isEmpty() || (container.sId.size() > 32767) || container.sId.contains(QChar(0)) ||
                        mapContainers.contains(container.sId) || !burnParseUnsignedDecimal(sFileSize, &container.nFileSize) ||
                        !burnParseSHA1(sHash, &container.baSHA1) ||
                        (!sAttached.isEmpty() && !container.bAttached)) {
                        return false;
                    }
                    if (container.bAttached) {
                        qint64 nIndex = -1;
                        if (!burnParseUnsignedDecimal(sAttachedIndex, &nIndex) ||
                            (nIndex > (std::numeric_limits<qint32>::max)())) return false;
                        container.nAttachedIndex = (qint32)nIndex;
                    } else if (!sAttachedIndex.isEmpty()) {
                        return false;
                    }
                    mapContainers.insert(container.sId, container);
                }
            }

            const bool bUXPayload = (sName == QStringLiteral("Payload")) && (listElements.size() == 2) &&
                                    (listElements.at(0) == QStringLiteral("BurnManifest")) &&
                                    (listElements.at(1) == QStringLiteral("UX"));
            const bool bGlobalPayload = (sName == QStringLiteral("Payload")) && (listElements.size() == 1) &&
                                        (listElements.at(0) == QStringLiteral("BurnManifest"));
            if (bUXPayload || bGlobalPayload) {
                BURN_PENDING_PAYLOAD payload = {};
                if (!burnReadPayloadAttributes(xml.attributes(), bUXPayload, &payload) ||
                    setPayloadIds.contains(payload.payload.sPayloadId)) {
                    return false;
                }
                setPayloadIds.insert(payload.payload.sPayloadId);
                listPayloads.append(payload);
            }

            if ((listElements.size() == 2) && (listElements.at(0) == QStringLiteral("BurnManifest")) &&
                (listElements.at(1) == QStringLiteral("Chain")) && burnIsPackageElement(sName)) {
                currentPackage.sId = xml.attributes().value(QStringLiteral("Id")).toString();
                currentPackage.sType = sName.left(sName.size() - QStringLiteral("Package").size());
                sCurrentPackageElement = sName;
                if (currentPackage.sId.isEmpty() || (currentPackage.sId.size() > 32767) ||
                    currentPackage.sId.contains(QChar(0)) || setPackageIds.contains(currentPackage.sId)) {
                    return false;
                }
                setPackageIds.insert(currentPackage.sId);
            } else if ((sName == QStringLiteral("PayloadRef")) && (listElements.size() == 3) &&
                       (listElements.at(0) == QStringLiteral("BurnManifest")) &&
                       (listElements.at(1) == QStringLiteral("Chain")) &&
                       (listElements.at(2) == sCurrentPackageElement) && !currentPackage.sId.isEmpty()) {
                const QString sPayloadId = xml.attributes().value(QStringLiteral("Id")).toString();
                if (sPayloadId.isEmpty() || (sPayloadId.size() > 32767) || sPayloadId.contains(QChar(0))) return false;
                setPayloadRefs.insert(sPayloadId);
                if (!mapPayloadPackages.contains(sPayloadId)) mapPayloadPackages.insert(sPayloadId, currentPackage);
            }

            listElements.append(sName);
        } else if (xml.isEndElement()) {
            const QString sName = xml.name().toString();
            if (listElements.isEmpty() || (listElements.constLast() != sName) ||
                (xml.namespaceUri().toString() != BURN_NAMESPACE)) {
                return false;
            }
            if ((listElements.size() == 3) && (sName == sCurrentPackageElement)) {
                currentPackage = BURN_PACKAGE_INFO();
                sCurrentPackageElement.clear();
            }
            listElements.removeLast();
        }
    }

    if (xml.hasError() || !listElements.isEmpty() || !bRootSeen || !bUXSeen || !bChainSeen) return false;
    for (const QString &sRef : setPayloadRefs) {
        if (!setPayloadIds.contains(sRef)) return false;
    }

    qint32 nAttachedContainers = 0;
    for (auto it = mapContainers.constBegin(); it != mapContainers.constEnd(); ++it) {
        // Detached containers are declared by the manifest but are not bytes in
        // this bundle.  Accepting them would make a successful open silently
        // omit part of the bundle, so the embedded-only reader fails closed.
        if (!it.value().bAttached) return false;
        // AttachedIndex is the Burn container index; UX occupies index zero.
        if ((it.value().nAttachedIndex != 1) || (++nAttachedContainers != 1)) return false;
        pInfo->bHasAttachedContainer = true;
        pInfo->nAttachedContainerSize = it.value().nFileSize;
        pInfo->baAttachedContainerSHA1 = it.value().baSHA1;
    }

    for (BURN_PENDING_PAYLOAD pending : listPayloads) {
        XBurn::PAYLOAD_RECORD &payload = pending.payload;
        const BURN_PACKAGE_INFO package = mapPayloadPackages.value(payload.sPayloadId);
        payload.sPackageId = package.sId;
        payload.sPackageType = package.sType;

        if (pending.bUX) {
            qint32 nEmbeddedIndex = -1;
            if ((payload.containerType != XBurn::CONTAINER_TYPE_UX) ||
                !burnEmbeddedNameIndex(payload.sSourcePath, QChar('u'), &nEmbeddedIndex)) return false;
            Q_UNUSED(nEmbeddedIndex)
            pInfo->listUXPayloads.append(payload);
        } else if (payload.containerType == XBurn::CONTAINER_TYPE_UNKNOWN) {
            if (!pending.bEmbedded) {
                if (!pending.sContainerId.isEmpty()) return false;
                return false;  // external payload: not physically extractable
            }
            if (pending.sContainerId.isEmpty()) return false;
            if (!mapContainers.contains(pending.sContainerId)) return false;
            const BURN_MANIFEST_CONTAINER container = mapContainers.value(pending.sContainerId);
            if (!container.bAttached) return false;

            qint32 nEmbeddedIndex = -1;
            if (!burnEmbeddedNameIndex(payload.sSourcePath, QChar('a'), &nEmbeddedIndex)) return false;
            Q_UNUSED(nEmbeddedIndex)
            payload.containerType = XBurn::CONTAINER_TYPE_ATTACHED;
            pInfo->listAttachedPayloads.append(payload);
        }
    }

    return XBinary::isPdStructNotCanceled(pPdStruct);
}

static bool burnMapCabinetPayloads(const QList<BURN_CAB_ENTRY> &listEntries,
                                   const QList<XBurn::PAYLOAD_RECORD> &listManifestPayloads,
                                   XBurn::CONTAINER_TYPE containerType,
                                   QList<XBurn::PAYLOAD_RECORD> *pOutput)
{
    if (!pOutput) return false;
    const qint32 nFirstPhysical = (containerType == XBurn::CONTAINER_TYPE_UX) ? 1 : 0;
    if ((listEntries.size() - nFirstPhysical) != listManifestPayloads.size()) return false;

    QMap<QString, XBurn::PAYLOAD_RECORD> mapPayloads;
    for (const XBurn::PAYLOAD_RECORD &payload : listManifestPayloads) {
        if (mapPayloads.contains(payload.sSourcePath)) return false;
        mapPayloads.insert(payload.sSourcePath, payload);
    }

    for (qint32 i = nFirstPhysical; i < listEntries.size(); i++) {
        const BURN_CAB_ENTRY &entry = listEntries.at(i);
        if (!mapPayloads.contains(entry.sName)) return false;
        XBurn::PAYLOAD_RECORD payload = mapPayloads.take(entry.sName);
        qint32 nEmbeddedIndex = -1;
        const QChar prefix = (containerType == XBurn::CONTAINER_TYPE_UX) ? QChar('u') : QChar('a');
        const qint32 nExpectedIndex = i - nFirstPhysical;
        if (!burnEmbeddedNameIndex(entry.sName, prefix, &nEmbeddedIndex) ||
            (nEmbeddedIndex != nExpectedIndex) || (payload.nFileSize != entry.nSize)) {
            return false;
        }
        payload.containerType = containerType;
        payload.nInnerIndex = entry.nIndex;
        pOutput->append(payload);
    }

    return mapPayloads.isEmpty();
}

static QString burnAddPublicPathSuffix(const QString &sPath, qint32 nSuffix)
{
    const qint32 nLeafOffset = sPath.lastIndexOf(QChar('/')) + 1;
    qint32 nExtensionOffset = sPath.lastIndexOf(QChar('.'));
    if (nExtensionOffset <= nLeafOffset) nExtensionOffset = sPath.size();
    return sPath.left(nExtensionOffset) + QStringLiteral(".burn-%1").arg(nSuffix) +
           sPath.mid(nExtensionOffset);
}

static bool burnAssignPublicPaths(QList<XBurn::PAYLOAD_RECORD> *pPayloads)
{
    if (!pPayloads) return false;
    QSet<QString> setPublicPaths;
    for (XBurn::PAYLOAD_RECORD &payload : *pPayloads) {
        QString sCandidate = payload.sFilePath;
        qint32 nSuffix = 2;
        while (setPublicPaths.contains(sCandidate.toCaseFolded())) {
            if (nSuffix > (pPayloads->size() + 1)) return false;
            sCandidate = burnAddPublicPathSuffix(payload.sFilePath, nSuffix++);
        }
        if (sCandidate.isEmpty() || (sCandidate.size() > 32767)) return false;
        payload.sPublicPath = sCandidate;
        setPublicPaths.insert(sCandidate.toCaseFolded());
    }
    return true;
}

static XBurn::CONTAINER_CONTEXT *burnGetContainer(XBurn::UNPACK_CONTEXT *pContext,
                                                   XBurn::CONTAINER_TYPE containerType)
{
    if (!pContext) return nullptr;
    if (containerType == XBurn::CONTAINER_TYPE_UX) return &pContext->ux;
    if (containerType == XBurn::CONTAINER_TYPE_ATTACHED) return &pContext->attached;
    return nullptr;
}

static bool burnPositionContainer(XBurn::CONTAINER_CONTEXT *pContainer, qint32 nTargetIndex,
                                  XBinary::PDSTRUCT *pPdStruct)
{
    if (!pContainer || !pContainer->bInitialized || !pContainer->pCab ||
        (nTargetIndex < 0) || (nTargetIndex >= pContainer->state.nNumberOfRecords) ||
        (pContainer->state.nCurrentIndex > nTargetIndex)) {
        return false;
    }
    while (pContainer->state.nCurrentIndex < nTargetIndex) {
        if (!pContainer->pCab->moveToNext(&pContainer->state, pPdStruct)) return false;
    }
    return pContainer->state.nCurrentIndex == nTargetIndex;
}

static bool burnFinishContainer(XBurn::CONTAINER_CONTEXT *pContainer)
{
    if (!pContainer) return true;
    bool bResult = true;
    if (pContainer->pCab) {
        if (pContainer->bInitialized) bResult = pContainer->pCab->finishUnpack(&pContainer->state, nullptr);
        delete pContainer->pCab;
        pContainer->pCab = nullptr;
    }
    if (pContainer->pSubDevice) {
        pContainer->pSubDevice->close();
        delete pContainer->pSubDevice;
        pContainer->pSubDevice = nullptr;
    }
    pContainer->bInitialized = false;
    pContainer->state = XBinary::UNPACK_STATE();
    return bResult;
}

static void burnInitializeContainerContext(XBurn::CONTAINER_CONTEXT *pContainer,
                                           qint64 nOffset, qint64 nSize)
{
    if (!pContainer) return;
    pContainer->pSubDevice = nullptr;
    pContainer->pCab = nullptr;
    pContainer->state = XBinary::UNPACK_STATE();
    pContainer->bInitialized = false;
    pContainer->nOuterOffset = nOffset;
    pContainer->nOuterSize = nSize;
}
}  // namespace

XBurn::UNPACK_LIFETIME_STATE::~UNPACK_LIFETIME_STATE()
{
    const QSet<UNPACK_CONTEXT *> contexts = setContexts;
    setContexts.clear();
    for (UNPACK_CONTEXT *pContext : contexts) XBurn::deleteUnpackContext(pContext);
}

bool XBurn::deleteUnpackContext(UNPACK_CONTEXT *pContext)
{
    if (!pContext) return true;
    bool bResult = burnFinishContainer(&pContext->attached);
    if (!burnFinishContainer(&pContext->ux)) bResult = false;
    if (pContext->pSourceValidator) {
        pContext->pSourceValidator->releaseUnpackSource(&pContext->sourceValidationState);
        delete pContext->pSourceValidator;
    }
    delete pContext;
    return bResult;
}

XBurn::XBurn(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress)
    : XBinary(pDevice, bIsImage, nModuleAddress)
{
    m_internalInfo = INTERNAL_INFO();
    m_pUnpackLifetimeState = QSharedPointer<UNPACK_LIFETIME_STATE>::create();
    setIsArchive(true);
}

XBurn::~XBurn()
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    if (pLifetime) pLifetime->bOwnerAlive = false;
    m_pUnpackLifetimeState.clear();
}

bool XBurn::isValid(PDSTRUCT *pPdStruct)
{
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XBurn> guardedThis(this);
    const INTERNAL_INFO *pInfo = static_cast<const INTERNAL_INFO *>(guardedThis->getInternalInfo(pPdStruct));
    return guardedThis && pInfo && pInfo->bIsValid;
}

bool XBurn::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XBurn burn(pDevice);
    return burn.isValid(pPdStruct);
}

XBurn::INTERNAL_INFO XBurn::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

bool XBurn::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XBurn> guardedThis(this);
    const bool bAlreadyHandled = guardedThis->isInternalInfoHandled();
    if (!guardedThis) return false;

    if (!bAlreadyHandled) {
        const quint64 nTransaction = guardedThis->beginInternalInfoTransaction();
        if (!nTransaction) return false;

        guardedThis->m_internalInfo = INTERNAL_INFO();
        INTERNAL_INFO info = guardedThis->_getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        if (!guardedThis->isInternalInfoTransactionCurrent(nTransaction) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }

        const auto memoryMap = guardedThis->getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
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
                nTransaction, static_cast<XBinary::INTERNAL_INFO *>(&guardedThis->m_internalInfo))) {
            guardedThis->rollbackInternalInfoTransaction(nTransaction);
            return false;
        }
    }

    return true;
}

void *XBurn::getInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XBurn> guardedThis(this);
    const bool bHandled = guardedThis->handleInternalInfo(pPdStruct);
    if (!guardedThis || !bHandled) return nullptr;
    return &guardedThis->m_internalInfo;
}

void XBurn::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XBurn::getFileType()
{
    XPE pe(getDevice(), isImage(), getModuleAddress());
    return pe.is64() ? FT_PE64_WIXBURN : FT_PE32_WIXBURN;
}

XBurn::INTERNAL_INFO XBurn::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nUXOffset = -1;
    result.nAttachedOffset = -1;
    if (isImage() || !getDevice() || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    XPE pe(getDevice(), false, getModuleAddress());
    if (!pe.isValid(pPdStruct)) {
        return result;
    }
    const qint64 nTotalSize = getSize();
    if (nTotalSize < BURN_SECTION_SIZE) return result;

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSectionHeaders = pe.getSectionHeaders(pPdStruct);
    QList<XPE::SECTION_RECORD> listSections = pe.getSectionRecords(&listSectionHeaders, pPdStruct);
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return result;

    XPE::SECTION_RECORD burnSection = {};
    burnSection.nOffset = -1;
    qint32 nBurnSections = 0;
    for (const XPE::SECTION_RECORD &section : listSections) {
        if (section.sName == QStringLiteral(".wixburn")) {
            burnSection = section;
            nBurnSections++;
        }
    }
    if ((nBurnSections != 1) || (burnSection.nSize < BURN_SECTION_SIZE) ||
        !burnRangeIsValid(burnSection.nOffset, burnSection.nSize, nTotalSize)) {
        return result;
    }

    const QByteArray baHeader = read_array_process(burnSection.nOffset, BURN_SECTION_SIZE, pPdStruct);
    if ((baHeader.size() != BURN_SECTION_SIZE) ||
        (burnReadLE32(baHeader, 0) != BURN_SECTION_MAGIC) ||
        (burnReadLE32(baHeader, 4) != BURN_SECTION_VERSION_V3) ||
        (burnReadLE32(baHeader, 40) != BURN_CONTAINER_FORMAT_CAB)) {
        return result;
    }

    const QByteArray baBundleId = baHeader.mid(8, 16);
    const qint64 nStubSize = burnReadLE32(baHeader, 24);
    const qint64 nOriginalSignatureOffset = burnReadLE32(baHeader, 32);
    const qint64 nOriginalSignatureSize = burnReadLE32(baHeader, 36);
    const quint32 nContainerCount = burnReadLE32(baHeader, 44);
    const qint64 nUXSize = burnReadLE32(baHeader, 48);
    const qint64 nAttachedSizeField = burnReadLE32(baHeader, 52);

    if (burnIsAllZero(baBundleId) || (nContainerCount < 1) || (nContainerCount > 2) ||
        (nStubSize <= 0) || (nUXSize < (qint64)sizeof(XCab::CFHEADER)) ||
        !burnRangeIsValid(0, nStubSize, nTotalSize) ||
        !burnRangeIsValid(nStubSize, nUXSize, nTotalSize) ||
        ((burnSection.nOffset + burnSection.nSize) > nStubSize) ||
        ((nOriginalSignatureOffset == 0) != (nOriginalSignatureSize == 0))) {
        return result;
    }

    const qint64 nUXEnd = nStubSize + nUXSize;
    XBinary::OFFSETSIZE signature = pe.getSignOffsetSize();
    if ((signature.nOffset < 0) || (signature.nSize < 0) ||
        ((signature.nSize > 0) && !burnRangeIsValid(signature.nOffset, signature.nSize, nTotalSize))) {
        return result;
    }

    qint64 nEngineEnd = nUXEnd;
    if (nOriginalSignatureOffset > 0) {
        if ((nOriginalSignatureOffset < nUXEnd) ||
            !burnRangeIsValid(nOriginalSignatureOffset, nOriginalSignatureSize, nTotalSize)) return result;
        nEngineEnd = nOriginalSignatureOffset + nOriginalSignatureSize;
    } else if ((signature.nSize > 0) && (nContainerCount < 2)) {
        if (signature.nOffset < nUXEnd) return result;
        nEngineEnd = signature.nOffset + signature.nSize;
    }

    qint64 nAttachedOffset = -1;
    qint64 nAttachedSize = 0;
    qint64 nPhysicalEnd = nEngineEnd;
    if (nContainerCount == 2) {
        if (nAttachedSizeField < (qint64)sizeof(XCab::CFHEADER)) return result;
        nAttachedOffset = nEngineEnd;
        nAttachedSize = nAttachedSizeField;
        if (!burnRangeIsValid(nAttachedOffset, nAttachedSize, nTotalSize)) return result;
        nPhysicalEnd = nAttachedOffset + nAttachedSize;
    } else if (nAttachedSizeField != 0) {
        return result;
    }

    // A valid writer leaves only the current Authenticode certificate after
    // the UX/attached contents.  For a one-container signed bundle EngineEnd
    // itself includes that certificate, so compare against the actual content
    // boundary rather than EngineEnd.
    const qint64 nContentEnd = (nContainerCount == 2) ? nPhysicalEnd : nUXEnd;
    if (signature.nSize > 0) {
        if ((signature.nOffset < nContentEnd) ||
            ((signature.nOffset + signature.nSize) != nTotalSize)) return result;
    } else if (nPhysicalEnd != nTotalSize) {
        return result;
    }

    QList<BURN_CAB_ENTRY> listUXEntries;
    QList<BURN_CAB_ENTRY> listAttachedEntries;
    QByteArray baManifest;
    if (!burnScanCabinet(getDevice(), nStubSize, nUXSize, true, &listUXEntries, &baManifest, pPdStruct)) {
        return result;
    }
    if ((nContainerCount == 2) &&
        !burnScanCabinet(getDevice(), nAttachedOffset, nAttachedSize, false,
                         &listAttachedEntries, nullptr, pPdStruct)) {
        return result;
    }

    BURN_MANIFEST_INFO manifestInfo = {};
    if (!burnParseManifest(baManifest, &manifestInfo, pPdStruct) ||
        (manifestInfo.bHasAttachedContainer != (nContainerCount == 2))) {
        return result;
    }
    if (nContainerCount == 2) {
        if ((manifestInfo.nAttachedContainerSize != nAttachedSize) ||
            (manifestInfo.baAttachedContainerSHA1.size() != 20)) {
            return result;
        }
        QByteArray baAttachedSHA1;
        if (!burnHashRange(getDevice(), nAttachedOffset, nAttachedSize, &baAttachedSHA1, pPdStruct) ||
            (baAttachedSHA1 != manifestInfo.baAttachedContainerSHA1)) {
            return result;
        }
    } else if (!manifestInfo.listAttachedPayloads.isEmpty()) {
        return result;
    }

    QList<PAYLOAD_RECORD> listPublicPayloads;
    PAYLOAD_RECORD manifestPayload = {};
    manifestPayload.containerType = CONTAINER_TYPE_UX;
    manifestPayload.nInnerIndex = listUXEntries.constFirst().nIndex;
    manifestPayload.sSourcePath = QStringLiteral("0");
    manifestPayload.sFilePath = QStringLiteral("manifest.xml");
    manifestPayload.sPayloadId = QStringLiteral("BurnManifest");
    manifestPayload.nFileSize = baManifest.size();
    manifestPayload.baSHA1 = QCryptographicHash::hash(baManifest, QCryptographicHash::Sha1);
    listPublicPayloads.append(manifestPayload);

    if (!burnMapCabinetPayloads(listUXEntries, manifestInfo.listUXPayloads,
                                CONTAINER_TYPE_UX, &listPublicPayloads) ||
        !burnMapCabinetPayloads(listAttachedEntries, manifestInfo.listAttachedPayloads,
                                CONTAINER_TYPE_ATTACHED, &listPublicPayloads) ||
        !burnAssignPublicPaths(&listPublicPayloads)) {
        return result;
    }

    result.bIsValid = true;
    result.baBundleId = baBundleId;
    result.nUXOffset = nStubSize;
    result.nUXSize = nUXSize;
    result.nAttachedOffset = nAttachedOffset;
    result.nAttachedSize = nAttachedSize;
    result.listPayloads = listPublicPayloads;
    result.sVersion = pe.getResourcesVersionValue(QStringLiteral("FileVersion")).trimmed();
    if (result.sVersion.isEmpty()) result.sVersion = pe.getFileVersion().trimmed();
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) result.bIsValid = false;
    return result;
}

QMap<XBinary::UNPACK_PROP, QVariant> XBurn::getDefaultUnpackProperties()
{
    return XBinary::getDefaultUnpackProperties();
}

namespace {
static bool burnOpenContainer(XBurn::CONTAINER_CONTEXT *pContainer, QIODevice *pSource,
                              const QMap<XBinary::UNPACK_PROP, QVariant> &mapProperties,
                              XBinary::PDSTRUCT *pPdStruct)
{
    if (!pContainer || !pSource || (pContainer->nOuterOffset < 0) ||
        (pContainer->nOuterSize < (qint64)sizeof(XCab::CFHEADER))) return false;

    pContainer->pSubDevice = new SubDevice(pSource, pContainer->nOuterOffset, pContainer->nOuterSize);
    if (!pContainer->pSubDevice->open(QIODevice::ReadOnly)) {
        delete pContainer->pSubDevice;
        pContainer->pSubDevice = nullptr;
        return false;
    }

    pContainer->pCab = new XCab(pContainer->pSubDevice);
    if (!pContainer->pCab->initUnpack(&pContainer->state, mapProperties, pPdStruct)) {
        // XCab may allocate decoder state before reporting an initialization
        // failure.  Give it the matching cleanup call before destroying it.
        pContainer->pCab->finishUnpack(&pContainer->state, nullptr);
        delete pContainer->pCab;
        pContainer->pCab = nullptr;
        pContainer->pSubDevice->close();
        delete pContainer->pSubDevice;
        pContainer->pSubDevice = nullptr;
        pContainer->state = XBinary::UNPACK_STATE();
        return false;
    }
    pContainer->bInitialized = true;
    return true;
}

static bool burnResolveActiveRecord(
    XBurn *pThis, const QSharedPointer<XBurn::UNPACK_LIFETIME_STATE> &pLifetime,
    XBinary::UNPACK_STATE *pState, XBurn::UNPACK_CONTEXT **ppContext,
    XBurn::CONTAINER_CONTEXT **ppContainer, const XBurn::PAYLOAD_RECORD **ppPayload)
{
    if (!pThis || !pLifetime || !pState || !ppContext || !ppContainer || !ppPayload ||
        !pState->pContext || !pState->baUnpackSourceToken.isEmpty() ||
        (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }

    XBurn::UNPACK_CONTEXT *pContext = static_cast<XBurn::UNPACK_CONTEXT *>(pState->pContext);
    if (!pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pContext->pOwnerState != pState) || !pContext->pOuterSourceDevice ||
        (pContext->pOuterSourceDevice != pThis->getDevice()) ||
        (pContext->nOwnerDeviceGeneration != pThis->getDeviceGeneration()) ||
        !pContext->pSourceValidator ||
        (pContext->nCurrentPayload != pState->nCurrentIndex) ||
        (pContext->listPayloads.size() != pState->nNumberOfRecords)) {
        return false;
    }

    const XBurn::PAYLOAD_RECORD *pPayload = &pContext->listPayloads.at(pContext->nCurrentPayload);
    XBurn::CONTAINER_CONTEXT *pContainer = burnGetContainer(pContext, pPayload->containerType);
    if (!pContainer || !pContainer->bInitialized || !pContainer->pCab ||
        (pContainer->state.nCurrentIndex != pPayload->nInnerIndex) ||
        (pContainer->state.nCurrentOffset != pState->nCurrentOffset)) {
        return false;
    }

    *ppContext = pContext;
    *ppContainer = pContainer;
    *ppPayload = pPayload;
    return true;
}
}  // namespace

bool XBurn::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties,
                       PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    BurnOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XBurn> guardedThis(this);

    if (pState->pContext) {
        UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pLifetime->setContexts.contains(pOldContext) || (pOldContext->pOwnerState != pState)) return false;
        pLifetime->setContexts.remove(pOldContext);
        pState->pContext = nullptr;
        const bool bClean = deleteUnpackContext(pOldContext);
        *pState = UNPACK_STATE();
        if (!guardedThis || !pLifetime->bOwnerAlive || !bClean) return false;
    }
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    *pState = UNPACK_STATE();
    pState->mapUnpackProperties = mapProperties;

    QPointer<QIODevice> guardedSource(getDevice());
    if (!guardedSource) return false;
    XArchive *pSourceValidator = new XArchive(guardedSource.data());
    UNPACK_STATE sourceValidationState = {};
    if (!pSourceValidator->bindUnpackSource(&sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedSource) {
        pSourceValidator->releaseUnpackSource(&sourceValidationState);
        delete pSourceValidator;
        return false;
    }

    XBurn detector(guardedSource.data(), isImage(), getModuleAddress());
    const qint64 nTotalSize = guardedSource->size();
    const INTERNAL_INFO info = detector._detect(pPdStruct);
    if (!guardedThis || !guardedSource || (nTotalSize < 0) || !info.bIsValid ||
        !pSourceValidator->isUnpackSourceCurrent(&sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedSource || !pLifetime->bOwnerAlive) {
        pSourceValidator->releaseUnpackSource(&sourceValidationState);
        delete pSourceValidator;
        return false;
    }

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;
    pContext->pOuterSourceDevice = guardedSource;
    pContext->nOwnerDeviceGeneration = getDeviceGeneration();
    pContext->pOwnerState = nullptr;
    burnInitializeContainerContext(&pContext->ux, info.nUXOffset, info.nUXSize);
    burnInitializeContainerContext(&pContext->attached, info.nAttachedOffset, info.nAttachedSize);
    pContext->listPayloads = info.listPayloads;
    pContext->nCurrentPayload = 0;
    pContext->pSourceValidator = pSourceValidator;
    pContext->sourceValidationState = UNPACK_STATE();

    if (!pContext->pSourceValidator->transferUnpackSourceOwnership(
            &sourceValidationState, &pContext->sourceValidationState)) {
        pContext->pSourceValidator->releaseUnpackSource(&sourceValidationState);
        deleteUnpackContext(pContext);
        return false;
    }

    bool bOpen = burnOpenContainer(&pContext->ux, guardedSource.data(), mapProperties, pPdStruct);
    if (bOpen && (info.nAttachedSize > 0)) {
        bOpen = burnOpenContainer(&pContext->attached, guardedSource.data(), mapProperties, pPdStruct);
    }
    if (!bOpen || !guardedThis || !guardedSource || !pLifetime->bOwnerAlive ||
        (pContext->ux.state.nNumberOfRecords < 1)) {
        deleteUnpackContext(pContext);
        return false;
    }

    if (!pContext->listPayloads.isEmpty()) {
        const PAYLOAD_RECORD &firstPayload = pContext->listPayloads.constFirst();
        CONTAINER_CONTEXT *pFirstContainer = burnGetContainer(pContext, firstPayload.containerType);
        if (!burnPositionContainer(pFirstContainer, firstPayload.nInnerIndex, pPdStruct) ||
            !guardedThis || !guardedSource || !pLifetime->bOwnerAlive) {
            deleteUnpackContext(pContext);
            return false;
        }
    }

    if (!pContext->pSourceValidator->validateAndFinalizeUnpackSource(
            &pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedSource || !pLifetime->bOwnerAlive) {
        deleteUnpackContext(pContext);
        return false;
    }

    pState->nTotalSize = nTotalSize;
    pState->nNumberOfRecords = pContext->listPayloads.size();
    pState->nCurrentIndex = 0;
    if (!pContext->listPayloads.isEmpty()) {
        CONTAINER_CONTEXT *pFirstContainer = burnGetContainer(
            pContext, pContext->listPayloads.constFirst().containerType);
        if (!pFirstContainer) {
            deleteUnpackContext(pContext);
            return false;
        }
        pState->nCurrentOffset = pFirstContainer->state.nCurrentOffset;
        pState->mapArchiveProperties = pFirstContainer->state.mapArchiveProperties;
    } else {
        pState->nCurrentOffset = 0;
        pState->mapArchiveProperties = pContext->ux.state.mapArchiveProperties;
    }
    pContext->pOwnerState = pState;
    pState->pContext = pContext;
    pLifetime->setContexts.insert(pContext);
    return true;
}

XBinary::ARCHIVERECORD XBurn::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    ARCHIVERECORD result = {};
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    BurnOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired() || !XBinary::isPdStructNotCanceled(pPdStruct)) return result;
    QPointer<XBurn> guardedThis(this);

    UNPACK_CONTEXT *pContext = nullptr;
    CONTAINER_CONTEXT *pContainer = nullptr;
    const PAYLOAD_RECORD *pPayload = nullptr;
    if (!burnResolveActiveRecord(this, pLifetime, pState, &pContext, &pContainer, &pPayload) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext)) {
        return result;
    }

    result = pContainer->pCab->infoCurrent(&pContainer->state, pPdStruct);
    if (!guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext)) {
        return ARCHIVERECORD();
    }

    bool bInnerSizeOK = false;
    const qint64 nInnerSize = result.mapProperties.value(FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(&bInnerSizeOK);
    if (!bInnerSizeOK || (nInnerSize != pPayload->nFileSize) ||
        (result.mapProperties.value(FPART_PROP_ORIGINALNAME).toString() != pPayload->sSourcePath)) {
        return ARCHIVERECORD();
    }

    if (result.nStreamSize > 0) {
        if (!burnRangeIsValid(result.nStreamOffset, result.nStreamSize, pContainer->nOuterSize) ||
            (result.nStreamOffset > ((std::numeric_limits<qint64>::max)() - pContainer->nOuterOffset))) {
            return ARCHIVERECORD();
        }
        result.nStreamOffset += pContainer->nOuterOffset;
        result.mapProperties.insert(FPART_PROP_STREAMOFFSET, result.nStreamOffset);
        result.mapProperties.insert(FPART_PROP_STREAMSIZE, result.nStreamSize);
    }

    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, pPayload->sPublicPath);
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, pPayload->nFileSize);
    result.mapProperties.insert(FPART_PROP_RESOURCEID, pPayload->sPayloadId);
    QString sInfo = (pPayload->containerType == CONTAINER_TYPE_UX)
                        ? QStringLiteral("WiX Burn UX payload")
                        : QStringLiteral("WiX Burn attached payload");
    if (!pPayload->sPackageType.isEmpty()) {
        sInfo = QStringLiteral("WiX Burn %1 package").arg(pPayload->sPackageType);
        if (!pPayload->sPackageId.isEmpty()) sInfo += QStringLiteral(" (%1)").arg(pPayload->sPackageId);
    }
    if (pPayload->sPublicPath != pPayload->sFilePath) {
        sInfo += QStringLiteral("; manifest path: %1").arg(pPayload->sFilePath);
    }
    result.mapProperties.insert(FPART_PROP_INFO, sInfo);
    return result;
}

bool XBurn::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    BurnOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XBurn> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!guardedOutput || !guardedOutput->isOpen() || !guardedOutput->isWritable() ||
        guardedOutput->isSequential() || !guardedThis || !guardedOutput ||
        (guardedOutput->openMode() & (QIODevice::Append | QIODevice::Text)) ||
        !XBinary::isResizeEnable(guardedOutput.data()) || !guardedThis || !guardedOutput ||
        !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    UNPACK_CONTEXT *pContext = nullptr;
    CONTAINER_CONTEXT *pContainer = nullptr;
    const PAYLOAD_RECORD *pPayload = nullptr;
    if (!burnResolveActiveRecord(this, pLifetime, pState, &pContext, &pContainer, &pPayload) ||
        XBinary::devicesAlias(pContext->pOuterSourceDevice.data(), guardedOutput.data()) ||
        !guardedThis || !guardedOutput ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) {
        return false;
    }

    QTemporaryFile stage;
    if (!stage.open()) return false;
    if (!pContainer->pCab->unpackCurrent(&pContainer->state, &stage, pPdStruct) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) {
        return false;
    }

    QByteArray baSHA1;
    if ((stage.size() != pPayload->nFileSize) ||
        !burnHashDevice(&stage, &baSHA1, pPdStruct) || (baSHA1 != pPayload->baSHA1) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) {
        return false;
    }

    BurnPublisher publisher(pContext->pOuterSourceDevice.data());
    UNPACK_STATE publicationState = {};
    if (!publisher.bindUnpackSource(&publicationState, pPdStruct) ||
        !publisher.validateAndFinalizeUnpackSource(&publicationState, pPdStruct) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext) ||
        !publisher.publishUnpackOutput(&stage, guardedOutput.data(), &publicationState, pPdStruct) ||
        !guardedThis || !guardedOutput || !pLifetime->bOwnerAlive ||
        !pLifetime->setContexts.contains(pContext) || (pState->pContext != pContext)) {
        return false;
    }

    pState->nCurrentOffset = pContainer->state.nCurrentOffset;
    pState->mapArchiveProperties = pContainer->state.mapArchiveProperties;
    return true;
}

bool XBurn::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    BurnOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    QPointer<XBurn> guardedThis(this);

    UNPACK_CONTEXT *pContext = nullptr;
    CONTAINER_CONTEXT *pCurrentContainer = nullptr;
    const PAYLOAD_RECORD *pCurrentPayload = nullptr;
    if (!burnResolveActiveRecord(this, pLifetime, pState, &pContext, &pCurrentContainer, &pCurrentPayload) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext)) {
        return false;
    }

    const qint32 nNextPayload = pContext->nCurrentPayload + 1;
    if (nNextPayload >= pContext->listPayloads.size()) {
        // Match the streaming API convention used by the other static unpackers:
        // the final move reports false, but advances the state to the end sentinel.
        pContext->nCurrentPayload = nNextPayload;
        pState->nCurrentIndex = nNextPayload;
        pState->nCurrentOffset = 0;
        return false;
    }
    const PAYLOAD_RECORD &nextPayload = pContext->listPayloads.at(nNextPayload);
    CONTAINER_CONTEXT *pNextContainer = burnGetContainer(pContext, nextPayload.containerType);
    if (!burnPositionContainer(pNextContainer, nextPayload.nInnerIndex, pPdStruct) ||
        !guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext) ||
        !pContext->pSourceValidator->isUnpackSourceCurrent(&pContext->sourceValidationState, pPdStruct) ||
        !guardedThis || !pLifetime->bOwnerAlive || !pLifetime->setContexts.contains(pContext) ||
        (pState->pContext != pContext)) {
        return false;
    }

    pContext->nCurrentPayload = nNextPayload;
    pState->nCurrentIndex = nNextPayload;
    pState->nCurrentOffset = pNextContainer->state.nCurrentOffset;
    pState->mapArchiveProperties = pNextContainer->state.mapArchiveProperties;
    return true;
}

bool XBurn::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState || !pState->baUnpackSourceToken.isEmpty()) return false;
    QSharedPointer<UNPACK_LIFETIME_STATE> pLifetime = m_pUnpackLifetimeState;
    BurnOperationGuard operationGuard(pLifetime);
    if (!operationGuard.isAcquired()) return false;
    QPointer<XBurn> guardedThis(this);

    bool bResult = true;
    if (pState->pContext) {
        UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
        if (!pLifetime->setContexts.contains(pContext) || (pContext->pOwnerState != pState)) return false;
        pLifetime->setContexts.remove(pContext);
        pState->pContext = nullptr;
        bResult = deleteUnpackContext(pContext);
        if (!guardedThis || !pLifetime->bOwnerAlive) return false;
    }
    *pState = UNPACK_STATE();
    return bResult;
}
