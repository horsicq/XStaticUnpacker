/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */

#include "xsmartinstall.h"

#include <climits>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <cstring>
#include <zlib.h>

#include "Algos/xlzxdecoder.h"
#include "xpe.h"

static const qint64 SI_MAX_ARCHIVE_SIZE = 256ll << 20;
static const qint32 SI_MAX_COMPANION_VOLUMES = 256;
static const qint32 SI_MAX_CONFIG_FIELDS = 0x40000;
static const qint32 SI_MAX_FILE_COUNT = 0x10000;

XSmartInstall::XSmartInstall(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress) : XBinary(pDevice, bIsImage, nModuleAddress)
{
    setIsArchive(true);
}

XSmartInstall::~XSmartInstall()
{
}

bool XSmartInstall::isValid(PDSTRUCT *pPdStruct)
{
    return static_cast<INTERNAL_INFO *>(getInternalInfo(pPdStruct))->bIsValid;
}

bool XSmartInstall::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XSmartInstall x(pDevice);
    return x.isValid(pPdStruct);
}

XSmartInstall::INTERNAL_INFO XSmartInstall::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    return _detect(pPdStruct);
}

// Cache format-specific parsing together with the XBinary memory map.
bool XSmartInstall::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    if (!isInternalInfoHandled()) {
        m_internalInfo = INTERNAL_INFO();
        setIsInternalInfoHandled(true);
        m_internalInfo = _getInternalInfo(pPdStruct);
        m_internalInfo.memoryMap = getMemoryMap(MAPMODE_UNKNOWN, pPdStruct);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
    }

    return true;
}

void *XSmartInstall::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);
    return &m_internalInfo;
}

void XSmartInstall::setInternalInfo(void *pInternalInfo)
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

XBinary::FT XSmartInstall::getFileType()
{
    return FT_ARCHIVE;
}

static inline quint32 siRd32(const quint8 *p)
{
    return (quint32)(p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24));
}
static inline quint16 siRd16(const quint8 *p)
{
    return (quint16)(p[0] | ((quint16)p[1] << 8));
}
static inline quint64 siRd64(const quint8 *p)
{
    quint64 v = 0;
    for (int i = 0; i < 8; i++) v |= ((quint64)p[i]) << (8 * i);
    return v;
}

static quint32 siCabChecksum(const quint8 *pData, qint64 nSize, quint32 nSeed = 0)
{
    if (!pData || (nSize < 0)) return 0;

    qint64 nOffset = 0;
    while (nSize - nOffset >= 4) {
        nSeed ^= siRd32(pData + nOffset);
        nOffset += 4;
    }

    const qint64 nRemaining = nSize - nOffset;
    if (nRemaining == 3) {
        nSeed ^= ((quint32)pData[nOffset] << 16) | ((quint32)pData[nOffset + 1] << 8) | pData[nOffset + 2];
    } else if (nRemaining == 2) {
        nSeed ^= ((quint32)pData[nOffset] << 8) | pData[nOffset + 1];
    } else if (nRemaining == 1) {
        nSeed ^= pData[nOffset];
    }
    return nSeed;
}

static qint64 siDataEnd(XPE *pPe, qint64 nFileSize)
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

static QString siGenericName(qint32 nIndex)
{
    return QString("file_%1").arg(nIndex, 4, 10, QChar('0'));
}

static bool siIsDecimalField(const QByteArray &baValue)
{
    if (baValue.isEmpty() || (baValue.size() > 10)) return false;
    for (int i = 0; i < baValue.size(); i++) {
        if ((baValue.at(i) < '0') || (baValue.at(i) > '9')) return false;
    }
    return true;
}

static bool siSplitConfigFields(const QByteArray &baConfig, QList<QByteArray> *pListFields)
{
    if (!pListFields) return false;
    pListFields->clear();

    int nPosition = 0;
    while (nPosition <= baConfig.size()) {
        if (pListFields->size() >= SI_MAX_CONFIG_FIELDS) {
            pListFields->clear();
            return false;
        }

        int nEnd = baConfig.indexOf('\0', nPosition);
        if (nEnd < 0) nEnd = baConfig.size();
        pListFields->append(baConfig.mid(nPosition, nEnd - nPosition));
        if (nEnd == baConfig.size()) break;
        nPosition = nEnd + 1;
    }

    return true;
}

// Manifest paths have the form "@$&%NN\<relative path>".  Accept only clean,
// relative paths so an unrelated config string can never become an output name.
static QString siManifestPath(const QByteArray &baValue)
{
    if ((baValue.size() > 4096) || !baValue.startsWith("@$&%")) return QString();

    int nPos = 4;
    int nDigits = 0;
    while ((nPos < baValue.size()) && (baValue.at(nPos) >= '0') && (baValue.at(nPos) <= '9')) {
        nPos++;
        nDigits++;
    }
    if ((nDigits == 0) || (nPos >= baValue.size()) || ((baValue.at(nPos) != '\\') && (baValue.at(nPos) != '/'))) return QString();

    QString sPath = QString::fromLatin1(baValue.mid(nPos + 1));
    sPath.replace('\\', '/');
    sPath = QDir::cleanPath(sPath);
    if (sPath.isEmpty() || (sPath == ".") || QDir::isAbsolutePath(sPath) || sPath.contains(':') || (sPath == "..") || sPath.startsWith("../") ||
        sPath.contains("/../")) {
        return QString();
    }

    static const QString sForbidden = QStringLiteral("<>:\"\\|?*");
    static const QSet<QString> setReserved = {
        QStringLiteral("CON"),  QStringLiteral("PRN"),  QStringLiteral("AUX"),  QStringLiteral("NUL"),  QStringLiteral("COM1"),
        QStringLiteral("COM2"), QStringLiteral("COM3"), QStringLiteral("COM4"), QStringLiteral("COM5"), QStringLiteral("COM6"),
        QStringLiteral("COM7"), QStringLiteral("COM8"), QStringLiteral("COM9"), QStringLiteral("LPT1"), QStringLiteral("LPT2"),
        QStringLiteral("LPT3"), QStringLiteral("LPT4"), QStringLiteral("LPT5"), QStringLiteral("LPT6"), QStringLiteral("LPT7"),
        QStringLiteral("LPT8"), QStringLiteral("LPT9")};
    const QStringList listComponents = sPath.split('/');
    for (const QString &sComponent : listComponents) {
        if (sComponent.isEmpty() || (sComponent == ".") || (sComponent == "..") || (sComponent.size() > 255) ||
            sComponent.endsWith(' ') || sComponent.endsWith('.')) {
            return QString();
        }
        for (QChar character : sComponent) {
            if (sForbidden.contains(character) || !character.isPrint()) return QString();
        }
        if (setReserved.contains(sComponent.section('.', 0, 0).toUpper())) return QString();
    }

    return sPath;
}

// A real file-manifest entry is a path followed by two decimal fields.  Other
// path-like config values do not have this shape.  The three decimal fields
// immediately before the manifest include the total compressed-region size.
// Select only a unique longest run so suffixes and unrelated target paths
// cannot be mistaken for the declaration.
static bool siManifestDeclaration(const QByteArray &baConfig, QStringList *pListNames, qint64 *pnArchiveSize)
{
    if (!pListNames || !pnArchiveSize) return false;
    pListNames->clear();
    *pnArchiveSize = -1;

    QList<QByteArray> listFields;
    if (!siSplitConfigFields(baConfig, &listFields)) return false;
    QMap<QString, QPair<QStringList, qint64> > mapCandidates;
    qint32 nBestCount = 0;

    for (int i = 0; i + 2 < listFields.size();) {
        const int nStart = i;
        QStringList listRun;
        int nPos = nStart;

        while (nPos + 2 < listFields.size()) {
            QString sPath = siManifestPath(listFields.at(nPos));
            if (sPath.isEmpty() || !siIsDecimalField(listFields.at(nPos + 1)) || !siIsDecimalField(listFields.at(nPos + 2))) break;
            listRun.append(sPath);
            if (listRun.size() > 0x10000) return false;
            nPos += 3;
        }

        if (listRun.isEmpty()) {
            i++;
            continue;
        }

        if ((nStart >= 3) && siIsDecimalField(listFields.at(nStart - 3)) && siIsDecimalField(listFields.at(nStart - 2)) &&
            siIsDecimalField(listFields.at(nStart - 1))) {
            bool bSizeValid = false;
            qint64 nArchiveSize = listFields.at(nStart - 3).toLongLong(&bSizeValid);
            if (bSizeValid && (nArchiveSize >= 0) && (nArchiveSize <= SI_MAX_ARCHIVE_SIZE)) {
                if (listRun.size() > nBestCount) {
                    nBestCount = listRun.size();
                    mapCandidates.clear();
                }
                if (listRun.size() == nBestCount) {
                    QString sKey = listRun.join(QChar(0x1f)) + QChar(0x1e) + QString::number(nArchiveSize);
                    mapCandidates.insert(sKey, qMakePair(listRun, nArchiveSize));
                }
            }
        }

        i = nPos;
    }

    if ((nBestCount <= 0) || (mapCandidates.size() != 1)) return false;

    *pListNames = mapCandidates.constBegin().value().first;
    *pnArchiveSize = mapCandidates.constBegin().value().second;
    return true;
}

static bool siAssignManifestNames(QList<XSmartInstall::FILE_ENTRY> *pListEntries, const QStringList &listManifest)
{
    if (!pListEntries || (listManifest.size() != pListEntries->size())) return false;

    QSet<qint32> setIndexes;
    QSet<QString> setNames;
    for (int i = 0; i < pListEntries->size(); i++) {
        qint32 nIndex = pListEntries->at(i).nNameIndex;
        if ((nIndex < 0) || (nIndex >= listManifest.size()) || setIndexes.contains(nIndex)) return false;
        QString sNameKey = listManifest.at(nIndex).toCaseFolded();
        if (setNames.contains(sNameKey)) return false;
        setIndexes.insert(nIndex);
        setNames.insert(sNameKey);
    }

    for (int i = 0; i < pListEntries->size(); i++) {
        XSmartInstall::FILE_ENTRY &entry = (*pListEntries)[i];
        entry.sName = listManifest.at(entry.nNameIndex);
    }
    return true;
}

static bool siLooksLikeCabHeader(const quint8 *p, qint64 nRegionSize)
{
    if (!p || (nRegionSize < 48) || (nRegionSize > SI_MAX_ARCHIVE_SIZE)) return false;

    quint32 nCabinetSize = siRd32(p + 4);
    quint32 nFilesOffset = siRd32(p + 12);
    quint16 nFolders = siRd16(p + 22);
    quint16 nFiles = siRd16(p + 24);
    quint32 nDataOffset = siRd32(p + 32);
    quint16 nDataBlocks = siRd16(p + 36);
    quint16 nCompression = siRd16(p + 38);
    quint16 nMethod = nCompression & 0x000f;

    // Every observed SIM region is literally a complete CAB with only "MSCF"
    // removed, so all CAB absolute offsets/sizes are four bytes larger.
    if ((siRd32(p) != 0) || (siRd32(p + 8) != 0) || (siRd32(p + 16) != 0) ||
        (p[20] != 3) || (p[21] != 1) || (siRd16(p + 26) != 0)) {
        return false;
    }
    if ((nCabinetSize != (quint32)nRegionSize + 4) || (nFolders != 1) || (nFiles == 0)) return false;
    if ((nFilesOffset != 44) || ((qint64)nFilesOffset - 4 >= nRegionSize)) return false;
    if (nDataOffset < 44) return false;
    if (nDataBlocks) {
        if ((qint64)nDataOffset - 4 + 8 > nRegionSize) return false;
    } else if ((qint64)nDataOffset - 4 != nRegionSize) {
        // A CAB containing only empty files has no CFDATA records; its folder
        // data offset points exactly one byte past this signature-less region.
        return false;
    }
    if ((nMethod != 1) && (nMethod != 3)) return false;  // MSZIP or LZX
    if ((nMethod == 3) && ((((nCompression >> 8) & 0x1f) < 15) || (((nCompression >> 8) & 0x1f) > 21))) return false;

    return true;
}

static bool siLooksLikeCabRegion(const QByteArray &baRegion)
{
    return siLooksLikeCabHeader(reinterpret_cast<const quint8 *>(baRegion.constData()), baRegion.size());
}

static bool siVolumePattern(const QByteArray &baConfig, QString *psPrefix, QString *psSuffix)
{
    if (!psPrefix || !psSuffix) return false;

    QMap<QString, QPair<QString, QString> > mapPatterns;
    QList<QByteArray> listFields;
    if (!siSplitConfigFields(baConfig, &listFields)) return false;
    for (int i = 0; i < listFields.size(); i++) {
        QByteArray baField = listFields.at(i);
        if (baField.size() > 4096) continue;
        int nMacro = baField.indexOf("@$&%");
        if (nMacro < 0) continue;

        int nPos = nMacro + 4;
        int nDigits = 0;
        while ((nPos < baField.size()) && (baField.at(nPos) >= '0') && (baField.at(nPos) <= '9')) {
            nPos++;
            nDigits++;
        }
        if ((nDigits == 0) || (nMacro == 0) || (nPos >= baField.size())) continue;

        QString sPrefix = QString::fromLatin1(baField.left(nMacro));
        QString sSuffix = QString::fromLatin1(baField.mid(nPos));
        if (!sSuffix.endsWith(".pak", Qt::CaseInsensitive)) continue;
        mapPatterns.insert(sPrefix.toLower() + QChar(0x1f) + sSuffix.toLower(), qMakePair(sPrefix, sSuffix));
    }

    if (mapPatterns.size() != 1) return false;
    *psPrefix = mapPatterns.constBegin().value().first;
    *psSuffix = mapPatterns.constBegin().value().second;
    return true;
}

static bool siCompanionCabRegions(QIODevice *pDevice, const QByteArray &baConfig, qint64 nDeclaredSize, QList<QByteArray> *pListRegions,
                                  XBinary::PDSTRUCT *pPdStruct)
{
    if (!pListRegions || (nDeclaredSize <= 0) || (nDeclaredSize > SI_MAX_ARCHIVE_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    pListRegions->clear();

    QFile *pInputFile = qobject_cast<QFile *>(pDevice);
    if (!pInputFile) return false;

    QString sPrefix;
    QString sSuffix;
    if (!siVolumePattern(baConfig, &sPrefix, &sSuffix)) return false;

    QFileInfo inputInfo(pInputFile->fileName());
    QDir inputDir(inputInfo.absolutePath());
    QFileInfoList listFiles = inputDir.entryInfoList(QDir::Files | QDir::Readable, QDir::Name | QDir::IgnoreCase);
    QMap<qint32, QFileInfo> mapVolumes;
    qint32 nCandidates = 0;

    for (int i = 0; i < listFiles.size(); i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        const QFileInfo &fileInfo = listFiles.at(i);
        if (fileInfo.absoluteFilePath() == inputInfo.absoluteFilePath()) continue;

        QString sFileName = fileInfo.fileName();
        if (!sFileName.startsWith(sPrefix, Qt::CaseInsensitive) || !sFileName.endsWith(sSuffix, Qt::CaseInsensitive) ||
            (sFileName.size() <= sPrefix.size() + sSuffix.size())) {
            continue;
        }

        QString sNumber = sFileName.mid(sPrefix.size(), sFileName.size() - sPrefix.size() - sSuffix.size());
        bool bDecimal = !sNumber.isEmpty();
        for (int j = 0; j < sNumber.size(); j++) {
            if ((sNumber.at(j) < QChar('0')) || (sNumber.at(j) > QChar('9'))) {
                bDecimal = false;
                break;
            }
        }
        if (!bDecimal || fileInfo.isSymLink()) continue;

        bool bNumberValid = false;
        qint32 nVolume = sNumber.toInt(&bNumberValid);
        if (!bNumberValid || (nVolume < 2)) continue;

        qint64 nCandidateSize = fileInfo.size();
        if ((nCandidateSize < 48) || (nCandidateSize > SI_MAX_ARCHIVE_SIZE)) continue;
        QFile headerFile(fileInfo.absoluteFilePath());
        if (!headerFile.open(QIODevice::ReadOnly)) continue;
        QByteArray baHeader = headerFile.read(40);
        headerFile.close();
        if ((baHeader.size() != 40) ||
            !siLooksLikeCabHeader(reinterpret_cast<const quint8 *>(baHeader.constData()), nCandidateSize)) {
            continue;
        }

        nCandidates++;
        if (nCandidates > SI_MAX_COMPANION_VOLUMES || mapVolumes.contains(nVolume)) return false;
        mapVolumes.insert(nVolume, fileInfo);
    }

    if (mapVolumes.isEmpty()) return false;

    qint32 nExpectedVolume = 2;
    qint64 nAggregateSize = 0;
    for (QMap<qint32, QFileInfo>::const_iterator it = mapVolumes.constBegin(); it != mapVolumes.constEnd(); ++it, ++nExpectedVolume) {
        if (it.key() != nExpectedVolume) return false;

        qint64 nFileSize = it.value().size();
        if ((nFileSize < 48) || (nFileSize > SI_MAX_ARCHIVE_SIZE) || (nFileSize > SI_MAX_ARCHIVE_SIZE - nAggregateSize)) return false;
        nAggregateSize += nFileSize;
    }

    if (nAggregateSize != nDeclaredSize) return false;

    for (QMap<qint32, QFileInfo>::const_iterator it = mapVolumes.constBegin(); it != mapVolumes.constEnd(); ++it) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        qint64 nFileSize = it.value().size();
        QFile file(it.value().absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly) || (file.size() != nFileSize)) return false;

        QByteArray baRegion;
        baRegion.reserve((int)nFileSize);
        while (baRegion.size() < nFileSize) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                file.close();
                return false;
            }
            qint64 nToRead = qMin(Q_INT64_C(1024) * 1024, nFileSize - baRegion.size());
            QByteArray baChunk = file.read(nToRead);
            if (baChunk.size() != nToRead) {
                file.close();
                return false;
            }
            baRegion.append(baChunk);
        }
        bool bExactFile = (file.size() == nFileSize) && file.atEnd();
        file.close();

        if (!XBinary::isPdStructNotCanceled(pPdStruct) || !bExactFile || (baRegion.size() != nFileSize) || !siLooksLikeCabRegion(baRegion)) return false;
        pListRegions->append(baRegion);
    }

    return !pListRegions->isEmpty();
}

XSmartInstall::INTERNAL_INFO XSmartInstall::_detect(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result = {};
    result.nDataStart = -1;

    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return result;

    qint64 nOverlayOffset = pe.getOverlayOffset(pPdStruct);
    if ((nOverlayOffset <= 0) || (nOverlayOffset >= getSize())) return result;

    // Literal product tag "Smart Install Maker v" at the overlay start.
    QByteArray baTag = read_array_process(nOverlayOffset, 21, pPdStruct);
    if (baTag != QByteArray("Smart Install Maker v", 21)) return result;

    result.bIsValid = true;

    // Version digits: NUL-terminated ASCII at overlay + 0x17 ("v. <ver>\0").
    QString sVer = read_ansiString(nOverlayOffset + 0x17, 32).trimmed();
    if (!sVer.isEmpty()) result.sVersion = sVer;

    // 36-byte EOF footer: 4x u64 region pointers + [method:1][magic:3 = 03 78 F1].
    const qint64 nSize = getSize();
    const qint64 nDataEnd = siDataEnd(&pe, nSize);
    if ((nDataEnd >= 36) && (nDataEnd >= (nOverlayOffset + 36))) {
        QByteArray baFooter = read_array_process(nDataEnd - 36, 36, pPdStruct);
        if (baFooter.size() == 36) {
            const quint8 *pf = (const quint8 *)baFooter.constData();
            quint32 nFoot = siRd32(pf + 32);
            if ((nFoot >> 8) == 0xF17803) {
                quint8 nMethod = (quint8)(nFoot & 0xFF);
                quint64 q3 = siRd64(pf + 24);  // file-data region start (absolute)
                // Split builds legitimately point q3 at EOF-36: their CAB
                // region starts in a sibling diskN.pak rather than the EXE.
                if ((nMethod <= 1) && ((qint64)q3 >= nOverlayOffset) && ((qint64)q3 <= nDataEnd - 36)) {
                    result.bExtractable = true;
                    result.nMethod = nMethod;
                    result.nDataStart = (qint64)q3;
                }
            }
        }
    }

    return result;
}

// Raw-deflate (wbits -15) inflate of one block, with an optional preset dictionary.
// The reduced zlib in the build has no inflateSetDictionary, so the dictionary is
// supplied by prepending a stored (uncompressed) deflate block holding it and then
// stripping that prefix from the output. Reports block-N input bytes consumed.
static bool simInflate(const quint8 *pSrc, qint64 nSrcLen, const QByteArray &baDict, qint32 nExpectedSize, QByteArray *pOut, qint64 *pnConsumed,
                       XBinary::PDSTRUCT *pPdStruct)
{
    if (!pSrc || !pOut || (nSrcLen <= 0) || (nSrcLen > 0xFFFF) || (baDict.size() > 32768) || (nExpectedSize <= 0) ||
        (nExpectedSize > 32768)) {
        return false;
    }

    QByteArray baIn;
    int nPrefixIn = 0;
    if (!baDict.isEmpty()) {
        int nLen = baDict.size();  // <= 32768
        int nNlen = (~nLen) & 0xffff;
        baIn.append((char)0x00);  // stored block, BFINAL=0
        baIn.append((char)(nLen & 0xff));
        baIn.append((char)((nLen >> 8) & 0xff));
        baIn.append((char)(nNlen & 0xff));
        baIn.append((char)((nNlen >> 8) & 0xff));
        baIn.append(baDict);
        nPrefixIn = baIn.size();
    }
    baIn.append((const char *)pSrc, (int)qMin(nSrcLen, (qint64)0x7fffffff));

    z_stream s;
    memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, -15) != Z_OK) return false;
    s.next_in = (Bytef *)baIn.constData();
    s.avail_in = (uInt)baIn.size();

    QByteArray baFull;
    char aBuf[65536];
    bool bOk = false;
    for (;;) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) break;

        s.next_out = (Bytef *)aBuf;
        s.avail_out = sizeof(aBuf);
        int rc = inflate(&s, Z_NO_FLUSH);
        qint32 nProduced = sizeof(aBuf) - s.avail_out;
        if (nProduced > baDict.size() + nExpectedSize - baFull.size()) break;
        baFull.append(aBuf, nProduced);
        if (rc == Z_STREAM_END) {
            bOk = true;
            break;
        }
        if (rc != Z_OK) break;
        if ((s.avail_in == 0) && (s.avail_out == sizeof(aBuf))) break;
    }
    qint64 nTotalIn = (qint64)s.total_in;
    inflateEnd(&s);
    if (!bOk || !XBinary::isPdStructNotCanceled(pPdStruct) || (nTotalIn - nPrefixIn != nSrcLen) ||
        (baFull.size() != baDict.size() + nExpectedSize)) {
        return false;
    }

    *pOut = baFull.mid(baDict.size());  // strip the dictionary prefix
    if (pnConsumed) *pnConsumed = nTotalIn - nPrefixIn;
    return true;
}

static bool siDecodeCabRegion(const QByteArray &baRegion, QList<quint32> *pListSizes, QList<qint32> *pListIndexes, QByteArray *pbaCombined,
                              XBinary::PDSTRUCT *pPdStruct)
{
    if (!pListSizes || !pListIndexes || !pbaCombined || !siLooksLikeCabRegion(baRegion) || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    pListSizes->clear();
    pListIndexes->clear();
    pbaCombined->clear();

    const quint8 *p = reinterpret_cast<const quint8 *>(baRegion.constData());
    const qint64 nRegionSize = baRegion.size();
    quint32 nFilesOffset = siRd32(p + 12);
    quint16 nFiles = siRd16(p + 24);
    quint32 nDataOffset = siRd32(p + 32);
    quint16 nDataBlocks = siRd16(p + 36);
    quint16 nCompression = siRd16(p + 38);
    quint16 nMethod = nCompression & 0x000f;

    qint64 nFilePos = (qint64)nFilesOffset - 4;  // CAB offsets include the omitted signature
    quint64 nFileBytes = 0;

    for (quint16 i = 0; i < nFiles; i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        // Standard CFFILE: cbFile/uoffFolderStart/iFolder/date/time/attribs/name.
        if ((nFilePos < 0) || (nFilePos + 16 > nRegionSize)) return false;

        quint32 nFileSize = siRd32(p + nFilePos);
        quint32 nFolderOffset = siRd32(p + nFilePos + 4);
        quint16 nFolderIndex = siRd16(p + nFilePos + 8);
        if ((nFolderIndex != 0) || (nFolderOffset != nFileBytes)) return false;

        qint64 nNameEnd = nFilePos + 16;
        qint64 nNameLimit = qMin(nRegionSize, nNameEnd + 4096);
        while ((nNameEnd < nNameLimit) && p[nNameEnd]) nNameEnd++;
        if (nNameEnd >= nNameLimit) return false;

        QByteArray baCabName(reinterpret_cast<const char *>(p + nFilePos + 16), (int)(nNameEnd - (nFilePos + 16)));
        bool bIndexValid = false;
        qint32 nNameIndex = baCabName.toInt(&bIndexValid);
        if (!bIndexValid || !siIsDecimalField(baCabName)) return false;

        nFileBytes += nFileSize;
        if (nFileBytes > (quint64)SI_MAX_ARCHIVE_SIZE) return false;
        pListSizes->append(nFileSize);
        pListIndexes->append(nNameIndex);
        nFilePos = nNameEnd + 1;
    }

    qint64 nBlockPos = (qint64)nDataOffset - 4;
    if (nFilePos != nBlockPos) return false;
    quint64 nBlockBytes = 0;
    QByteArray baLzxStream;

    for (quint16 i = 0; i < nDataBlocks; i++) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

        if ((nBlockPos < 0) || (nBlockPos + 8 > nRegionSize)) return false;

        quint16 nCompressedSize = siRd16(p + nBlockPos + 4);
        quint16 nUncompressedSize = siRd16(p + nBlockPos + 6);
        qint64 nPayloadPos = nBlockPos + 8;
        if ((nCompressedSize == 0) || (nUncompressedSize == 0) || (nUncompressedSize > 32768) ||
            (nPayloadPos + nCompressedSize > nRegionSize)) {
            return false;
        }

        quint32 nStoredChecksum = siRd32(p + nBlockPos);
        if (nStoredChecksum) {
            quint32 nCalculatedChecksum = siCabChecksum(p + nBlockPos + 4, 4);
            nCalculatedChecksum = siCabChecksum(p + nPayloadPos, nCompressedSize, nCalculatedChecksum);
            if (nCalculatedChecksum != nStoredChecksum) return false;
        }

        nBlockBytes += nUncompressedSize;
        if (nBlockBytes > (quint64)SI_MAX_ARCHIVE_SIZE) return false;

        if (nMethod == 1) {
            // MSZIP CFDATA payload = "CK" + raw DEFLATE.  Its dictionary is
            // the final 32 KiB produced by all preceding CFDATA blocks.
            if ((nCompressedSize < 3) || (p[nPayloadPos] != 'C') || (p[nPayloadPos + 1] != 'K')) return false;

            QByteArray baBlock;
            qint64 nConsumed = 0;
            QByteArray baDictionary = (pbaCombined->size() > 32768) ? pbaCombined->right(32768) : *pbaCombined;
            if (!simInflate(p + nPayloadPos + 2, nCompressedSize - 2, baDictionary, nUncompressedSize, &baBlock, &nConsumed, pPdStruct) ||
                (nConsumed != nCompressedSize - 2) || (baBlock.size() != nUncompressedSize)) {
                return false;
            }
            pbaCombined->append(baBlock);
        } else {
            baLzxStream.append(reinterpret_cast<const char *>(p + nPayloadPos), nCompressedSize);
        }

        nBlockPos = nPayloadPos + nCompressedSize;
    }

    if ((nBlockBytes != nFileBytes) || (pListSizes->size() != nFiles) || (nBlockPos != nRegionSize)) return false;

    if ((nMethod == 3) && nBlockBytes) {
        qint32 nWindowBits = (nCompression >> 8) & 0x1f;
        if (!XLZXDecoder::decompressCABFolder(baLzxStream, pbaCombined, (qint64)nBlockBytes, nWindowBits, pPdStruct)) return false;
    } else if (!nBlockBytes && !baLzxStream.isEmpty()) {
        return false;
    }

    return XBinary::isPdStructNotCanceled(pPdStruct) && ((quint64)pbaCombined->size() == nFileBytes);
}

bool XSmartInstall::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    if (!pState) return false;

    pState->nCurrentOffset = 0;
    pState->nTotalSize = getSize();
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->pContext = nullptr;
    pState->mapUnpackProperties = mapProperties;

    INTERNAL_INFO info = _detect(pPdStruct);
    if (!info.bIsValid || !info.bExtractable || (info.nDataStart < 0)) return false;

    const qint64 nSize = getSize();
    XPE pe(getDevice(), isImage(), getModuleAddress());
    if (!pe.isValid(pPdStruct)) return false;
    const qint64 nInstallerEnd = siDataEnd(&pe, nSize);
    if ((nInstallerEnd < 36) || (nInstallerEnd < info.nDataStart + 36)) return false;
    qint64 nDataEnd = nInstallerEnd - 36;
    if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    UNPACK_CONTEXT *pContext = new UNPACK_CONTEXT;

    QByteArray baConfig;
    QByteArray baFooter = read_array_process(nInstallerEnd - 36, 36, pPdStruct);
    if ((baFooter.size() == 36) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        qint64 nOverlayOffset = (qint64)siRd64(reinterpret_cast<const quint8 *>(baFooter.constData()));
        qint64 nConfigEnd = qMin(info.nDataStart, nDataEnd);
        qint64 nConfigSize = nConfigEnd - nOverlayOffset;
        if ((nOverlayOffset >= 0) && (nConfigSize > 0) && (nConfigSize <= (16 << 20))) {
            baConfig = read_array_process(nOverlayOffset, nConfigSize, pPdStruct);
            if ((baConfig.size() != nConfigSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) baConfig.clear();
        }
    }

    QStringList listManifest;
    qint64 nDeclaredArchiveSize = -1;
    if (baConfig.isEmpty() || !siManifestDeclaration(baConfig, &listManifest, &nDeclaredArchiveSize)) {
        delete pContext;
        return false;
    }

    QList<FILE_ENTRY> listEntries;

    if (info.nMethod == 0) {
        // STORE: sequential {u32 idx; u32 size; u32 rsv; u64 FILETIME; u32 attr} + raw bytes.
        const qint64 nStoreSize = nDataEnd - info.nDataStart;
        if ((nDeclaredArchiveSize != 0) || (nStoreSize <= 0) || (nStoreSize > SI_MAX_ARCHIVE_SIZE) ||
            !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }

        QByteArray baData = read_array_process(info.nDataStart, nStoreSize, pPdStruct);
        if ((baData.size() != nStoreSize) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }

        const quint8 *p = (const quint8 *)baData.constData();
        const qint64 n = baData.size();
        qint64 pos = 0;
        int nRecord = 0;

        while (pos < n) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                delete pContext;
                return false;
            }

            if (n - pos < 24) {
                delete pContext;
                return false;
            }

            quint32 nNameIndex = siRd32(p + pos);
            quint32 nRecSize = siRd32(p + 4 + pos);
            qint64 nDataOff = pos + 24;
            if ((siRd32(p + pos + 8) != 0) || (nNameIndex > INT_MAX) ||
                (nRecSize > (quint32)SI_MAX_ARCHIVE_SIZE) || ((qint64)nRecSize > n - nDataOff) ||
                (listEntries.size() >= listManifest.size()) || (listEntries.size() >= SI_MAX_FILE_COUNT)) {
                delete pContext;
                return false;
            }

            FILE_ENTRY e;
            e.sName = siGenericName(nRecord++);
            e.nNameIndex = (qint32)nNameIndex;
            e.baData = QByteArray((const char *)p + nDataOff, (int)nRecSize);
            listEntries.append(e);
            pos = nDataOff + (qint64)nRecSize;
        }

        if (listEntries.isEmpty() || (pos != n)) {
            delete pContext;
            return false;
        }
    } else {
        // COMPRESSED: this is a complete CAB with only its "MSCF" signature
        // omitted.  The primary EXE holds it inline; split builds put the same
        // region in diskN.pak companion files.
        if ((nDeclaredArchiveSize <= 0) || (nDeclaredArchiveSize > SI_MAX_ARCHIVE_SIZE)) {
            delete pContext;
            return false;
        }

        QList<QByteArray> listRegions;
        const qint64 nPrimarySize = nDataEnd - info.nDataStart;
        if ((nPrimarySize < 0) || (nPrimarySize > SI_MAX_ARCHIVE_SIZE) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
            delete pContext;
            return false;
        }

        if (nPrimarySize > 0) {
            QByteArray baPrimaryRegion = read_array_process(info.nDataStart, nPrimarySize, pPdStruct);
            if (!XBinary::isPdStructNotCanceled(pPdStruct) || (baPrimaryRegion.size() != nPrimarySize) ||
                (nPrimarySize != nDeclaredArchiveSize) || !siLooksLikeCabRegion(baPrimaryRegion)) {
                delete pContext;
                return false;
            }
            listRegions.append(baPrimaryRegion);
        } else if (!siCompanionCabRegions(getDevice(), baConfig, nDeclaredArchiveSize, &listRegions, pPdStruct)) {
            delete pContext;
            return false;
        }

        if (listRegions.isEmpty()) {
            delete pContext;
            return false;
        }

        qint32 nRecord = 0;
        qint64 nTotalDecodedSize = 0;
        for (int nRegion = 0; nRegion < listRegions.size(); nRegion++) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                delete pContext;
                return false;
            }

            QList<quint32> listSizes;
            QList<qint32> listIndexes;
            QByteArray baCombined;
            if (!siDecodeCabRegion(listRegions.at(nRegion), &listSizes, &listIndexes, &baCombined, pPdStruct) ||
                (listSizes.size() != listIndexes.size())) {
                delete pContext;
                return false;
            }

            qint64 nOffset = 0;
            for (int i = 0; i < listSizes.size(); i++) {
                quint32 nFileSize = listSizes.at(i);
                if (!XBinary::isPdStructNotCanceled(pPdStruct) || (nOffset + nFileSize > baCombined.size()) ||
                    ((qint64)nFileSize > SI_MAX_ARCHIVE_SIZE - nTotalDecodedSize) ||
                    (nRecord >= listManifest.size()) || (nRecord >= SI_MAX_FILE_COUNT)) {
                    delete pContext;
                    return false;
                }

                FILE_ENTRY entry;
                entry.sName = siGenericName(nRecord++);
                entry.nNameIndex = listIndexes.at(i);
                entry.baData = baCombined.mid((int)nOffset, (int)nFileSize);
                listEntries.append(entry);
                nOffset += nFileSize;
                nTotalDecodedSize += nFileSize;
            }

            if (nOffset != baCombined.size()) {
                delete pContext;
                return false;
            }
        }
    }

    if (listEntries.isEmpty() || (listEntries.size() != listManifest.size()) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        delete pContext;
        return false;
    }

    if (!siAssignManifestNames(&listEntries, listManifest)) {
        delete pContext;
        return false;
    }
    pContext->listEntries = listEntries;

    pState->nNumberOfRecords = pContext->listEntries.size();
    pState->pContext = pContext;
    return true;
}

XBinary::ARCHIVERECORD XSmartInstall::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    ARCHIVERECORD result = {};
    if (!pState || !pState->pContext) return result;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return result;

    const FILE_ENTRY &e = pContext->listEntries.at(nIndex);
    result.nStreamSize = e.baData.size();
    result.mapProperties[FPART_PROP_ORIGINALNAME] = e.sName;
    result.mapProperties[FPART_PROP_UNCOMPRESSEDSIZE] = (qint64)e.baData.size();
    result.mapProperties[FPART_PROP_ISFOLDER] = false;
    return result;
}

bool XSmartInstall::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !pDevice || !pDevice->isWritable() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    qint32 nIndex = pState->nCurrentIndex;
    if ((nIndex < 0) || (nIndex >= pContext->listEntries.size())) return false;

    const QByteArray &baData = pContext->listEntries.at(nIndex).baData;
    qint64 nWritten = 0;
    pState->nCurrentOffset = 0;
    while (nWritten < baData.size()) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        qint64 nChunk = qMin<qint64>(1 << 20, baData.size() - nWritten);
        qint64 nResult = pDevice->write(baData.constData() + nWritten, nChunk);
        if ((nResult <= 0) || (nResult > nChunk)) return false;
        nWritten += nResult;
        pState->nCurrentOffset = nWritten;
    }
    return XBinary::isPdStructNotCanceled(pPdStruct);
}

bool XSmartInstall::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    if (!pState || !pState->pContext || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    UNPACK_CONTEXT *pContext = (UNPACK_CONTEXT *)pState->pContext;
    if ((pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pContext->listEntries.size() - 1)) return false;
    pState->nCurrentIndex++;
    pState->nCurrentOffset = 0;
    return true;
}

bool XSmartInstall::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    if (!pState) return false;
    if (pState->pContext) {
        delete (UNPACK_CONTEXT *)pState->pContext;
        pState->pContext = nullptr;
    }
    pState->nCurrentOffset = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    return true;
}
