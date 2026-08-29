/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xiscab.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QPointer>
#include <QSet>
#include <QTemporaryFile>
#include <QtEndian>

#include <limits>
#include <new>

#include "zlib.h"

namespace {
const quint32 IS_CAB_SIGNATURE = 0x28635349U;  // "ISc(" as little endian.
const qint64 IS_COMMON_HEADER_SIZE = 20;
const qint64 IS_VOLUME_HEADER_V5_SIZE = 40;
const qint64 IS_VOLUME_HEADER_V6_SIZE = 64;
const qint64 IS_MAX_CATALOG_SIZE = 256LL * 1024 * 1024;
const quint32 IS_MAX_RECORDS = 1000000U;
const qint32 IS_MAX_STRING_BYTES = 0x10000;
const quint16 IS_FILE_SPLIT = 0x0001;
const quint16 IS_FILE_OBFUSCATED = 0x0002;
const quint16 IS_FILE_COMPRESSED = 0x0004;
const quint16 IS_FILE_INVALID = 0x0008;
const quint8 IS_LINK_PREV = 0x01;

bool isRangeWithin(qint64 nSize, quint64 nOffset, quint64 nLength)
{
    if (nSize < 0) return false;
    const quint64 nTotal = static_cast<quint64>(nSize);
    return (nOffset <= nTotal) && (nLength <= (nTotal - nOffset));
}

bool isRangeWithin(const QByteArray &baData, quint64 nOffset, quint64 nLength)
{
    return isRangeWithin(baData.size(), nOffset, nLength);
}

quint16 readLE16(const QByteArray &baData, quint64 nOffset)
{
    return qFromLittleEndian<quint16>(reinterpret_cast<const uchar *>(baData.constData() + nOffset));
}

quint32 readLE32(const QByteArray &baData, quint64 nOffset)
{
    return qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(baData.constData() + nOffset));
}

quint64 readLE64(const QByteArray &baData, quint64 nOffset)
{
    return qFromLittleEndian<quint64>(reinterpret_cast<const uchar *>(baData.constData() + nOffset));
}

qint32 majorVersion(quint32 nVersion)
{
    const quint8 nFamily = static_cast<quint8>(nVersion >> 24);
    if (nFamily == 1) return static_cast<qint32>((nVersion >> 12) & 0x0f);
    if ((nFamily == 2) || (nFamily == 4)) {
        const quint32 nValue = nVersion & 0xffffU;
        return nValue ? static_cast<qint32>(nValue / 100U) : 0;
    }
    return 0;
}

QString mediaPrefixFromPath(const QString &sPath)
{
    if (sPath.isEmpty()) return QString();
    const QFileInfo fileInfo(sPath);
    const QString sBaseName = fileInfo.completeBaseName();
    qint32 nCut = sBaseName.size();
    while ((nCut > 0) && sBaseName.at(nCut - 1).isDigit()) --nCut;
    if (nCut <= 0) return QString();
    return QDir(fileInfo.absolutePath()).filePath(sBaseName.left(nCut));
}

QString resolveCaseInsensitivePath(const QString &sCandidate)
{
    const QFileInfo exactInfo(sCandidate);
    if (exactInfo.exists() && exactInfo.isFile()) return exactInfo.absoluteFilePath();

    QDir directory(exactInfo.absolutePath());
    const QString sWanted = exactInfo.fileName().toCaseFolded();
    const QFileInfoList listFiles = directory.entryInfoList(QDir::Files | QDir::Readable | QDir::NoDotAndDotDot, QDir::Name);
    for (const QFileInfo &fileInfo : listFiles) {
        if (fileInfo.fileName().toCaseFolded() == sWanted) return fileInfo.absoluteFilePath();
    }
    return QString();
}

QString mediaPath(const QString &sPrefix, quint32 nVolume, const QString &sSuffix)
{
    if (sPrefix.isEmpty() || !nVolume) return QString();
    return resolveCaseInsensitivePath(QStringLiteral("%1%2.%3").arg(sPrefix).arg(nVolume).arg(sSuffix));
}

bool readFileBounded(const QString &sFileName, QByteArray *pData)
{
    if (!pData || sFileName.isEmpty()) return false;
    pData->clear();
    QFile file(sFileName);
    if (!file.open(QIODevice::ReadOnly) || file.isSequential()) return false;
    const qint64 nSize = file.size();
    if ((nSize < IS_COMMON_HEADER_SIZE) || (nSize > IS_MAX_CATALOG_SIZE) || (nSize > (std::numeric_limits<qint32>::max)())) {
        return false;
    }
    *pData = file.read(nSize);
    return pData->size() == nSize;
}

QString readCabString(const QByteArray &baData, quint64 nOffset, qint32 nMajorVersion)
{
    if (!isRangeWithin(baData, nOffset, 1)) return QString();
    if (nMajorVersion >= 17) {
        QString sResult;
        for (qint32 i = 0; i < (IS_MAX_STRING_BYTES / 2); ++i) {
            const quint64 nCharacterOffset = nOffset + (quint64)i * 2U;
            if (!isRangeWithin(baData, nCharacterOffset, 2)) return QString();
            const quint16 nCharacter = readLE16(baData, nCharacterOffset);
            if (!nCharacter) return sResult;
            sResult.append(QChar(nCharacter));
        }
        return QString();
    }

    qint32 nLength = 0;
    while (nLength < IS_MAX_STRING_BYTES) {
        if (!isRangeWithin(baData, nOffset + (quint64)nLength, 1)) return QString();
        if (!baData.at(static_cast<qint32>(nOffset) + nLength)) return QString::fromLatin1(baData.constData() + nOffset, nLength);
        ++nLength;
    }
    return QString();
}

QString safeArchiveName(QString sDirectory, QString sFileName, qint32 nIndex)
{
    sDirectory.replace(QLatin1Char('\\'), QLatin1Char('/'));
    sFileName.replace(QLatin1Char('\\'), QLatin1Char('/'));
    QString sCombined = sDirectory.isEmpty() ? sFileName : (sDirectory + QLatin1Char('/') + sFileName);
    sCombined = QDir::cleanPath(sCombined);

    bool bSafe = !sCombined.isEmpty() && !sCombined.startsWith(QLatin1Char('/')) && !sCombined.startsWith(QLatin1String("../")) && (sCombined != QLatin1String("..")) &&
                 !sCombined.contains(QLatin1String("/../")) && !sCombined.contains(QLatin1Char(':'));
    const QStringList listParts = sCombined.split(QLatin1Char('/'), Qt::KeepEmptyParts);
    for (const QString &sPart : listParts) {
        if (sPart.isEmpty() || (sPart == QLatin1String(".")) || (sPart == QLatin1String(".."))) {
            bSafe = false;
            break;
        }
    }
    if (bSafe) {
        const QString sFixed = XBinary::fixFileName(sCombined);
        if (!sFixed.isEmpty()) return sFixed;
    }
    return QStringLiteral("file_%1.bin").arg(nIndex, 6, 10, QLatin1Char('0'));
}

QString uniqueArchiveName(const QString &sName, QSet<QString> *pNames)
{
    if (!pNames) return sName;
    QString sResult = sName;
    QString sKey = sResult.toCaseFolded();
    qint32 nSuffix = 2;
    while (pNames->contains(sKey) && (nSuffix <= 1000000)) {
        const qint32 nSlash = sName.lastIndexOf(QLatin1Char('/'));
        const qint32 nDot = sName.lastIndexOf(QLatin1Char('.'));
        const bool bHasExtension = nDot > nSlash + 1;
        const QString sTag = QStringLiteral("_%1").arg(nSuffix++);
        sResult = bHasExtension ? sName.left(nDot) + sTag + sName.mid(nDot) : sName + sTag;
        sKey = sResult.toCaseFolded();
    }
    pNames->insert(sKey);
    return sResult;
}

struct VOLUME_HEADER {
    quint64 nDataOffset = 0;
    quint32 nFirstFileIndex = 0;
    quint32 nLastFileIndex = 0;
    quint64 nFirstFileOffset = 0;
    quint64 nFirstExpandedSize = 0;
    quint64 nFirstCompressedSize = 0;
    quint64 nLastFileOffset = 0;
    quint64 nLastExpandedSize = 0;
    quint64 nLastCompressedSize = 0;
};

bool parseVolumeFile(const QString &sPath, qint32 nMajorVersion, VOLUME_HEADER *pHeader, qint64 *pnFileSize)
{
    if (!pHeader || !pnFileSize || sPath.isEmpty()) return false;
    *pHeader = VOLUME_HEADER();
    *pnFileSize = -1;
    QFile file(sPath);
    if (!file.open(QIODevice::ReadOnly) || file.isSequential()) return false;
    *pnFileSize = file.size();
    const qint64 nHeaderSize = IS_COMMON_HEADER_SIZE + ((nMajorVersion <= 5) ? IS_VOLUME_HEADER_V5_SIZE : IS_VOLUME_HEADER_V6_SIZE);
    if (*pnFileSize < nHeaderSize) return false;
    const QByteArray baHeader = file.read(nHeaderSize);
    if ((baHeader.size() != nHeaderSize) || (readLE32(baHeader, 0) != IS_CAB_SIGNATURE)) {
        return false;
    }
    if (majorVersion(readLE32(baHeader, 4)) != nMajorVersion) return false;

    quint64 nOffset = IS_COMMON_HEADER_SIZE;
    if (nMajorVersion <= 5) {
        pHeader->nDataOffset = readLE32(baHeader, nOffset);
        nOffset += 8;
        pHeader->nFirstFileIndex = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nLastFileIndex = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nFirstFileOffset = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nFirstExpandedSize = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nFirstCompressedSize = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nLastFileOffset = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nLastExpandedSize = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nLastCompressedSize = readLE32(baHeader, nOffset);
        if (!pHeader->nLastFileOffset) pHeader->nLastFileOffset = 0x7fffffffU;
    } else {
        pHeader->nDataOffset = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nFirstFileIndex = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nLastFileIndex = readLE32(baHeader, nOffset);
        nOffset += 4;
        pHeader->nFirstFileOffset = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nFirstExpandedSize = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nFirstCompressedSize = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nLastFileOffset = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nLastExpandedSize = readLE64(baHeader, nOffset);
        nOffset += 8;
        pHeader->nLastCompressedSize = readLE64(baHeader, nOffset);
    }
    return (pHeader->nDataOffset <= static_cast<quint64>(*pnFileSize)) && (pHeader->nFirstFileIndex <= pHeader->nLastFileIndex);
}

struct INPUT_SEGMENT {
    QString sPath;
    quint64 nOffset = 0;
    quint64 nSize = 0;
};

bool buildSegments(const QString &sPrefix, qint32 nMajorVersion, quint16 nFlags, quint64 nExpandedSize, quint64 nCompressedSize, quint64 nDataOffset,
                   quint16 nEntryVolume, qint32 nEntryIndex, qint32 nEntryCount, QList<INPUT_SEGMENT> *pSegments)
{
    if (!pSegments || sPrefix.isEmpty() || (nEntryIndex < 0) || (nEntryCount <= nEntryIndex)) {
        return false;
    }
    pSegments->clear();
    const bool bCompressed = nFlags & IS_FILE_COMPRESSED;
    bool bSplit = nFlags & IS_FILE_SPLIT;
    quint64 nRemaining = bCompressed ? nCompressedSize : nExpandedSize;
    if (!nRemaining) return true;
    quint32 nVolume = (nMajorVersion <= 5) ? 1U : qMax<quint32>(1U, nEntryVolume);

    for (quint32 nAttempt = 0; nAttempt < 10000U; ++nAttempt, ++nVolume) {
        const QString sPath = mediaPath(sPrefix, nVolume, QStringLiteral("cab"));
        if (sPath.isEmpty()) return false;
        VOLUME_HEADER volume = {};
        qint64 nFileSize = -1;
        if (!parseVolumeFile(sPath, nMajorVersion, &volume, &nFileSize)) return false;

        if ((nMajorVersion <= 5) && (static_cast<quint32>(nEntryIndex) > volume.nLastFileIndex)) {
            continue;
        }

        // InstallShield 5 does not reliably publish FILE_SPLIT.  Unshield
        // infers it from the boundary member sizes in each volume.
        if (!bSplit && (nMajorVersion == 5)) {
            if ((nEntryIndex + 1 < nEntryCount) && (static_cast<quint32>(nEntryIndex) == volume.nLastFileIndex) && (volume.nLastCompressedSize != nCompressedSize)) {
                bSplit = true;
            } else if ((nEntryIndex > 0) && (static_cast<quint32>(nEntryIndex) == volume.nFirstFileIndex) && (volume.nFirstCompressedSize != nCompressedSize)) {
                bSplit = true;
            }
        }

        INPUT_SEGMENT segment;
        segment.sPath = sPath;
        if (!bSplit) {
            segment.nOffset = nDataOffset;
            segment.nSize = nRemaining;
        } else if ((static_cast<quint32>(nEntryIndex) == volume.nLastFileIndex) && (volume.nLastFileOffset != 0x7fffffffU)) {
            segment.nOffset = volume.nLastFileOffset;
            segment.nSize = bCompressed ? volume.nLastCompressedSize : volume.nLastExpandedSize;
        } else if (static_cast<quint32>(nEntryIndex) == volume.nFirstFileIndex) {
            segment.nOffset = volume.nFirstFileOffset;
            segment.nSize = bCompressed ? volume.nFirstCompressedSize : volume.nFirstExpandedSize;
        } else {
            return false;
        }

        if (segment.nSize > nRemaining) segment.nSize = nRemaining;
        if ((nRemaining && !segment.nSize) || (segment.nOffset < volume.nDataOffset) || !isRangeWithin(nFileSize, segment.nOffset, segment.nSize)) {
            return false;
        }
        pSegments->append(segment);
        nRemaining -= segment.nSize;
        if (!nRemaining) return true;
        if (!bSplit) return false;
    }
    return false;
}

class SegmentReader {
public:
    explicit SegmentReader(const QList<INPUT_SEGMENT> &listSegments) : m_listSegments(listSegments), m_nIndex(0), m_nPosition(0)
    {
    }

    bool readExact(char *pData, qint64 nSize)
    {
        if (!pData || (nSize < 0)) return false;
        qint64 nDone = 0;
        while (nDone < nSize) {
            if (m_nIndex >= m_listSegments.count()) return false;
            const INPUT_SEGMENT &segment = m_listSegments.at(m_nIndex);
            if (m_file.fileName() != segment.sPath) {
                m_file.close();
                m_file.setFileName(segment.sPath);
                if (!m_file.open(QIODevice::ReadOnly) || !m_file.seek(static_cast<qint64>(segment.nOffset))) {
                    return false;
                }
                m_nPosition = 0;
            }
            const quint64 nAvailable = segment.nSize - m_nPosition;
            if (!nAvailable) {
                m_file.close();
                ++m_nIndex;
                m_nPosition = 0;
                continue;
            }
            const qint64 nRequest =
                qMin<qint64>(nSize - nDone, static_cast<qint64>(qMin<quint64>(nAvailable, static_cast<quint64>((std::numeric_limits<qint64>::max)()))));
            const qint64 nRead = m_file.read(pData + nDone, nRequest);
            if (nRead != nRequest) return false;
            nDone += nRead;
            m_nPosition += static_cast<quint64>(nRead);
        }
        return true;
    }

private:
    QList<INPUT_SEGMENT> m_listSegments;
    qint32 m_nIndex;
    quint64 m_nPosition;
    QFile m_file;
};

quint8 rotateRight2(quint8 nValue)
{
    return static_cast<quint8>((nValue >> 2) | (nValue << 6));
}

void deobfuscate(char *pData, qint64 nSize, quint64 *pnSeed)
{
    if (!pData || !pnSeed || (nSize <= 0)) return;
    quint64 nSeed = *pnSeed;
    for (qint64 i = 0; i < nSize; ++i, ++nSeed) {
        const quint8 nValue = static_cast<quint8>(pData[i]);
        pData[i] = static_cast<char>(rotateRight2(static_cast<quint8>(nValue ^ 0xd5U)) - static_cast<quint8>(nSeed % 0x47U));
    }
    *pnSeed = nSeed;
}

bool writeAll(QIODevice *pDevice, const char *pData, qint64 nSize)
{
    if (!pDevice || !pData || (nSize < 0)) return false;
    qint64 nDone = 0;
    while (nDone < nSize) {
        const qint64 nWritten = pDevice->write(pData + nDone, nSize - nDone);
        if (nWritten <= 0) return false;
        nDone += nWritten;
    }
    return true;
}

bool inflateInstallShieldBlock(const QByteArray &baInput, QByteArray *pOutput)
{
    if (!pOutput || baInput.isEmpty()) return false;
    QByteArray baPadded = baInput;
    baPadded.append('\0');
    QByteArray baResult(64 * 1024, '\0');

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = reinterpret_cast<Bytef *>(baPadded.data());
    stream.avail_in = static_cast<uInt>(baPadded.size());
    stream.next_out = reinterpret_cast<Bytef *>(baResult.data());
    stream.avail_out = static_cast<uInt>(baResult.size());
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return false;
    const int nResult = inflate(&stream, Z_FINISH);
    const bool bResult = (nResult == Z_STREAM_END) && (stream.total_out <= (uLong)baResult.size());
    const qint32 nOutputSize = static_cast<qint32>(stream.total_out);
    inflateEnd(&stream);
    if (!bResult) return false;
    baResult.resize(nOutputSize);
    *pOutput = baResult;
    return true;
}
}  // namespace

XISCab::XISCab(QIODevice *pDevice) : XArchive(pDevice)
{
}

bool XISCab::_readCommonHeader(QIODevice *pDevice, COMMON_HEADER *pHeader, PDSTRUCT *pPdStruct) const
{
    if (pHeader) *pHeader = COMMON_HEADER();
    if (!pDevice || !pHeader || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;

    QPointer<XISCab> guardedThis(const_cast<XISCab *>(this));
    QPointer<QIODevice> guardedDevice(pDevice);
    const bool bOpen = guardedDevice->isOpen();
    if (!guardedThis || !guardedDevice || !bOpen) return false;
    const bool bReadable = guardedDevice->isReadable();
    if (!guardedThis || !guardedDevice || !bReadable) return false;
    const bool bSequential = guardedDevice->isSequential();
    if (!guardedThis || !guardedDevice || bSequential) return false;

    const qint64 nSavedPosition = guardedDevice->pos();
    if (!guardedThis || !guardedDevice || (nSavedPosition < 0)) return false;
    const qint64 nSize = guardedDevice->size();
    if (!guardedThis || !guardedDevice || (nSize < IS_COMMON_HEADER_SIZE)) return false;
    const qint64 nReadSize = qMin<qint64>(nSize, IS_COMMON_HEADER_SIZE + IS_VOLUME_HEADER_V6_SIZE);
    const bool bSeeked = guardedDevice->seek(0);
    if (!guardedThis || !guardedDevice || !bSeeked) return false;
    const QByteArray baHeader = guardedDevice->read(nReadSize);
    if (!guardedThis || !guardedDevice) return false;
    const bool bRestored = guardedDevice->seek(nSavedPosition);
    if (!guardedThis || !guardedDevice || !bRestored || (baHeader.size() != nReadSize) || (readLE32(baHeader, 0) != IS_CAB_SIGNATURE)) {
        return false;
    }

    pHeader->nVersion = readLE32(baHeader, 4);
    pHeader->nVolumeInfo = readLE32(baHeader, 8);
    pHeader->nDescriptorOffset = readLE32(baHeader, 12);
    pHeader->nDescriptorSize = readLE32(baHeader, 16);
    pHeader->nMajorVersion = majorVersion(pHeader->nVersion);
    if (pHeader->nMajorVersion > 32) return false;
    if (pHeader->nDescriptorSize) {
        return (pHeader->nDescriptorOffset >= IS_COMMON_HEADER_SIZE) && isRangeWithin(nSize, pHeader->nDescriptorOffset, 0x30);
    }

    const qint64 nVolumeHeaderSize = (pHeader->nMajorVersion <= 5) ? IS_VOLUME_HEADER_V5_SIZE : IS_VOLUME_HEADER_V6_SIZE;
    if ((nSize < (IS_COMMON_HEADER_SIZE + nVolumeHeaderSize)) || (baHeader.size() < (IS_COMMON_HEADER_SIZE + nVolumeHeaderSize))) {
        return false;
    }
    const quint64 nDataOffset = (pHeader->nMajorVersion <= 5) ? readLE32(baHeader, IS_COMMON_HEADER_SIZE) : readLE64(baHeader, IS_COMMON_HEADER_SIZE);
    return nDataOffset <= static_cast<quint64>(nSize);
}

bool XISCab::isValid(PDSTRUCT *pPdStruct)
{
    COMMON_HEADER common;
    return _readCommonHeader(getDevice(), &common, pPdStruct);
}

bool XISCab::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XISCab archive(pDevice);
    return archive.isValid(pPdStruct);
}

XISCab::INTERNAL_INFO XISCab::_getInternalInfo(PDSTRUCT *pPdStruct)
{
    INTERNAL_INFO result;
    COMMON_HEADER common;
    result.bIsValid = _readCommonHeader(getDevice(), &common, pPdStruct);
    if (result.bIsValid) {
        result.nMajorVersion = common.nMajorVersion;
        result.bHasCabDescriptor = common.nDescriptorSize != 0;
        result.nVolumeNumber = common.nVolumeInfo;
    }
    return result;
}

bool XISCab::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    QPointer<XISCab> guardedThis(this);
    if (!isInternalInfoHandled()) {
        if (!XArchive::handleInternalInfo(pPdStruct) || !guardedThis) return false;
        XArchive::INTERNAL_INFO *pBase = static_cast<XArchive::INTERNAL_INFO *>(XArchive::getInternalInfo(pPdStruct));
        if (!guardedThis || !pBase) return false;
        static_cast<XArchive::INTERNAL_INFO &>(m_internalInfo) = *pBase;
        const INTERNAL_INFO detected = _getInternalInfo(pPdStruct);
        if (!guardedThis) return false;
        m_internalInfo.bIsValid = detected.bIsValid;
        m_internalInfo.nMajorVersion = detected.nMajorVersion;
        m_internalInfo.bHasCabDescriptor = detected.bHasCabDescriptor;
        m_internalInfo.nVolumeNumber = detected.nVolumeNumber;
    }
    return true;
}

void *XISCab::getInternalInfo(PDSTRUCT *pPdStruct)
{
    return handleInternalInfo(pPdStruct) ? &m_internalInfo : nullptr;
}

void XISCab::setInternalInfo(void *pInternalInfo)
{
    if (pInternalInfo) {
        m_internalInfo = *static_cast<INTERNAL_INFO *>(pInternalInfo);
        XArchive::setInternalInfo(static_cast<XArchive::INTERNAL_INFO *>(&m_internalInfo));
    } else {
        m_internalInfo = INTERNAL_INFO();
        XArchive::setInternalInfo(nullptr);
    }
}

XBinary::FT XISCab::getFileType()
{
    return FT_ISCAB;
}

XBinary::MODE XISCab::getMode()
{
    return MODE_32;
}

qint32 XISCab::getType()
{
    return TYPE_ARCHIVE;
}

XBinary::ENDIAN XISCab::getEndian()
{
    return ENDIAN_LITTLE;
}

QString XISCab::getArch()
{
    return QString();
}

QString XISCab::getFileFormatExt()
{
    return QStringLiteral("cab");
}

QString XISCab::getFileFormatExtsString()
{
    return QStringLiteral("InstallShield Cabinet (*.cab *.hdr)");
}

QString XISCab::getMIMEString()
{
    return QStringLiteral("application/x-installshield-cabinet");
}

qint64 XISCab::getFileFormatSize(PDSTRUCT *pPdStruct)
{
    return isValid(pPdStruct) ? getSize() : 0;
}

XBinary::OSNAME XISCab::getOsName()
{
    return OSNAME_WINDOWS;
}

QString XISCab::getVersion()
{
    INTERNAL_INFO *pInfo = static_cast<INTERNAL_INFO *>(getInternalInfo(nullptr));
    return (pInfo && pInfo->bIsValid && pInfo->nMajorVersion) ? QString::number(pInfo->nMajorVersion) : QString();
}

QList<QString> XISCab::getSearchSignatures()
{
    return QList<QString>() << QStringLiteral("'ISc('");
}

XBinary *XISCab::createInstance(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress)
{
    Q_UNUSED(bIsImage)
    Q_UNUSED(nModuleAddress)
    return new XISCab(pDevice);
}

QMap<XBinary::UNPACK_PROP, QVariant> XISCab::getDefaultUnpackProperties()
{
    return XArchive::getDefaultUnpackProperties();
}

bool XISCab::_loadCatalog(QByteArray *pCatalog, QString *pMediaPrefix, QString *pSourcePath, COMMON_HEADER *pHeader, PDSTRUCT *pPdStruct) const
{
    if (!pCatalog || !pMediaPrefix || !pSourcePath || !pHeader) return false;
    pCatalog->clear();
    pMediaPrefix->clear();
    pSourcePath->clear();
    *pHeader = COMMON_HEADER();

    QPointer<XISCab> guardedThis(const_cast<XISCab *>(this));
    QPointer<QIODevice> guardedDevice(guardedThis ? guardedThis->getDevice() : nullptr);
    if (!guardedThis || !guardedDevice) return false;
    COMMON_HEADER sourceHeader;
    const bool bHeaderRead = _readCommonHeader(guardedDevice.data(), &sourceHeader, pPdStruct);
    if (!guardedThis || !guardedDevice || !bHeaderRead) return false;

    QFile *pSourceFile = dynamic_cast<QFile *>(guardedDevice.data());
    const QString sSourcePath = pSourceFile ? QFileInfo(pSourceFile->fileName()).absoluteFilePath() : QString();
    const QString sPrefix = mediaPrefixFromPath(sSourcePath);

    if (sourceHeader.nDescriptorSize) {
        const qint64 nSize = guardedDevice->size();
        if (!guardedThis || !guardedDevice || (nSize < IS_COMMON_HEADER_SIZE) || (nSize > IS_MAX_CATALOG_SIZE) || (nSize > (std::numeric_limits<qint32>::max)())) {
            return false;
        }
        const qint64 nSavedPosition = guardedDevice->pos();
        if (!guardedThis || !guardedDevice || (nSavedPosition < 0)) return false;
        const bool bSeeked = guardedDevice->seek(0);
        if (!guardedThis || !guardedDevice || !bSeeked) return false;
        *pCatalog = guardedDevice->read(nSize);
        if (!guardedThis || !guardedDevice) {
            pCatalog->clear();
            return false;
        }
        const bool bRestored = guardedDevice->seek(nSavedPosition);
        if (!guardedThis || !guardedDevice || !bRestored || (pCatalog->size() != nSize)) {
            pCatalog->clear();
            return false;
        }
        *pHeader = sourceHeader;
        *pMediaPrefix = sPrefix;
        *pSourcePath = sSourcePath;
        return true;
    }

    if (sPrefix.isEmpty()) {
        XBinary::setPdStructErrorString(pPdStruct, tr("InstallShield cabinet catalog is not embedded; DATA1.HDR is required"));
        return false;
    }

    const QStringList listCandidates = QStringList() << mediaPath(sPrefix, 1, QStringLiteral("hdr")) << mediaPath(sPrefix, 1, QStringLiteral("cab"));
    for (const QString &sCandidate : listCandidates) {
        if (sCandidate.isEmpty()) continue;
        QByteArray baCandidate;
        if (!readFileBounded(sCandidate, &baCandidate)) continue;
        if (!isRangeWithin(baCandidate, 0, IS_COMMON_HEADER_SIZE) || (readLE32(baCandidate, 0) != IS_CAB_SIGNATURE)) {
            continue;
        }
        COMMON_HEADER candidate;
        candidate.nVersion = readLE32(baCandidate, 4);
        candidate.nVolumeInfo = readLE32(baCandidate, 8);
        candidate.nDescriptorOffset = readLE32(baCandidate, 12);
        candidate.nDescriptorSize = readLE32(baCandidate, 16);
        candidate.nMajorVersion = majorVersion(candidate.nVersion);
        if (!candidate.nDescriptorSize || (candidate.nMajorVersion != sourceHeader.nMajorVersion) || (candidate.nMajorVersion > 32) ||
            (candidate.nDescriptorOffset < IS_COMMON_HEADER_SIZE) || !isRangeWithin(baCandidate, candidate.nDescriptorOffset, 0x30)) {
            continue;
        }
        *pCatalog = baCandidate;
        *pHeader = candidate;
        *pMediaPrefix = sPrefix;
        *pSourcePath = sSourcePath;
        return true;
    }

    XBinary::setPdStructErrorString(pPdStruct, tr("InstallShield cabinet catalog was not found; DATA1.HDR is required"));
    return false;
}

bool XISCab::_parseCatalog(const QByteArray &baCatalog, const COMMON_HEADER &common, QList<FILE_ENTRY> *pEntries, QList<qint32> *pVisibleIndices,
                           PDSTRUCT *pPdStruct) const
{
    if (pEntries) pEntries->clear();
    if (pVisibleIndices) pVisibleIndices->clear();
    if (!pEntries || !pVisibleIndices || !common.nDescriptorSize || !XBinary::isPdStructNotCanceled(pPdStruct) ||
        !isRangeWithin(baCatalog, common.nDescriptorOffset, 0x30)) {
        return false;
    }

    const quint64 nDescriptor = common.nDescriptorOffset;
    const quint32 nFileTableOffset = readLE32(baCatalog, nDescriptor + 0x0c);
    const quint32 nFileTableSize = readLE32(baCatalog, nDescriptor + 0x14);
    const quint32 nFileTableSize2 = readLE32(baCatalog, nDescriptor + 0x18);
    const quint32 nDirectoryCount = readLE32(baCatalog, nDescriptor + 0x1c);
    const quint32 nFileCount = readLE32(baCatalog, nDescriptor + 0x28);
    const quint32 nFileTableOffset2 = readLE32(baCatalog, nDescriptor + 0x2c);
    if ((nDirectoryCount > IS_MAX_RECORDS) || (nFileCount > IS_MAX_RECORDS) || (nDirectoryCount > IS_MAX_RECORDS - nFileCount) || (nFileTableSize != nFileTableSize2)) {
        return false;
    }

    const quint64 nTable = nDescriptor + nFileTableOffset;
    const quint64 nOffsetCount = static_cast<quint64>(nDirectoryCount) + nFileCount;
    if (!isRangeWithin(baCatalog, nTable, nOffsetCount * 4U) || (nFileTableSize && !isRangeWithin(baCatalog, nTable, nFileTableSize))) {
        return false;
    }

    QList<QString> listDirectories;
    listDirectories.reserve(static_cast<qint32>(nDirectoryCount));
    for (quint32 i = 0; i < nDirectoryCount; ++i) {
        const quint32 nStringOffset = readLE32(baCatalog, nTable + i * 4U);
        if (!isRangeWithin(baCatalog, nTable + nStringOffset, 1)) return false;
        listDirectories.append(readCabString(baCatalog, nTable + nStringOffset, common.nMajorVersion));
    }

    pEntries->reserve(static_cast<qint32>(nFileCount));
    QSet<QString> setNames;
    for (quint32 i = 0; i < nFileCount; ++i) {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) return false;
        FILE_ENTRY entry;
        quint64 nEntryOffset = 0;
        quint64 nRequiredSize = 0;
        if (common.nMajorVersion <= 5) {
            const quint32 nRelative = readLE32(baCatalog, nTable + static_cast<quint64>(nDirectoryCount + i) * 4U);
            nEntryOffset = nTable + nRelative;
            nRequiredSize = (common.nMajorVersion == 5) ? 0x3a : 0x2a;
            if (!isRangeWithin(baCatalog, nEntryOffset, nRequiredSize)) return false;
            entry.nNameOffset = readLE32(baCatalog, nEntryOffset);
            entry.nDirectoryIndex = readLE16(baCatalog, nEntryOffset + 4);
            entry.nFlags = readLE16(baCatalog, nEntryOffset + 8);
            entry.nExpandedSize = readLE32(baCatalog, nEntryOffset + 10);
            entry.nCompressedSize = readLE32(baCatalog, nEntryOffset + 14);
            entry.nDataOffset = readLE32(baCatalog, nEntryOffset + 38);
            if (common.nMajorVersion == 5) entry.baMD5 = baCatalog.mid(static_cast<qint32>(nEntryOffset + 42), 16);
            entry.nVolume = 1;
        } else {
            nEntryOffset = nTable + nFileTableOffset2 + static_cast<quint64>(i) * 0x57U;
            nRequiredSize = 0x57;
            if (!isRangeWithin(baCatalog, nEntryOffset, nRequiredSize)) return false;
            entry.nFlags = readLE16(baCatalog, nEntryOffset);
            entry.nExpandedSize = readLE64(baCatalog, nEntryOffset + 2);
            entry.nCompressedSize = readLE64(baCatalog, nEntryOffset + 10);
            entry.nDataOffset = readLE64(baCatalog, nEntryOffset + 18);
            entry.baMD5 = baCatalog.mid(static_cast<qint32>(nEntryOffset + 26), 16);
            entry.nNameOffset = readLE32(baCatalog, nEntryOffset + 58);
            entry.nDirectoryIndex = readLE16(baCatalog, nEntryOffset + 62);
            entry.nLinkPrevious = readLE32(baCatalog, nEntryOffset + 76);
            entry.nLinkNext = readLE32(baCatalog, nEntryOffset + 80);
            entry.nLinkFlags = static_cast<quint8>(baCatalog.at(static_cast<qint32>(nEntryOffset + 84)));
            entry.nVolume = readLE16(baCatalog, nEntryOffset + 85);
        }

        const bool bSizeValid = (entry.nExpandedSize <= static_cast<quint64>((std::numeric_limits<qint64>::max)())) &&
                                (entry.nCompressedSize <= static_cast<quint64>((std::numeric_limits<qint64>::max)())) &&
                                (entry.nDataOffset <= static_cast<quint64>((std::numeric_limits<qint64>::max)()));
        const QString sFile = entry.nNameOffset ? readCabString(baCatalog, nTable + entry.nNameOffset, common.nMajorVersion) : QString();
        const bool bDirectoryValid = entry.nDirectoryIndex < listDirectories.count();
        const QString sDirectory = bDirectoryValid ? listDirectories.at(entry.nDirectoryIndex) : QString();
        entry.sFileName = uniqueArchiveName(safeArchiveName(sDirectory, sFile, static_cast<qint32>(i)), &setNames);
        entry.bVisible = bSizeValid && !(entry.nFlags & IS_FILE_INVALID) && entry.nNameOffset && !sFile.isEmpty() && bDirectoryValid && entry.nDataOffset;
        pEntries->append(entry);
        if (entry.bVisible) pVisibleIndices->append(static_cast<qint32>(i));
    }
    return true;
}

bool XISCab::initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct)
{
    QPointer<XISCab> guardedThis(this);
    if (m_bUnpackOperationInProgress) return false;
    UNPACK_OPERATION_GUARD operationGuard(&m_bUnpackOperationInProgress);
    if (!operationGuard.isAcquired() || !pState) return false;
    if ((pState->pContext || !pState->baUnpackSourceToken.isEmpty()) && !ownsUnpackSource(pState)) {
        return false;
    }

    UNPACK_CONTEXT *pOldContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    releaseUnpackSource(pState);
    pState->pContext = nullptr;
    *pState = UNPACK_STATE();
    delete pOldContext;
    if (!guardedThis || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    if (!bindUnpackSource(pState, pPdStruct) || !guardedThis) return false;

    UNPACK_CONTEXT *pContext = new (std::nothrow) UNPACK_CONTEXT;
    if (!pContext) {
        releaseUnpackSource(pState);
        return false;
    }
    bool bResult = _loadCatalog(&pContext->baCatalog, &pContext->sMediaPrefix, &pContext->sSourcePath, &pContext->common, pPdStruct);
    bResult = bResult && guardedThis && _parseCatalog(pContext->baCatalog, pContext->common, &pContext->listEntries, &pContext->listVisibleIndices, pPdStruct);
    if (!guardedThis) {
        delete pContext;
        *pState = UNPACK_STATE();
        return false;
    }
    if (!bResult || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        delete pContext;
        releaseUnpackSource(pState);
        *pState = UNPACK_STATE();
        return false;
    }

    const qint64 nTotalSize = getSize();
    if (!guardedThis || (nTotalSize < 0)) {
        delete pContext;
        if (guardedThis) releaseUnpackSource(pState);
        *pState = UNPACK_STATE();
        return false;
    }

    pState->pContext = pContext;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = pContext->listVisibleIndices.count();
    pState->nCurrentOffset = 0;
    pState->nTotalSize = nTotalSize;
    pState->mapUnpackProperties = mapProperties;
    if (!validateAndFinalizeUnpackSource(pState, pContext, pPdStruct)) {
        if (!guardedThis) {
            delete pContext;
            *pState = UNPACK_STATE();
            return false;
        }
        pState->pContext = nullptr;
        releaseUnpackSource(pState);
        delete pContext;
        *pState = UNPACK_STATE();
        return false;
    }
    return true;
}

XBinary::ARCHIVERECORD XISCab::infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QPointer<XISCab> guardedThis(this);
    UNPACK_OPERATION_GUARD operationGuard(&m_bUnpackOperationInProgress, &m_bNestedUnpackInfoAuthorized);
    if (!operationGuard.isAllowed() || !pState || !pState->pContext) {
        return ARCHIVERECORD();
    }
    const bool bSourceCurrent = isUnpackSourceCurrent(pState, pPdStruct);
    if (!guardedThis || !bSourceCurrent || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return ARCHIVERECORD();
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if ((pState->nNumberOfRecords != pContext->listVisibleIndices.count()) || (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return ARCHIVERECORD();
    }
    const qint32 nEntryIndex = pContext->listVisibleIndices.at(pState->nCurrentIndex);
    if ((nEntryIndex < 0) || (nEntryIndex >= pContext->listEntries.count())) return ARCHIVERECORD();
    const FILE_ENTRY entry = pContext->listEntries.at(nEntryIndex);

    ARCHIVERECORD result = {};
    result.nStreamOffset = static_cast<qint64>(entry.nDataOffset);
    result.nStreamSize = static_cast<qint64>(entry.nCompressedSize);
    result.mapProperties.insert(FPART_PROP_ORIGINALNAME, entry.sFileName);
    result.mapProperties.insert(FPART_PROP_UNCOMPRESSEDSIZE, static_cast<qint64>(entry.nExpandedSize));
    result.mapProperties.insert(FPART_PROP_COMPRESSEDSIZE, static_cast<qint64>(entry.nCompressedSize));
    result.mapProperties.insert(FPART_PROP_ENCRYPTED, false);
    result.mapProperties.insert(FPART_PROP_FILEMODE, (quint32)0644);
    result.mapProperties.insert(FPART_PROP_ISFOLDER, false);
    if (entry.baMD5.size() == 16) result.mapProperties.insert(FPART_PROP_FILEMD5, QString::fromLatin1(entry.baMD5.toHex()));
    if (!XBinary::markArchiveStreamRecord(&result, pState->nCurrentIndex)) return ARCHIVERECORD();
    return result;
}

bool XISCab::_extractEntry(const UNPACK_CONTEXT *pContext, qint32 nEntryIndex, QIODevice *pStageDevice, UNPACK_STATE *pState, PDSTRUCT *pPdStruct) const
{
    if (!pContext || !pStageDevice || !pState || (nEntryIndex < 0) || (nEntryIndex >= pContext->listEntries.count()) || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }

    qint32 nSourceIndex = nEntryIndex;
    QSet<qint32> setVisited;
    while ((nSourceIndex >= 0) && (nSourceIndex < pContext->listEntries.count())) {
        if (setVisited.contains(nSourceIndex)) return false;
        setVisited.insert(nSourceIndex);
        const FILE_ENTRY &candidate = pContext->listEntries.at(nSourceIndex);
        if (!(candidate.nLinkFlags & IS_LINK_PREV)) break;
        if (candidate.nLinkPrevious >= static_cast<quint32>(pContext->listEntries.count())) {
            return false;
        }
        nSourceIndex = static_cast<qint32>(candidate.nLinkPrevious);
    }
    if ((nSourceIndex < 0) || (nSourceIndex >= pContext->listEntries.count())) return false;
    const FILE_ENTRY &entry = pContext->listEntries.at(nSourceIndex);

    QList<INPUT_SEGMENT> listSegments;
    if (!buildSegments(pContext->sMediaPrefix, pContext->common.nMajorVersion, entry.nFlags, entry.nExpandedSize, entry.nCompressedSize, entry.nDataOffset, entry.nVolume,
                       nSourceIndex, pContext->listEntries.count(), &listSegments)) {
        XBinary::setPdStructErrorString(pPdStruct, tr("InstallShield cabinet volume is missing or invalid"));
        return false;
    }
    SegmentReader reader(listSegments);
    const bool bObfuscated = entry.nFlags & IS_FILE_OBFUSCATED;
    const bool bCompressed = entry.nFlags & IS_FILE_COMPRESSED;
    quint64 nSeed = 0;
    quint64 nWritten = 0;
    QCryptographicHash hash(QCryptographicHash::Md5);

    const auto publishChunk = [&](QByteArray *pChunk) -> bool {
        if (!pChunk || !XBinary::isPdStructNotCanceled(pPdStruct) || (nWritten > entry.nExpandedSize) ||
            (static_cast<quint64>(pChunk->size()) > (entry.nExpandedSize - nWritten))) {
            return false;
        }
        if (pState->spOutputBudget && !pState->spOutputBudget->debit(pChunk->size())) {
            if (pState->spOutputBudget->isEnforcing()) {
                XBinary::setPdStructErrorString(pPdStruct, tr("Unpacked output exceeds the configured limit"));
                return false;
            }
            XBinary::OUTPUT_BUDGET::noteShadowRefusal(pState->spOutputBudget.data());
        }
        if (!writeAll(pStageDevice, pChunk->constData(), pChunk->size())) return false;
        hash.addData(*pChunk);
        nWritten += static_cast<quint64>(pChunk->size());
        return true;
    };

    if (!bCompressed) {
        quint64 nRemaining = entry.nExpandedSize;
        QByteArray baBuffer(64 * 1024, '\0');
        while (nRemaining) {
            const qint64 nChunk = static_cast<qint64>(qMin<quint64>(nRemaining, (quint64)baBuffer.size()));
            if (!reader.readExact(baBuffer.data(), nChunk)) return false;
            if (bObfuscated) deobfuscate(baBuffer.data(), nChunk, &nSeed);
            QByteArray baOutput = baBuffer.left(static_cast<qint32>(nChunk));
            if (!publishChunk(&baOutput)) return false;
            nRemaining -= static_cast<quint64>(nChunk);
        }
    } else {
        quint64 nRemaining = entry.nCompressedSize;
        while (nRemaining) {
            if (nRemaining < 2) return false;
            char szLength[2];
            if (!reader.readExact(szLength, 2)) return false;
            if (bObfuscated) deobfuscate(szLength, 2, &nSeed);
            nRemaining -= 2;
            const quint16 nBlockSize = static_cast<quint8>(szLength[0]) | (static_cast<quint16>(static_cast<quint8>(szLength[1])) << 8);
            if (!nBlockSize || (nBlockSize > nRemaining)) return false;
            QByteArray baBlock(nBlockSize, '\0');
            if (!reader.readExact(baBlock.data(), nBlockSize)) return false;
            if (bObfuscated) deobfuscate(baBlock.data(), nBlockSize, &nSeed);
            nRemaining -= nBlockSize;
            QByteArray baOutput;
            if (!inflateInstallShieldBlock(baBlock, &baOutput) || !publishChunk(&baOutput)) {
                XBinary::setPdStructErrorString(pPdStruct, tr("InstallShield cabinet deflate block is invalid"));
                return false;
            }
        }
    }

    if (nWritten != entry.nExpandedSize) return false;
    if ((pContext->common.nMajorVersion >= 6) && (entry.baMD5.size() == 16) && (hash.result() != entry.baMD5)) {
        XBinary::setPdStructErrorString(pPdStruct, tr("InstallShield cabinet member checksum mismatch"));
        return false;
    }
    return true;
}

bool XISCab::unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    UNPACK_OPERATION_GUARD operationGuard(&m_bUnpackOperationInProgress);
    QPointer<XISCab> guardedThis(this);
    QPointer<QIODevice> guardedOutput(pDevice);
    if (!operationGuard.isAcquired() || !pState || !pState->pContext || !guardedOutput) {
        return false;
    }
    const bool bOutputSupported = isUnpackOutputSupported(guardedOutput.data());
    if (!guardedThis || !guardedOutput || !bOutputSupported) return false;
    const bool bSourceCurrent = isUnpackSourceCurrent(pState, pPdStruct);
    if (!guardedThis || !guardedOutput || !bSourceCurrent || !XBinary::isPdStructNotCanceled(pPdStruct) || (pState->nCurrentIndex < 0) ||
        (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if (pState->nNumberOfRecords != pContext->listVisibleIndices.count()) return false;
    const qint32 nEntryIndex = pContext->listVisibleIndices.at(pState->nCurrentIndex);
    const FILE_ENTRY entry = pContext->listEntries.at(nEntryIndex);

    qint32 nSourceIndex = nEntryIndex;
    QSet<qint32> setVisited;
    while ((nSourceIndex >= 0) && (nSourceIndex < pContext->listEntries.count())) {
        if (setVisited.contains(nSourceIndex)) return false;
        setVisited.insert(nSourceIndex);
        const FILE_ENTRY &candidate = pContext->listEntries.at(nSourceIndex);
        if (!(candidate.nLinkFlags & IS_LINK_PREV)) break;
        if (candidate.nLinkPrevious >= static_cast<quint32>(pContext->listEntries.count())) {
            return false;
        }
        nSourceIndex = static_cast<qint32>(candidate.nLinkPrevious);
    }
    if ((nSourceIndex < 0) || (nSourceIndex >= pContext->listEntries.count())) return false;
    const quint64 nOutputSize = pContext->listEntries.at(nSourceIndex).nExpandedSize;

    qint64 nOutputLimit = -1;
    if (!XBinary::getUnpackOutputLimit(pState->mapUnpackProperties, &nOutputLimit) || ((nOutputLimit >= 0) && (nOutputSize > static_cast<quint64>(nOutputLimit)))) {
        XBinary::setPdStructErrorString(pPdStruct, tr("Unpacked output exceeds the configured limit"));
        return false;
    }
    if (pState->spOutputBudget && !pState->spOutputBudget->beginEntry(pState->nCurrentIndex, entry.sFileName)) {
        if (pState->spOutputBudget->isEnforcing()) {
            XBinary::setPdStructErrorString(pPdStruct, tr("Unpacked output exceeds the configured limit"));
            return false;
        }
        XBinary::OUTPUT_BUDGET::noteShadowRefusal(pState->spOutputBudget.data());
    }

    QTemporaryFile stage;
    if (!stage.open()) return false;
    bool bResult = _extractEntry(pContext, nEntryIndex, &stage, pState, pPdStruct);
    bResult = bResult && guardedThis && guardedOutput && isUnpackSourceCurrent(pState, pPdStruct) && guardedThis;
    if (bResult) bResult = publishUnpackOutput(&stage, guardedOutput.data(), pState, pPdStruct);
    return bResult;
}

bool XISCab::moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    QPointer<XISCab> guardedThis(this);
    UNPACK_OPERATION_GUARD operationGuard(&m_bUnpackOperationInProgress);
    if (!operationGuard.isAcquired() || !pState || !pState->pContext) {
        return false;
    }
    const bool bSourceCurrent = isUnpackSourceCurrent(pState, pPdStruct);
    if (!guardedThis || !bSourceCurrent || !XBinary::isPdStructNotCanceled(pPdStruct)) {
        return false;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    if ((pState->nNumberOfRecords != pContext->listVisibleIndices.count()) || (pState->nCurrentIndex < 0) || (pState->nCurrentIndex >= pState->nNumberOfRecords)) {
        return false;
    }
    ++pState->nCurrentIndex;
    pState->nCurrentOffset = pState->nCurrentIndex;
    return pState->nCurrentIndex < pState->nNumberOfRecords;
}

bool XISCab::finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    UNPACK_OPERATION_GUARD operationGuard(&m_bUnpackOperationInProgress);
    if (!operationGuard.isAcquired() || !pState) return false;
    if ((pState->pContext || !pState->baUnpackSourceToken.isEmpty()) && !ownsUnpackSource(pState)) {
        return false;
    }
    UNPACK_CONTEXT *pContext = static_cast<UNPACK_CONTEXT *>(pState->pContext);
    releaseUnpackSource(pState);
    pState->pContext = nullptr;
    pState->nCurrentOffset = 0;
    pState->nTotalSize = 0;
    pState->nCurrentIndex = 0;
    pState->nNumberOfRecords = 0;
    pState->mapUnpackProperties.clear();
    pState->mapArchiveProperties.clear();
    delete pContext;
    return true;
}

QList<XBinary::FPART_PROP> XISCab::getAvailableFPARTProperties()
{
    return QList<FPART_PROP>() << FPART_PROP_ORIGINALNAME << FPART_PROP_UNCOMPRESSEDSIZE << FPART_PROP_COMPRESSEDSIZE << FPART_PROP_FILEMD5 << FPART_PROP_ENCRYPTED
                               << FPART_PROP_FILEMODE;
}
