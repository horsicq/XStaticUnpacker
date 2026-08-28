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
#ifndef XISCAB_H
#define XISCAB_H

#include "../XArchive/xarchive.h"

// InstallShield's proprietary ISc( cabinet family.  This is deliberately a
// separate reader from XCab: Microsoft cabinets use MSCF and have an unrelated
// on-disk layout.  InstallShield media may consist of DATA1.HDR plus one or
// more DATA<n>.CAB volumes; a QFile source lets the reader resolve those
// companions case-insensitively from the same directory.
class XISCab : public XArchive {
    Q_OBJECT

public:
    struct INTERNAL_INFO : XArchive::INTERNAL_INFO {
        bool bIsValid = false;
        qint32 nMajorVersion = 0;
        bool bHasCabDescriptor = false;
        quint32 nVolumeNumber = 0;
    };

    explicit XISCab(QIODevice *pDevice = nullptr);

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);

    bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    void setInternalInfo(void *pInternalInfo) override;

    FT getFileType() override;
    MODE getMode() override;
    qint32 getType() override;
    ENDIAN getEndian() override;
    QString getArch() override;
    QString getFileFormatExt() override;
    QString getFileFormatExtsString() override;
    QString getMIMEString() override;
    qint64 getFileFormatSize(PDSTRUCT *pPdStruct = nullptr) override;
    OSNAME getOsName() override;
    QString getVersion() override;
    QList<QString> getSearchSignatures() override;
    XBinary *createInstance(QIODevice *pDevice, bool bIsImage = false,
                            XADDR nModuleAddress = -1) override;

    QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
    bool initUnpack(UNPACK_STATE *pState,
                    const QMap<UNPACK_PROP, QVariant> &mapProperties,
                    PDSTRUCT *pPdStruct = nullptr) override;
    ARCHIVERECORD infoCurrent(UNPACK_STATE *pState,
                              PDSTRUCT *pPdStruct = nullptr) override;
    bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice,
                       PDSTRUCT *pPdStruct = nullptr) override;
    bool moveToNext(UNPACK_STATE *pState,
                    PDSTRUCT *pPdStruct = nullptr) override;
    bool finishUnpack(UNPACK_STATE *pState,
                      PDSTRUCT *pPdStruct = nullptr) override;
    QList<FPART_PROP> getAvailableFPARTProperties() override;

private:
    struct COMMON_HEADER {
        quint32 nVersion = 0;
        quint32 nVolumeInfo = 0;
        quint32 nDescriptorOffset = 0;
        quint32 nDescriptorSize = 0;
        qint32 nMajorVersion = 0;
    };

    struct FILE_ENTRY {
        quint16 nFlags = 0;
        quint64 nExpandedSize = 0;
        quint64 nCompressedSize = 0;
        quint64 nDataOffset = 0;
        QByteArray baMD5;
        quint32 nNameOffset = 0;
        quint16 nDirectoryIndex = 0;
        quint32 nLinkPrevious = 0;
        quint32 nLinkNext = 0;
        quint8 nLinkFlags = 0;
        quint16 nVolume = 0;
        QString sFileName;
        bool bVisible = false;
    };

    struct UNPACK_CONTEXT {
        QList<FILE_ENTRY> listEntries;
        QList<qint32> listVisibleIndices;
        QByteArray baCatalog;
        QString sMediaPrefix;
        QString sSourcePath;
        COMMON_HEADER common;
    };

    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    bool _readCommonHeader(QIODevice *pDevice, COMMON_HEADER *pHeader,
                           PDSTRUCT *pPdStruct) const;
    bool _loadCatalog(QByteArray *pCatalog, QString *pMediaPrefix,
                      QString *pSourcePath, COMMON_HEADER *pHeader,
                      PDSTRUCT *pPdStruct) const;
    bool _parseCatalog(const QByteArray &baCatalog,
                       const COMMON_HEADER &common,
                       QList<FILE_ENTRY> *pEntries,
                       QList<qint32> *pVisibleIndices,
                       PDSTRUCT *pPdStruct) const;
    bool _extractEntry(const UNPACK_CONTEXT *pContext, qint32 nEntryIndex,
                       QIODevice *pStageDevice, UNPACK_STATE *pState,
                       PDSTRUCT *pPdStruct) const;

private:
    INTERNAL_INFO m_internalInfo;
};

#endif  // XISCAB_H
