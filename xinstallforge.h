/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINSTALLFORGE_H
#define XINSTALLFORGE_H

#include "xbinary.h"

class SubDevice;
class XArchive;

/* Detector + extractor for InstallForge installers. The MSVC PE stub stores its
 * payload in the overlay behind a 13-byte "IFSETUP_START" (+1) marker and an
 * 8-byte little-endian length, followed by a standard 7-Zip archive. Extraction
 * delegates to the XArchive 7z handler on that archive region. Note: InstallForge
 * obfuscates entry names as base64(UTF-16LE(name)); file content is stored raw. */

class XInstallForge : public XBinary {
    Q_OBJECT

public:
    enum PAYLOAD {
        PAYLOAD_UNKNOWN = 0,
        PAYLOAD_7Z,
        PAYLOAD_BZIP2,
        PAYLOAD_GZIP
    };

    struct INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        qint64 nArchiveOffset;
        qint64 nArchiveSize;
        PAYLOAD payload;  // container format of the file payload (varies by compressor)
    };

    struct UNPACK_CONTEXT {
        SubDevice *pSubDevice;
        XArchive *pArchive;
        UNPACK_STATE innerState;
    };

    explicit XInstallForge(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInstallForge() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XINSTALLFORGE_H
