/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XBOXEDAPP_H
#define XBOXEDAPP_H

#include <QSet>

#include "xbinary.h"

/* Detector + VFS extractor for BoxedApp Packer (Softanics)
 * application-virtualizer output.
 * The wrapped PE carries a ".bxpck" control section followed by a ".main"
 * section that holds the BoxedApp engine + the sandboxed virtual filesystem,
 * identified by the "BoxedApp::" C++ symbol strings. The VFS file nodes expose
 * STORE and zlib streams directly. Trial builds are flagged via the embedded
 * demo nag ("demo"). */

class XBoxedApp : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;  // "demo" for trial builds, otherwise empty
        qint64 nBxpckOffset;
        qint64 nBxpckSize;
        qint64 nMainOffset;
        qint64 nMainSize;
    };

    struct FILE_ENTRY {
        QString sName;
        QByteArray baData;  // decoded content (store or inflated)
    };

    struct UNPACK_CONTEXT {
        UNPACK_CONTEXT() : nTotalOutput(0) {}

        QList<FILE_ENTRY> listEntries;
        QSet<QString> setNames;
        qint64 nTotalOutput;
    };

    explicit XBoxedApp(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XBoxedApp() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual FT getFileType() override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _scanRecords(const QByteArray &baRegion, const QSet<QString> &setDeclaredNames, UNPACK_CONTEXT *pContext,
                      PDSTRUCT *pPdStruct);
};

#endif  // XBOXEDAPP_H
