/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XBOXEDAPP_H
#define XBOXEDAPP_H

#include <QSet>
#include <QSharedPointer>

#include "xbinary.h"

class XMaterializedUnpackGuard;

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
        UNPACK_CONTEXT() : nTotalOutput(0), pOwnerState(nullptr), nDeviceGeneration(0), nSourceSize(0), nCurrentOffset(0), nCurrentIndex(0) {}
        ~UNPACK_CONTEXT();

        QList<FILE_ENTRY> listEntries;
        QSet<QString> setNames;
        qint64 nTotalOutput = 0;
        qint32 nCurrentIndex = 0;
        qint64 nCurrentOffset = 0;
        qint64 nSourceSize = 0;
        XMaterializedUnpackGuard *pSourceGuard = nullptr;
        quint64 nDeviceGeneration = 0;
        QPointer<QIODevice> pSourceDevice;
        UNPACK_STATE *pOwnerState = nullptr;
        QByteArray baToken;
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

protected:
    bool isDeviceReplacementAllowed() const override;

private:
    struct LIFETIME_STATE {
        bool bOperationInProgress = false;
        bool bOwnerAlive = true;
        QSet<UNPACK_CONTEXT *> setContexts;
        ~LIFETIME_STATE();
    };
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _scanRecords(const QByteArray &baRegion, const QSet<QString> &setDeclaredNames, UNPACK_CONTEXT *pContext,
                      PDSTRUCT *pPdStruct);
    QSharedPointer<LIFETIME_STATE> m_pUnpackLifetimeState;
    bool m_bTrustedSnapshot = false;
};

#endif  // XBOXEDAPP_H
