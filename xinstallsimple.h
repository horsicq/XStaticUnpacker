/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINSTALLSIMPLE_H
#define XINSTALLSIMPLE_H

#ifdef USE_XEMULATOR

#include <QSet>
#include <QSharedPointer>

#include "xbinary.h"

class XMaterializedUnpackGuard;

/* Detector + extractor for Install Simple (InstallSimple) installers. The
 * UPX-packed MASM32 PE stub stores independently coded records in its overlay.
 * Its proprietary adaptive range/LZ codec is decoded by executing only the
 * unpacked stub's decoder routines in XEmulator's sandboxed x86 core. */

class XInstallSimple : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
    };

    struct FILE_ENTRY {
        QString sName;
        QByteArray baData;
    };

    struct UNPACK_CONTEXT {
        ~UNPACK_CONTEXT();
        QList<FILE_ENTRY> listEntries;
        QPointer<QIODevice> pSourceDevice;
        UNPACK_STATE *pOwnerState = nullptr;
        QByteArray baToken;
        quint64 nDeviceGeneration = 0;
        qint64 nSourceSize = 0;
        XMaterializedUnpackGuard *pSourceGuard = nullptr;
        qint64 nCurrentOffset = 0;
        qint32 nCurrentIndex = 0;
    };

    explicit XInstallSimple(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInstallSimple() override;

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
    QSharedPointer<LIFETIME_STATE> m_pUnpackLifetimeState;
    bool m_bTrustedSnapshot = false;
};

#endif  // USE_XEMULATOR

#endif  // XINSTALLSIMPLE_H
