/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XSFX_H
#define XSFX_H

#include "xarchive.h"

class SubDevice;
struct XSFX_ZPAQ_SCAN_CACHE;
struct XSFX_FREEARC_SCAN_CACHE;

/* XSFX detects self-extracting archives: an executable (PE/MZ/ELF) stub followed
 * by an embedded archive in its unmapped suffix. It locates the archive and
 * delegates the streaming unpack API to the matching XArchive handler,
 * presenting only the archive region through a SubDevice. */

class XSFX : public XBinary {
    Q_OBJECT

public:
    enum ARCTYPE {
        ARC_UNKNOWN = 0,
        ARC_7Z,
        ARC_ZIP,
        ARC_RAR,
        ARC_CAB,
        ARC_FREEARC,
        ARC_ZPAQ
    };

    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        bool bProvisional;
        bool bResourceIndeterminate;
        bool bAllowOpaqueZpaq;
        bool bUseOuterDevice;
        ARCTYPE arcType;
        qint64 nArchiveOffset;
        qint64 nArchiveSize;
    };

    struct UNPACK_CONTEXT {
        QPointer<QIODevice> pOuterSourceDevice;
        quint64 nOwnerDeviceGeneration;
        UNPACK_STATE *pOwnerState = nullptr;
        INTERNAL_INFO info;
        SubDevice *pSubDevice;
        XArchive *pArchive;
        UNPACK_STATE innerState;
        // The public outer state never retains helper passwords. Keep a
        // sanitized retry map plus one detached credential copy private until
        // the provisional candidate is authenticated, then scrub it.
        QMap<UNPACK_PROP, QVariant> mapPrivateUnpackProperties;
        QString sPrivatePassword;
        QByteArray baPrivatePassword;
    };

    struct UNPACK_DEFERRED_CLEANUP {
        ~UNPACK_DEFERRED_CLEANUP();
        QSet<UNPACK_CONTEXT *> setContexts;
    };

    explicit XSFX(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XSFX() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual FT getFileType() override;
    virtual QString getArch() override;
    virtual MODE getMode() override;
    virtual QString getMIMEString() override;

    virtual QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

protected:
    explicit XSFX(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress,
                  ARCTYPE requiredArcType);

    bool isDeviceReplacementAllowed() const override
    {
        return (!m_pUnpackOperationState || !*m_pUnpackOperationState) && m_setUnpackContexts.isEmpty();
    }

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct,
                          XSFX_ZPAQ_SCAN_CACHE *pZpaqScanCache = nullptr,
                          XSFX_FREEARC_SCAN_CACHE *pFreeArcScanCache = nullptr,
                          qint64 nMinimumArchiveOffset = -1);
    bool _matchArchiveAt(qint64 nOffset, qint64 nSize, ARCTYPE *pType,
                          qint64 *pArchiveSize, PDSTRUCT *pPdStruct,
                          XSFX_ZPAQ_SCAN_CACHE *pZpaqScanCache,
                          XSFX_FREEARC_SCAN_CACHE *pFreeArcScanCache,
                          bool *pbProvisional,
                          bool *pbResourceIndeterminate,
                          bool *pbUseOuterDevice);
    XArchive *_createArchive(ARCTYPE arcType, QIODevice *pDevice,
                             bool bAllowOpaqueZpaq = false);
    QSharedPointer<bool> m_pUnpackOperationState;
    QSharedPointer<UNPACK_DEFERRED_CLEANUP> m_pUnpackDeferredCleanup;
    QSet<UNPACK_CONTEXT *> m_setUnpackContexts;
    ARCTYPE m_requiredArcType;
};

#endif  // XSFX_H
