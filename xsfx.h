/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XSFX_H
#define XSFX_H

#include "xarchive.h"

class SubDevice;

/* XSFX detects self-extracting archives: an executable (PE/MZ) stub followed by
 * an embedded 7-Zip / RAR / CAB archive (typically in the overlay). It locates
 * the archive and delegates the streaming unpack API to the matching XArchive
 * handler, presenting the archive region through a SubDevice. */

class XSFX : public XBinary {
    Q_OBJECT

public:
    enum ARCTYPE {
        ARC_UNKNOWN = 0,
        ARC_7Z,
        ARC_RAR,
        ARC_CAB
    };

    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
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
    bool isDeviceReplacementAllowed() const override
    {
        return (!m_pUnpackOperationState || !*m_pUnpackOperationState) && m_setUnpackContexts.isEmpty();
    }

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _matchArchiveAt(qint64 nOffset, qint64 nSize, ARCTYPE *pType, qint64 *pArchiveSize, PDSTRUCT *pPdStruct);
    XArchive *_createArchive(ARCTYPE arcType, QIODevice *pDevice);
    QSharedPointer<bool> m_pUnpackOperationState;
    QSharedPointer<UNPACK_DEFERRED_CLEANUP> m_pUnpackDeferredCleanup;
    QSet<UNPACK_CONTEXT *> m_setUnpackContexts;
};

#endif  // XSFX_H
