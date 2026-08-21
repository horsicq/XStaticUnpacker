/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XBURN_H
#define XBURN_H

#include "xbinary.h"

class SubDevice;
class XArchive;
class XCab;

/* WiX Toolset v3 Burn bundle detector and payload extractor.
 *
 * This reader supports a CAB UX container and, optionally, one attached CAB
 * after the PE engine.  The UX container owns the Burn manifest which
 * authenticates the physical CAB members and supplies their public paths.
 * Additional attached containers, detached/external payloads, and newer Burn
 * section/container formats are deliberately rejected until their layouts can
 * be handled completely without guessing or omitting records. */
class XBurn : public XBinary {
    Q_OBJECT

public:
    enum CONTAINER_TYPE {
        CONTAINER_TYPE_UNKNOWN = 0,
        CONTAINER_TYPE_UX,
        CONTAINER_TYPE_ATTACHED
    };

    struct PAYLOAD_RECORD {
        CONTAINER_TYPE containerType;
        qint32 nInnerIndex;
        QString sSourcePath;
        QString sFilePath;
        QString sPublicPath;
        QString sPayloadId;
        QString sPackageId;
        QString sPackageType;
        qint64 nFileSize;
        QByteArray baSHA1;
    };

    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        QByteArray baBundleId;
        qint64 nUXOffset;
        qint64 nUXSize;
        qint64 nAttachedOffset;
        qint64 nAttachedSize;
        QList<PAYLOAD_RECORD> listPayloads;
    };

    struct CONTAINER_CONTEXT {
        SubDevice *pSubDevice;
        XCab *pCab;
        UNPACK_STATE state;
        bool bInitialized;
        qint64 nOuterOffset;
        qint64 nOuterSize;
    };

    struct UNPACK_CONTEXT {
        QPointer<QIODevice> pOuterSourceDevice;
        quint64 nOwnerDeviceGeneration;
        UNPACK_STATE *pOwnerState;
        CONTAINER_CONTEXT ux;
        CONTAINER_CONTEXT attached;
        QList<PAYLOAD_RECORD> listPayloads;
        qint32 nCurrentPayload;
        XArchive *pSourceValidator;
        UNPACK_STATE sourceValidationState;
    };

    struct UNPACK_LIFETIME_STATE {
        UNPACK_LIFETIME_STATE() : bOperationInProgress(false), bOwnerAlive(true) {}
        ~UNPACK_LIFETIME_STATE();
        bool bOperationInProgress;
        bool bOwnerAlive;
        QSet<UNPACK_CONTEXT *> setContexts;
    };

    static bool deleteUnpackContext(UNPACK_CONTEXT *pContext);

    explicit XBurn(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XBurn() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    void setInternalInfo(void *pInternalInfo) override;

    FT getFileType() override;

    QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
    bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties,
                    PDSTRUCT *pPdStruct = nullptr) override;
    ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

protected:
    bool isDeviceReplacementAllowed() const override
    {
        return m_pUnpackLifetimeState && m_pUnpackLifetimeState->bOwnerAlive &&
               !m_pUnpackLifetimeState->bOperationInProgress && m_pUnpackLifetimeState->setContexts.isEmpty();
    }

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);

    INTERNAL_INFO m_internalInfo;
    QSharedPointer<UNPACK_LIFETIME_STATE> m_pUnpackLifetimeState;
};

#endif  // XBURN_H
