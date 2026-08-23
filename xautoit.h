/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XAUTOIT_H
#define XAUTOIT_H

#include "xbinary.h"

#include <QSet>
#include <QSharedPointer>

class XMaterializedUnpackGuard;

/* Extractor for AutoIt v2/v3-compiled PE files. Clean-room implementation
 * based on the documented v2/JB01 and EA05/EA06 container behaviour and
 * independently checked against the official AutoIt tools and libclamav's
 * autoit.c implementation.
 *
 * EA05 uses the MT stream cipher. EA06 uses the LAME additive generator; its
 * floating-point value is assembled from an IEEE-754 binary64 bit pattern, so
 * extraction is deterministic on supported Qt targets and does not depend on
 * x87 extended precision. */

class XAUTOIT : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_RECORD,
    };

    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        int nVersion;  // 2 (v2/JB01), 5 (EA05), or 6 (EA06)
        QString sVersion;
        qint64 nMarkerOffset;
    };

    struct RECORD {
        QString sName;
        QByteArray baData;
    };

    struct UNPACK_CONTEXT {
        ~UNPACK_CONTEXT();
        // Declared before listRecords so record buffers are destroyed before
        // their process-wide reservation is released (reverse member order).
        UNPACK_MEMORY_RESERVATION memoryReservation;
        QList<RECORD> listRecords;
        QPointer<QIODevice> pSourceDevice;
        UNPACK_STATE *pOwnerState;
        QByteArray baToken;
        quint64 nDeviceGeneration;
        qint64 nSourceSize;
        qint64 nCurrentOffset;
        qint32 nCurrentIndex;
        XMaterializedUnpackGuard *pSourceGuard = nullptr;
    };

    explicit XAUTOIT(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XAUTOIT() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual FT getFileType() override;
    virtual QString getVersion() override;

    virtual QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
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
    QSharedPointer<LIFETIME_STATE> m_pUnpackLifetimeState;
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    static void _v2Decrypt(quint8 *pBuf, quint32 nSize, quint32 nSeed);
    static void _mtDecrypt(quint8 *pBuf, quint32 nSize, quint32 nSeed);
    static bool _inflate(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize, bool bEA06 = false,
                         quint32 *pActualSize = nullptr);
    static bool _inflateV2(const quint8 *pInput, quint32 nCsize, quint8 *pOutput, quint32 nUsize);
    static quint32 _u2a(quint8 *pDest, quint32 nLen);
    QList<RECORD> _parseV2(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                           const QMap<UNPACK_PROP, QVariant> &mapProperties,
                           UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct);
    QList<RECORD> _parseEA05(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                             const QMap<UNPACK_PROP, QVariant> &mapProperties,
                             UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct);
    QList<RECORD> _parseEA06(const quint8 *pData, qint64 nSize, qint64 nBase, qint64 nOutputLimit,
                             const QMap<UNPACK_PROP, QVariant> &mapProperties,
                             UNPACK_MEMORY_RESERVATION *pRecordReservation, PDSTRUCT *pPdStruct);
};

#endif  // XAUTOIT_H
