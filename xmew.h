/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XMEW_H
#define XMEW_H

#include "xpe.h"

#include <QSet>
#include <QSharedPointer>

class XMaterializedUnpackGuard;

/* Static unpacker for MEW (11 SE) packed PE files. Clean-room implementation
 * derived from the (GPL) libclamav mew.c / packlibs.c / pe.c reference.
 *
 * MEW's non-LZMA path uses the same aPLib-style bitstream as FSG (`unmew` ==
 * `cli_unfsg`). The LZMA path turned out to be *stock* LZMA1 (lc=4/lp=0/pb=2,
 * verified byte-exact against the reference clear32.unp.exe), so it is decoded
 * with the public-domain LZMA-SDK decoder (XArchive/3rdparty/lzma) — no GPL
 * code is reused, only the MEW-specific container framing and the optional
 * "special" x86 call/jmp de-filter are reimplemented from format facts. */

class XMEW : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        bool bUsesLzma;
        QString sVersion;
    };

    explicit XMEW(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XMEW() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct = nullptr) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    virtual FT getFileType() override;

    virtual QMap<UNPACK_PROP, QVariant> getDefaultUnpackProperties() override;
    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;

protected:
    bool isDeviceReplacementAllowed() const override;

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    struct UNPACK_CONTEXT {
        ~UNPACK_CONTEXT();
        QByteArray baData;
        QString sFileName;
        QString sInfo;
        QPointer<QIODevice> pSourceDevice;
        UNPACK_STATE *pOwnerState;
        QByteArray baToken;
        quint64 nDeviceGeneration;
        qint64 nSourceSize;
        qint64 nCurrentOffset;
        qint32 nCurrentIndex;
        XMaterializedUnpackGuard *pSourceGuard = nullptr;
    };
    struct LIFETIME_STATE {
        bool bOperationInProgress = false;
        bool bOwnerAlive = true;
        QSet<UNPACK_CONTEXT *> setContexts;
        ~LIFETIME_STATE();
    };
    QSharedPointer<LIFETIME_STATE> m_pUnpackLifetimeState;
    struct SECT {
        quint32 rva;
        quint32 rsz;
        quint32 vsz;
        quint32 raw;
    };

    struct DETECT {
        bool bIsValid;
        quint32 nVersion;    // 10 or 11 (11 covers MEW 11 and 11 SE)
        qint32 nIndex;       // empty-section index i (dest = i, source = i+1)
        qint64 nFileOffset;  // MEW stub table file offset (0x154/0x155/0x158)
        quint32 nOffDiff;
        quint32 nSsize;
        quint32 nDsize;
        quint32 nSrcRaw;     // section[i+1] PointerToRawData
        quint32 nSrcRsz;     // section[i+1] SizeOfRawData
        quint32 nVadd;       // section[0].rva
        quint32 nImageBase;
        quint32 nUseLzma;
    };

    static qint64 _aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed);
    static QByteArray _buildPE(const QByteArray &baBuf, const QList<SECT> &listSections, quint32 nImageBase, quint32 nOEP,
                               qint64 nOutputLimit = -1);

    // LZMA path: stock raw LZMA1 (lc=4/lp=0/pb=2) decode + MEW container framing.
    static bool _decodeRawLzma(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, quint32 nDstSize, quint32 nDictSize);
    static void _bcjFilter(quint8 *pData, quint32 nSize, quint32 nLen);
    bool _lzmaDepack(QByteArray &baBuf, qint64 nContainerOff, quint32 nUseLzma, quint32 nDsize, quint32 nVma, PDSTRUCT *pPdStruct);

    bool _unpackMew10(QByteArray &baBuf, const DETECT &d, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    bool _unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    DETECT _detect(PDSTRUCT *pPdStruct);
};

#endif  // XMEW_H
