/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XFSG_H
#define XFSG_H

#include "xpe.h"

#include <QSet>
#include <QSharedPointer>

class XMaterializedUnpackGuard;

/* Static unpacker for FSG ("Fast Small Good") packed PE files, versions
 * 1.0/1.3, 1.1/1.2, 1.31, 1.33 and 2.0. Clean-room implementation: the FSG
 * loader-stub layout and the aPLib-style bit-stream format were understood from
 * the (GPL) libclamav fsg.c / packlibs.c / pe.c reference, then reimplemented
 * here from scratch; the pre-1.33 stub shapes were derived from the packed
 * corpus, since the reference only covers 1.33 and 2.0.
 *
 * Every generation shares one bit-stream; they differ in how the loader locates
 * the destination, the source and the per-section RVA list:
 *   - 1.33/2.0 use a 32-bit support list with a 12-byte header;
 *   - 1.0/1.3, 1.31 and 1.1/1.2 use a 16-bit support list and take the
 *     destination/source from entry-point immediates;
 *   - 1.1/1.2 additionally encrypt the stub behind a polymorphic byte loop.
 *
 * The rebuilt PE is a "dump" image suitable for static analysis (sections + OEP
 * restored; imports are not re-fixed). */

class XFSG : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        qint32 nVersion;  // 100, 112, 131, 133 or 200
        QString sVersion;
        quint32 nSupportRva;  // support/relocation table RVA (1.x paths)
        quint32 nDestVa;      // destination VA from the entry-point immediates
        quint32 nSrcVa;       // packed-stream VA from the entry-point immediates
        qint32 nJeOffset;     // `0F 84` OEP anchor, entry-point relative
        bool bWordList;       // 16-bit support list (pre-1.33) instead of 32-bit
        bool bEncryptedStub;  // 1.1/1.2 polymorphic stub encryption
    };

    explicit XFSG(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XFSG() override;

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
    struct SECTIONINFO {
        quint32 nRva;
        quint32 nRsz;  // raw size (offset into the decompressed blob is implicit/sequential)
        quint32 nVsz;
        quint32 nRaw;  // offset into the decompressed blob
    };

    // aPLib-style depacker used by FSG. Returns bytes written, or -1 on error.
    static qint64 _aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed);

    // Build a minimal analysis PE from a set of sections + OEP.
    static QByteArray _rebuildPE(const QByteArray &baBlob, const QList<SECTIONINFO> &listSections, quint32 nImageBase, quint32 nOEP, qint64 nOutputLimit = -1);

    // Order sections by ascending RVA (std::sort comparator).
    static bool _sectionRvaLess(const SECTIONINFO &a, const SECTIONINFO &b);

    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _findEmptyPair(XPE *pPE, qint32 *pnIndex);

    bool _resolveOep(XPE *pPE, const INTERNAL_INFO &info, quint32 *pnOEP, PDSTRUCT *pPdStruct);

    bool _unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    bool _unpackV200(XPE *pPE, qint32 nIndex, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    bool _unpackV133(XPE *pPE, qint32 nIndex, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    bool _unpackV1x(XPE *pPE, qint32 nIndex, const INTERNAL_INFO &info, QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
};

#endif  // XFSG_H
