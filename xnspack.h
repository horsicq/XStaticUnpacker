/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XNSPACK_H
#define XNSPACK_H

#include "xpe.h"

#include <QSet>
#include <QSharedPointer>

class XMaterializedUnpackGuard;

/* Static unpacker for NsPack-packed PE files. Clean-room implementation: the
 * NsPack loader-stub layout and its custom LZMA-style range decoder were
 * understood from the (GPL) libclamav unsp.c / pe.c reference, then
 * reimplemented here from scratch.
 *
 * NOTE: not yet verified against real samples. Output is a rebuilt analysis PE
 * (single decompressed section + restored OEP). */

class XNSPACK : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        qint64 nStartOfStuff;  // file offset of the compressed blob header
        quint32 nSsize;        // packed size
        quint32 nDsize;        // unpacked size
        quint32 nOEP;          // original entry point RVA
        quint32 nRva;          // target section RVA (sections[0].rva)
        quint32 nImageBase;
    };

    explicit XNSPACK(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XNSPACK() override;

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
    struct NSP_STATE {
        const quint8 *pSrcCurr;
        const quint8 *pSrcEnd;
        quint32 nBitmap;
        quint32 nOldval;
        int nError;
        quint16 *pTable;
        quint32 nTableEntries;
    };

    static quint8 _getByte(NSP_STATE *s);
    static int _getBit(NSP_STATE *s, quint32 nIndex);
    static quint32 _get100(NSP_STATE *s, quint32 nBase);
    static quint32 _get100Size(NSP_STATE *s, quint32 nBase, quint32 nMatchByte);
    static quint32 _getN(NSP_STATE *s, quint32 nBase, quint32 nBits);
    static quint32 _getNSize(NSP_STATE *s, quint32 nBase, quint32 nBackSize);
    static quint32 _getBB(NSP_STATE *s, quint32 nBase, quint32 nBack);
    static quint32 _getBitmap(NSP_STATE *s, quint32 nBits);

    static bool _decompress(quint32 nTre, quint32 nAllocsz, quint32 nFirstByte, const quint8 *pSrc, quint32 nSsize, quint8 *pDst, quint32 nDsize, quint16 *pTable,
                            quint32 nTableEntries);
    // Reverse NsPack's E8/E9 CALL/JMP address filter over the decompressed blob.
    static void _deFilterCallJmp(quint8 *pData, quint32 nSize);
    // Rebuild the original import directory from NsPack's descriptor stream. Fills the
    // IAT inside *pBaBlob and returns the bytes of a fresh import section to be placed
    // at RVA nImpRva (empty on failure / no imports). Sets *pnDescSize.
    QByteArray _reconstructImports(QByteArray *pBaBlob, quint32 nRva, quint32 nImpRva, quint32 *pnDescSize, PDSTRUCT *pPdStruct);
    static QByteArray _buildPE(const QByteArray &baBlob, quint32 nRva, quint32 nImageBase, quint32 nOEP, const QByteArray &baImportSection = QByteArray(),
                               quint32 nImpRva = 0, quint32 nDescSize = 0, qint64 nOutputLimit = -1);

    bool _unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    // Locate the nsp0 compressed-block header (start-of-stuff) by scanning for the
    // highest self-consistent header whose dsize field equals nSec0Vsize. Used for
    // NsPack versions whose entry-point stub does not carry the 2.x delta.
    qint64 _findStartOfStuff(quint32 nSec0Vsize, PDSTRUCT *pPdStruct);
};

#endif  // XNSPACK_H
