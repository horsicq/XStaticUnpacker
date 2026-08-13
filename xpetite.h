/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XPETITE_H
#define XPETITE_H

#include "xpe.h"

/* Static unpacker for Petite 2.x packed PE files. Clean-room implementation:
 * the Petite loader layout, its NRV-like LZ (XOR-obfuscated literals) and the
 * entry-point decryption / import walk were understood from the (GPL) libclamav
 * petite.c / pe.c reference, then reimplemented here from scratch.
 *
 * NOTE: not yet verified against real samples. Import unmangling is not
 * performed (as in the reference); the rebuilt PE is for static analysis. */

class XPETITE : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        int nVersion;  // 1 or 2
        QString sVersion;
    };

    explicit XPETITE(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XPETITE() override;

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

private:
    INTERNAL_INFO _getInternalInfo(PDSTRUCT *pPdStruct);
    INTERNAL_INFO m_internalInfo;
    struct UNPACK_CONTEXT {
        QByteArray baData;
        QString sFileName;
    };
    bool _unpackToBuffer(QByteArray &baOut, PDSTRUCT *pPdStruct);
    struct USECT {
        quint32 rva;
        quint32 rsz;
        quint32 vsz;
        quint32 raw;
    };

    // Order unpacked sections by ascending RVA (std::stable_sort comparator).
    static bool _usectRvaLess(const USECT &a, const USECT &b);

    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    // Recover the operations-table offset the loader actually uses. Petite builds
    // compute it dynamically (mov eax, loaderbase; lea reg, [eax + imm]) rather
    // than at a fixed offset, so locate that instruction pair and validate the
    // op table it points at. Returns a buffer offset, or -1 if none is found.
    static qint64 _findOpTable(const quint8 *buf, quint32 bufsz, quint32 nMinRva, quint32 nLoaderRva, quint32 nLoaderVsz, quint32 nImageBase);
    static int _doubledl(const quint8 *buf, qint64 bufsz, qint64 *pSrcOff, quint8 *pMydl);
    static bool _inflate(quint8 *buf, quint32 nMinRva, quint32 bufsz, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase,
                         quint32 nPep, int nVersion, QList<USECT> *pOut, quint32 *pEncEp);
    static QByteArray _buildPE(const QByteArray &baBuf, const QList<USECT> &listOut, quint32 nImageBase, quint32 nOEP, quint32 nResRva, quint32 nResSize);
};

#endif  // XPETITE_H


