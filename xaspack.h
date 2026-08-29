/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XASPACK_H
#define XASPACK_H

#include "xpe.h"

#include <QSet>
#include <QSharedPointer>

class XMaterializedUnpackGuard;

/* Static unpacker for ASPack-packed PE files (2.12 / >2.12<2.42 / 2.42).
 * Clean-room implementation: the ASPack loader-stub layout and its DEFLATE-style
 * dynamic-Huffman + LZ decoder (with 4 code dictionaries and LZMA-like distance
 * history) were understood from the (GPL) libclamav aspack.c / pe.c reference,
 * then reimplemented here from scratch.
 *
 * NOTE: not yet verified against real samples. Output is a rebuilt analysis PE
 * (decompressed sections mapped by RVA + restored OEP). */

class XASPACK : public XBinary {
    Q_OBJECT

public:
    enum AVER {
        AVER_NONE = 0,
        AVER_200,  // 2.000
        AVER_201,  // 2.001 and 2.1 share one stub layout
        AVER_212,
        AVER_22,     // 2.2x
        AVER_OTHER,  // >2.12, <2.42
        AVER_242,
        AVER_211,  // 2.11 and 2.11r share one stub layout (encrypted head)
        AVER_211C  // 2.11c and 2.11d share one stub layout (encrypted head)
    };

    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        AVER version;
        QString sVersion;
    };

    explicit XASPACK(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XASPACK() override;

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
    struct DICT_HELPER {
        quint32 *starts;
        quint8 *ends;
        quint32 size;
    };

    struct ASPK {
        quint32 bitpos;
        quint32 hash;
        quint32 init_array[58];
        DICT_HELPER dict_helper[4];
        const quint8 *input;
        const quint8 *iend;
        quint8 *decrypt_dict;
        quint32 decarray3[4][24];
        quint32 decarray4[4][24];
        int dict_ok;
        quint8 array2[758];
        quint8 array1[19];
    };

    static int _readstream(ASPK *s);
    static quint32 _getdec(ASPK *s, quint8 which, int *err);
    static quint8 _buildArray(ASPK *s, quint8 *array, quint8 which);
    static quint8 _getbits(ASPK *s, quint32 num, int *err);
    static int _buildDicts(ASPK *s);
    static int _decrypt(ASPK *s, const quint8 *stuff, quint32 size, quint8 *output);
    static int _decompBlock(ASPK *s, quint32 size, const quint8 *stuff, quint8 *output);
    static void _initDict(ASPK *s, quint8 **ppWrkbuf, int n, quint32 sz);

    static QByteArray _buildPE(const QByteArray &baImage, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase, quint32 nOEP,
                               qint64 nOutputLimit = -1);

    bool _unpackToBuffer(QByteArray &baOut, qint64 nOutputLimit, PDSTRUCT *pPdStruct);
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XASPACK_H
