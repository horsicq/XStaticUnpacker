/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XASPACK_H
#define XASPACK_H

#include "xpe.h"

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
        AVER_212,
        AVER_OTHER,  // >2.12, <2.42
        AVER_242
    };

    struct INTERNAL_INFO {
        bool bIsValid;
        AVER version;
        QString sVersion;
    };

    explicit XASPACK(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XASPACK() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;
    virtual QString getVersion() override;

    virtual bool unpack(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;

private:
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

    static QByteArray _buildPE(const QByteArray &baImage, const QList<XPE_DEF::IMAGE_SECTION_HEADER> &listSections, int nSectCount, quint32 nImageBase, quint32 nOEP);

    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
};

#endif  // XASPACK_H
