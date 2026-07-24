/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XFSG_H
#define XFSG_H

#include "xpe.h"

/* Static unpacker for FSG ("Fast Small Good") packed PE files, versions 1.33
 * and 2.0. Clean-room implementation: the FSG loader-stub layout and the
 * aPLib-style bit-stream format were understood from the (GPL) libclamav
 * fsg.c / packlibs.c / pe.c reference, then reimplemented here from scratch.
 *
 * NOTE: not yet verified against real samples (no FSG-packed samples were
 * available at implementation time). The rebuilt PE is a "dump" image suitable
 * for static analysis (sections + OEP restored; imports are not re-fixed). */

class XFSG : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO {
        bool bIsValid;
        qint32 nVersion;  // 133 or 200
        QString sVersion;
    };

    explicit XFSG(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XFSG() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual FT getFileType() override;
    virtual QString getVersion() override;

    // Writes a rebuilt (unpacked) PE image to pDevice.
    virtual bool unpack(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;

private:
    struct SECTIONINFO {
        quint32 nRva;
        quint32 nRsz;  // raw size (offset into the decompressed blob is implicit/sequential)
        quint32 nVsz;
        quint32 nRaw;  // offset into the decompressed blob
    };

    // aPLib-style depacker used by FSG. Returns bytes written, or -1 on error.
    static qint64 _aplibDepack(const quint8 *pSrc, qint64 nSrcSize, quint8 *pDst, qint64 nDstSize, qint64 *pnSrcConsumed);

    // Build a minimal analysis PE from a set of sections + OEP.
    static QByteArray _rebuildPE(const QByteArray &baBlob, const QList<SECTIONINFO> &listSections, quint32 nImageBase, quint32 nOEP);

    // Order sections by ascending RVA (std::sort comparator).
    static bool _sectionRvaLess(const SECTIONINFO &a, const SECTIONINFO &b);

    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);
    bool _findEmptyPair(XPE *pPE, qint32 *pnIndex);

    bool _unpackV200(XPE *pPE, qint32 nIndex, QIODevice *pDevice, PDSTRUCT *pPdStruct);
    bool _unpackV133(XPE *pPE, qint32 nIndex, QIODevice *pDevice, PDSTRUCT *pPdStruct);
};

#endif  // XFSG_H
