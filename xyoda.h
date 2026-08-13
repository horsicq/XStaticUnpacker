/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XYODA_H
#define XYODA_H

#include "xpe.h"

/* Static unpacker for Yoda's Crypter ("yC" / Y0da Cryptor 1.3 and variants).
 * Clean-room implementation: the yC entry-point signatures, the per-byte
 * "poly decryptor" byte-VM, and the PE fixups were understood from the (GPL)
 * libclamav yc.c / pe.c reference, then reimplemented from scratch here.
 *
 * NOTE: not yet verified against real samples. Output is the decrypted PE with
 * the trailing yC section removed and OEP/headers restored. */

class XYODA : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : public XBinary::INTERNAL_INFO {
        bool bIsValid;
        QString sVersion;
        qint32 nOffset;  // yC-section decryptor offset selector (0, 0x10, or -0x18)
        quint32 nEcx;    // decryptor length
    };

    explicit XYODA(QIODevice *pDevice = nullptr, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XYODA() override;

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
    INTERNAL_INFO _detect(PDSTRUCT *pPdStruct);

    // Emulate the yC poly byte-decryptor. Returns 0 = ok, 1 = bad opcode, 2 = out of bounds.
    static int _polyEmulate(quint8 *pBase, qint64 nFileSize, qint64 nDecryptorOffset, qint64 nCodeOffset, quint32 nEcx, quint32 nMaxEmu);
};

#endif  // XYODA_H


