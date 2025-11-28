/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XNSIS_H
#define XNSIS_H

#include <QString>

#include "xbinary.h"

class XNSIS : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
    };

    struct INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sSignature;
        QString sVersion;
        bool bIsUnicode;
    };

    struct UNPACK_CONTEXT {
        qint64 nDataOffset;
        qint64 nDataSize;
        bool bIsSolid;
    };

    explicit XNSIS(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XNSIS() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual QString structIDToString(quint32 nID) override;

    virtual bool initUnpack(UNPACK_STATE *pState, const QMap<UNPACK_PROP, QVariant> &mapProperties, PDSTRUCT *pPdStruct = nullptr) override;
    virtual ARCHIVERECORD infoCurrent(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool unpackCurrent(UNPACK_STATE *pState, QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool moveToNext(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;
    virtual bool finishUnpack(UNPACK_STATE *pState, PDSTRUCT *pPdStruct = nullptr) override;

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
};

#endif  // XNSIS_H
