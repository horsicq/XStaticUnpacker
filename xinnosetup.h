/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XINNOSETUP_H
#define XINNOSETUP_H

#include <QString>

#include "xbinary.h"

class XInnoSetup : public XBinary {
    Q_OBJECT

public:
    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
    };
    struct INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sVersion;
    };

    explicit XInnoSetup(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XInnoSetup() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

    virtual QString structIDToString(quint32 nID) override;

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
};

#endif  // XINNOSETUP_H
