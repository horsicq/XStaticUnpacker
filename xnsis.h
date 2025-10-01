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
    struct INTERNAL_INFO {
        bool bIsValid;
        qint64 nSignatureOffset;
        QString sSignature;
        QString sVersion;
        bool bIsUnicode;
    };

    explicit XNSIS(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1);
    ~XNSIS() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    INTERNAL_INFO getInternalInfo(PDSTRUCT *pPdStruct = nullptr);

private:
    INTERNAL_INFO _analyse(PDSTRUCT *pPdStruct);
};

#endif  // XNSIS_H
