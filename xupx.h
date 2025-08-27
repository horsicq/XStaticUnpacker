/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XUPX_H
#define XUPX_H

#include "xbinary.h"
#include "xpe.h"

class XUPX : public XBinary {
    Q_OBJECT

public:
    struct UNPACK_INFO {
        bool bIsValid;
        FT fileType;
        QString sUPXVersion;
    };

    explicit XUPX(QIODevice *pDevice = nullptr);
    ~XUPX() override;

    bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    UNPACK_INFO getUnpackInfo(PDSTRUCT *pPdStruct = nullptr);
};

#endif  // XUPX_H
