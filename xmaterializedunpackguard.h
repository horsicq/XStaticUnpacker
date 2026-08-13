/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
 *
 * MIT License
 */
#ifndef XMATERIALIZEDUNPACKGUARD_H
#define XMATERIALIZEDUNPACKGUARD_H

#include <new>

#include <QFile>
#include <QList>
#include <QScopedPointer>

#include "../XArchive/xarchive.h"

// Materialized handlers decode into private memory during initUnpack(), then
// serve those cached bytes later.  Keep the same complete source identity and
// content authentication used by streaming archives for the whole lifetime of
// that cached context.  The UNPACK_STATE below is private and has a stable heap
// address, so copied public states cannot authorize or release the session.
class XMaterializedUnpackGuard {
public:
    static XMaterializedUnpackGuard *bind(QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct = nullptr, bool bOwnDevice = false)
    {
        if (!pDevice) return nullptr;
        QScopedPointer<QIODevice> pOwnedDevice(bOwnDevice ? pDevice : nullptr);
        QScopedPointer<XMaterializedUnpackGuard> pResult;
        try {
            pResult.reset(new XMaterializedUnpackGuard(pDevice));
        } catch (const std::bad_alloc &) {
            return nullptr;
        }
        if (bOwnDevice) pResult->m_pOwnedDevice.reset(pOwnedDevice.take());
        if (!pResult || !pResult->m_archive.bindUnpackSource(&pResult->m_state, pPdStruct)) return nullptr;
        pResult->m_bBound = true;
        return pResult.take();
    }

    static XMaterializedUnpackGuard *openFile(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr)
    {
        QScopedPointer<QFile> pFile;
        try {
            pFile.reset(new QFile(sFileName));
        } catch (const std::bad_alloc &) {
            return nullptr;
        }
        if (!pFile || !pFile->open(QIODevice::ReadOnly)) return nullptr;
        return bind(pFile.take(), pPdStruct, true);
    }

    ~XMaterializedUnpackGuard()
    {
        if (m_bBound) m_archive.releaseUnpackSource(&m_state);
    }

    bool validateAndFinalize(XBinary::PDSTRUCT *pPdStruct = nullptr)
    {
        if (!m_bBound || m_bFinalized || !m_archive.validateAndFinalizeUnpackSource(&m_state, pPdStruct)) return false;
        m_bFinalized = true;
        return true;
    }

    bool isCurrent(XBinary::PDSTRUCT *pPdStruct = nullptr)
    {
        return m_bBound && m_bFinalized && m_archive.isUnpackSourceCurrent(&m_state, pPdStruct);
    }

    QIODevice *device() { return m_archive.getDevice(); }

    static bool areCurrent(XMaterializedUnpackGuard *pPrimary, const QList<XMaterializedUnpackGuard *> &listCompanions,
                           XBinary::PDSTRUCT *pPdStruct = nullptr)
    {
        if (!pPrimary || !pPrimary->isCurrent(pPdStruct)) return false;
        for (XMaterializedUnpackGuard *pGuard : listCompanions) {
            if (!pGuard || !pGuard->isCurrent(pPdStruct)) return false;
        }
        return true;
    }

private:
    explicit XMaterializedUnpackGuard(QIODevice *pDevice)
        : m_archive(pDevice)
    {
    }

    Q_DISABLE_COPY(XMaterializedUnpackGuard)

    QScopedPointer<QIODevice> m_pOwnedDevice;
    XArchive m_archive;
    XBinary::UNPACK_STATE m_state = {};
    bool m_bBound = false;
    bool m_bFinalized = false;
};

#endif  // XMATERIALIZEDUNPACKGUARD_H
