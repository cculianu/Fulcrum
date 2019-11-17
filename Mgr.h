#ifndef MMMGR_H
#define MMMGR_H

#include "Mixins.h"

#include <QObject>
#include <QVariantMap>

/// Abstract base class of all subsystem controllers such as SrvMgr, BitcoinDMgr, etc.
/// These get created by the App on startup, based on config.
class Mgr : public QObject, public StatsMixin
{
    Q_OBJECT
public:
    explicit Mgr(QObject *parent = nullptr);
    ~Mgr() override;

    virtual void startup() = 0; ///< NB: mgrs may throw Exception here, so catch it and abort if that happens.
    virtual void cleanup() = 0;
};

#endif // MMMGR_H
