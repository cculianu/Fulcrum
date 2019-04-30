#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <QObject>
#include <QVariantMap>
/// Abstract base class of all subsystem controllers such as EXMgr, etc.
/// These get created by the App on startup, based on config.
class Mgr : public QObject
{
    Q_OBJECT
public:
    explicit Mgr(QObject *parent = nullptr);
    virtual ~Mgr();
    virtual void startup() = 0; ///< NB: mgrs may throw Exception here, so catch it and abort if that happens.
    virtual void cleanup() = 0;

    typedef QVariantMap Stats;

    /// Return controller-specific stats -- to be used later if we implement some sort of query mechanism
    /// for showing stats to clients and/or server admins.
    /// For now stub implementation returns an empty map.
    virtual Stats stats() const;
};

#endif // CONTROLLER_H
