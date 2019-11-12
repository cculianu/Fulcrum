#ifndef MMMGR_H
#define MMMGR_H

#include <QObject>
#include <QVariantMap>
/// Abstract base class of all subsystem controllers such as SrvMgr, BitcoinDMgr, etc.
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

    /// thread-safe wrapper around stats().
    Stats statsSafe() const;

protected:
    /// Return controller-specific stats -- to be used later if we implement some sort of query mechanism
    /// for showing stats to clients and/or server admins.
    /// For now stub implementation returns an empty map.
    /// Note this function is unsafe and meant to be called within the Mgr's thread.
    /// Outside client code should use public statsSafe(), which wraps the below call in a
    /// thread-safe call, so that derived classes don't have to worry about thread safety and
    /// can just implement this function by examining their own private data to populate the map
    /// without locks.
    virtual Stats stats() const;
};

#endif // MMMGR_H
