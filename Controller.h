#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <QObject>
#include <QMap>
/// Abstract base class of all subsystem controllers such as EXMgr, etc.
/// These get created by the App on startup, based on config.
class Controller : public QObject
{
    Q_OBJECT
public:
    explicit Controller(QObject *parent = nullptr);
    virtual ~Controller();
    virtual void startup() = 0; ///< NB: controllers may throw Exception here, so catch it and abort if that happens.
    virtual void cleanup() = 0;

    typedef QMap<QString, QString> Stats;

    /// Return controller-specific stats -- to be used later if we implement some sort of query mechanism
    /// for showing stats to clients and/or server admins.
    /// For now stub implementation returns an empty map.
    virtual Stats stats() const;
};

#endif // CONTROLLER_H
