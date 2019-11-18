#ifndef LOGGER_H
#define LOGGER_H

#include <QObject>
#include <QString>

class Logger : public QObject
{
    /** Abstract base class for a line-based logger */
    Q_OBJECT
public:
    explicit Logger(QObject *parent = nullptr);
    virtual ~Logger();

    enum Level {
        Info = 0, Warning, Critical, Fatal, Debug
    };

    /// returns true if the logger is logging to a tty (and thus supports ANSI color codes, etc)
    virtual bool isaTTY() const { return false; }

signals:
    void log(int level, const QString & line); ///< call this or emit it to log a line

public slots:
    virtual void gotLine(int level, const QString &) = 0;
};

class ConsoleLogger : public Logger
{
public:
    explicit ConsoleLogger(QObject *parent = nullptr, bool stdOut = true);

    bool isaTTY() const override;

public:
    void gotLine(int level, const QString &) override;
private:
    bool stdOut = true;
};

/// On Windows this just prints to stdout. On Unix, calls syslog()
class SysLogger : public ConsoleLogger
{
#ifdef Q_OS_UNIX
public:
    SysLogger(QObject *parent = nullptr);
    void gotLine(int level, const QString &) override;
    bool isaTTY() const override { return !opened && ConsoleLogger::isaTTY(); }
private:
    static bool opened;
#else
public:
    using ConsoleLogger::ConsoleLogger;
#endif
};

#endif // LOGGER_H
