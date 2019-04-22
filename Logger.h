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

    /// returns true if the logger is logging to a tty (and thus supports ANSI color codes, etc)
    virtual bool isaTTY() const { return false; }

signals:
    void log(const QString & line); ///< call this or emit it to log a line

public slots:
    virtual void gotLine(const QString &) = 0;
};

class ConsoleLogger : public Logger
{
public:
    explicit ConsoleLogger(QObject *parent = nullptr, bool stdOut = true);

    bool isaTTY() const override;

public:
    void gotLine(const QString &) override;
private:
    bool stdOut = true;
};

#endif // LOGGER_H
