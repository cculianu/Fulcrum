#ifndef APP_H
#define APP_H

#include <QCoreApplication>
#include <atomic>
#include <QHostAddress>
#include <QList>

class Logger;
class EXMgr;

class App : public QCoreApplication
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App();

    Logger *logger() { return _logger; }

    struct Options {
        std::atomic_bool verboseDebug = false; ///< gets set to true on debug builds
        std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

        typedef QPair<QHostAddress, quint16> Interface;
        QList<Interface> interfaces; ///< interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT
        QString serversFile = ":/file/servers.json";
    };
    Options options;

signals:

public slots:

private:
    Logger *_logger = nullptr;
    EXMgr *exmgr = nullptr;

    void startup();
    void cleanup();

    void parseArgs();
};

inline App *app() { return qApp ? dynamic_cast<App *>(qApp) : nullptr; }

#endif // APP_H
