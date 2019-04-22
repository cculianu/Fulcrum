#ifndef APP_H
#define APP_H

#include <QCoreApplication>

class Logger;
class EXMgr;

class App : public QCoreApplication
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App();

    Logger *logger() { return _logger; }

signals:

public slots:

private:
    Logger *_logger = nullptr;
    EXMgr *exmgr = nullptr;

    void startup();
    void cleanup();
};

inline App *app() { return dynamic_cast<App *>(qApp); }

#endif // APP_H
