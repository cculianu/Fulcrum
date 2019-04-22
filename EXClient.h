#ifndef EXCLIENT_H
#define EXCLIENT_H

#include <QObject>
#include <QThread>
class QTcpSocket;
class EXMgr;

class EXClient : public QObject
{
    Q_OBJECT
public:
    explicit EXClient(EXMgr *mgr,
                      const QString & host,
                      int tcpPort, int sslPort);
    ~EXClient();

protected:
    friend class EXMgr;

    enum Status {
        Never = 0,
        Connected,
        NotConnected
    };

    int status = Never;

    QThread thread;

    void start();
    void stop();

    QString host;
    int tport = 0, sport = 0;

signals:

public slots:

private:
    EXMgr *mgr = nullptr;
    QTcpSocket *socket = nullptr;
};

#endif // EXCLIENT_H
