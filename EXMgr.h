#ifndef ECMGR_H
#define ECMGR_H

#include <QObject>
#include <QList>

class EXClient;

class EXMgr : public QObject
{
    Q_OBJECT
public:
    explicit EXMgr(QObject *parent = nullptr);
    virtual ~EXMgr();
signals:

public slots:
private:
    void loadServers();
    QList<EXClient *> clients;
};

#endif // ECMGR_H
