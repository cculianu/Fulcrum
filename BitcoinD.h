#ifndef BITCOIND_H
#define BITCOIND_H

#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"

#include <QHostAddress>

#include <memory>

class BitcoinD;

class BitcoinDMgr : public Mgr, public IdMixin, public ThreadObjectMixin, protected TimersByNameMixin
{
    Q_OBJECT
public:
    BitcoinDMgr(const QHostAddress &host, quint16 port, const QString &user, const QString &pass);
    ~BitcoinDMgr() override;

    void startup() override; ///< from Mgr
    void cleanup() override; ///< from Mgr

    static constexpr int N_CLIENTS = 2;

protected:
    Stats stats() const override; // from Mgr

    QObject * qobj() override; ///< from ThreadObjectMixin & TimersByNameMixin

private:
    const QHostAddress host;
    const quint16 port;
    const QString user, pass;

    std::unique_ptr<BitcoinD> clients[N_CLIENTS];
};

class BitcoinD : public RPC::HttpConnection, public ThreadObjectMixin, protected TimersByNameMixin
{
    Q_OBJECT

public:
    explicit BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass);
    ~BitcoinD() override;

    using ThreadObjectMixin::start;
    using ThreadObjectMixin::stop;

    /// Not thread safe. Be sure to call this in this object's thread.
    QVariantMap getStats() const;

signals:
    void connected(BitcoinD *me);

protected:
    void on_started() override;
    void on_connected() override;

    void do_ping() override; // testing

    void reconnect();

    QObject * qobj() override; ///< from ThreadObjectMixin & TimersByNameMixin

private:
    const QHostAddress host;
    const quint16 port;
    std::atomic_bool badAuth = false;
};


#endif // BITCOIND_H
