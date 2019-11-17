#ifndef BITCOIND_H
#define BITCOIND_H

#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"

#include <QHostAddress>

#include <memory>

class BitcoinD;

class BitcoinDMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin
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

protected slots:
    // connected to BitcoinD gotMessage signal
    void on_Message(quint64 bitcoindId, const RPC::Message &msg);
    // connected to BitcoinD gotErrorMessage signal
    void on_ErrorMessage(quint64 bitcoindId, const RPC::Message &msg);

private:
    const QHostAddress host;
    const quint16 port;
    const QString user, pass;

    std::unique_ptr<BitcoinD> clients[N_CLIENTS];
};

class BitcoinD : public RPC::HttpConnection, public ThreadObjectMixin /* NB: also inherits TimersByNameMixin via AbstractConnection base */
{
    Q_OBJECT

public:
    explicit BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass);
    ~BitcoinD() override;

    using ThreadObjectMixin::start;
    using ThreadObjectMixin::stop;

    bool isGood() const override; ///< from AbstractConnection -- returns true iff Status==Connected AND auth confirmed ok.

signals:
    /// This is emitted immediately after successful socket connect but before auth. After this signal, client code
    /// can expect either one of the two following signals to be emitted: either the authenticated() signal below,
    /// or the base class's authFailure() signal.
    void connected(BitcoinD *me);
    void authenticated(BitcoinD *me); ///< This is emitted after we have successfully connected and auth'd.

protected:
    void on_started() override;
    void on_connected() override;

    void do_ping() override; // testing

    void reconnect();

    /// Not thread safe. Be sure to call this in this object's thread. Override from StatsMixin
    Stats stats() const override;

private:
    void connectMiscSignals(); ///< some signals/slots to self to do bookkeeping

    const QHostAddress host;
    const quint16 port;
    bool badAuth = false, needAuth = true;
};


#endif // BITCOIND_H
