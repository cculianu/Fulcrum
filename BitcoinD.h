#ifndef BITCOIND_H
#define BITCOIND_H

#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"

#include <QHostAddress>

#include <array>
#include <memory>
#include <set>

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

    using ResultsF = std::function<void(const RPC::Message &response)>;
    using ErrorF = ResultsF; // identical to ResultsF above except the message passed in is an error="" message.
    using FailF = std::function<void(const RPC::Message::Id &origId, const QString & failureReason)>;

    /// This is safe to call from any thread.
    /// Internally it dispatches messages to `this` obejct's thread. Results/Error/Fail functions are called in the
    /// context of the `sender` object's thread. Returns immediately regardless of which thread context it's called in,
    /// with one of the 3 following being called later, in the thread context of `sender`, when results/errors/failure
    /// is determined:
    /// - ResultsF will be called exactly once on success returning the reults encapsulated in an RPC::Message
    /// - If BitcoinD generated an error response, ErrorF will be called exactly once with the error wrapped in an
    ///   RPC::Message
    /// - If some other error occurred (such as timeout, or BitcoinD not connected, or connection lost, etc), FailF
    ///   will be called exactly once with a string message.
    void submitRequest(QObject *sender, const RPC::Message::Id &id, const QString & method, const QVariantList & params,
                       const ResultsF & = ResultsF(), const ErrorF & = ErrorF(), const FailF & = FailF());

signals:
    void gotFirstGoodConnection(quint64 bitcoindId); // emitted whenever the first bitcoind after a "down" state (or after startup) gets its first good status (after successful authentication)
    void allConnectionsLost(); // emitted whenever all bitcoind rpc connections are down.

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

    static constexpr int miniTimeout = 333, tinyTimeout = 167, medTimeout = 500, longTimeout = 1000;

    std::set<quint64> goodSet; ///< set of bitcoind's (by id) that are `isGood` (connected, authed). This set is updated as we get signaled from BitcoinD objects. May be empty. Has at most N_CLIENTS elements.

    std::unique_ptr<BitcoinD> clients[N_CLIENTS];

    quint64 lastBitcoinDUsed = NO_ID;
    BitcoinD *getBitcoinD(); ///< may return nullptr if none are up. Otherwise does a round-robin of the ones present to grab one. to be called only in this thread.
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
    std::atomic_bool badAuth = false, needAuth = true;
};


#endif // BITCOIND_H
