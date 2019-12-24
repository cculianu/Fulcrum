#ifndef SRVMGR_H
#define SRVMGR_H

#include "Mgr.h"
#include "Options.h"

#include <list>
#include <memory>

class BitcoinDMgr;
class Server;
class Storage;

class SrvMgr : public Mgr
{
    Q_OBJECT
public:
    explicit SrvMgr(const std::shared_ptr<Options> & options,
                    std::shared_ptr<Storage> storage, std::shared_ptr<BitcoinDMgr> bitcoindmgr,
                    QObject *parent = nullptr);
    ~SrvMgr() override;
    void startup() override; // may throw on error
    void cleanup() override;

    int nServers() const { return int(servers.size()); }

signals:
    /// Notifies all blockchain.headers.subscribe'd clients for the entire server about a new header.
    /// (normally connected to the Controller::newHeader signal).
    void newHeader(unsigned height, const QByteArray &header);

protected:
    Stats stats() const override;

private:
    void startServers();
    std::shared_ptr<Options> options;
    std::shared_ptr<Storage> storage;
    std::shared_ptr<BitcoinDMgr> bitcoindmgr;
    std::list<std::unique_ptr<Server>> servers;
};

#endif // SRVMGR_H
