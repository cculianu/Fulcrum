#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "BitcoinD.h"
#include "Options.h"
#include "SrvMgr.h"

class Controller : public Mgr
{
public:
    explicit Controller(const std::shared_ptr<Options> & options, QObject *parent = nullptr);
    ~Controller() override;

    void startup() override; ///< may throw
    void cleanup() override;

protected:
    Stats stats() const override;

private:
    const std::shared_ptr<Options> options;
    std::unique_ptr<SrvMgr> srvmgr;
    std::unique_ptr<BitcoinDMgr> bitcoindmgr;
};

#endif // CONTROLLER_H
