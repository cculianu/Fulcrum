#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "BitcoinD.h"
#include "Mixins.h"
#include "Options.h"
#include "SrvMgr.h"

class Controller : public Mgr, public ThreadObjectMixin, public TimersByNameMixin
{
public:
    explicit Controller(const std::shared_ptr<Options> & options);
    ~Controller() override;

    void startup() override; ///< may throw
    void cleanup() override;

protected:
    Stats stats() const override;

protected slots:
    void process(); ///< generic callback to advance state

private:
    const std::shared_ptr<Options> options;
    std::unique_ptr<SrvMgr> srvmgr;
    std::unique_ptr<BitcoinDMgr> bitcoindmgr;

    struct StateMachine;
    std::unique_ptr<StateMachine> sm;
};

#endif // CONTROLLER_H
