//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

#include "Controller.h"
#include "DSProof.h"
#include "Mempool.h"
#include "Storage.h"

#include <atomic>
#include <memory>
#include <utility>

/// This runs after the SynchMempoolTask to download new DSProofs and also update existing proofs
/// with new descendant info. This task is only run if the bitcoind we are connected to supports
/// the `getdsprooflist` and `getdsproof` RPC methods.
class SynchDSPsTask : public CtlTask {
public:
    SynchDSPsTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag);
    ~SynchDSPsTask() override;

protected:
    void process() override;

private:
    const std::shared_ptr<Storage> storage;
    const std::atomic_bool & notifyFlag;

    enum State {
        GetDSPList, WaitingForDSPList,
        DownloadingNewDSPs,
        ProcessDownloads,
        End,
    };

    State state = GetDSPList;

    Mempool::TxHashSet txsAffected;
    DSPs::DspMap dspsNeedingDownload, dspsDownloaded;
    unsigned dspDlsExpected = 0;
    DSPs::DspHashSet downloadsFailed;

    void doGetDSPList();
    void doDownloadNewDSPs();
    void dlNext(bool phase2, std::shared_ptr<DSPs::DspMap::node_type> node);
    void dlNext(bool phase2, DSPs::DspMap::node_type && node) { dlNext(phase2, std::make_shared<DSPs::DspMap::node_type>(std::move(node))); }
    void doProcessDownloads();
};
