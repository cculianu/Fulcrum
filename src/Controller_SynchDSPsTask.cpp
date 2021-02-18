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
#include "Controller_SynchDSPsTask.h"
#include "Util.h"

#include <utility>

namespace {
    /// We disabled updates (which grow the descendants set) since they are inefficient (too much network back and
    /// forth to constantly poll data that mostly never changes). Instead, we grow the descendants set directly in
    /// Mempool.cpp addNewTxs() more efficiently. We grow the descendants set there as we add new tx's.
    inline constexpr bool UpdatingEnabled = false;
    /// We may elect to disable dropping dsps from here. Rationale: bitcoind may restart and lose dsps, but they are
    /// still relevant.  We instead may want to rely on dropping dsps when the actual "owning" txs go out of "scope"
    /// (that is, they get confirmed in a block or evicted from mempool).  Mempool.cpp already takes care of removing
    /// dsps for dropped/confirmed tx's for us. Perhaps we should set this to false and rely on that for the dsp
    /// lifecycle. The reason we may want to do it that way is that a DSP that was once associated with an in-mempool tx
    /// will always be relevant, regardless of bitcoind's inability to remember it existed (after a restart).
    inline constexpr bool DropsEnabled = true;
    /// We may want to set this to false -- notifying clients of a drop may have little practicle utility for the same
    /// rationale as given above: a valid dsproof is always relevant.  The fact that we lost track of it doesn't mean
    /// the client shouldn't still be wary of the potential for a double-spend.
    inline constexpr bool DropsNotifyEnabled = true;
}

SynchDSPsTask::SynchDSPsTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag)
    : CtlTask(ctl_, "SynchDSPs"), storage(storage), notifyFlag(notifyFlag)
{
    // force emit of success or errored to lead to immediate state=End assignment as a side-effect
    connect(this, &CtlTask::success, this, [this]{state = End;});
    connect(this, &CtlTask::errored, this, [this]{state = End;});
}

SynchDSPsTask::~SynchDSPsTask() {
    stop();

    if (!dspsDownloaded.empty() || !downloadsFailed.empty() || !dspsUpdated.empty() || !updatesFailed.empty() || !txsAffected.empty()) {
        if (Debug::isEnabled()) {
            Debug d;
            d << objectName() << ": downloaded: " << dspsDownloaded.size() << ", failed: " << downloadsFailed.size();
            if constexpr (UpdatingEnabled)
                    d << ", updated: " << dspsUpdated.size() << ", updated failed: " << updatesFailed.size();
            d << ", txsAffecteed: " << txsAffected.size() << ", dsp count now: " << storage->mempool().first.dsps.size()
              << ", elapsed: " << elapsed.msecStr() << " msec";
        }
    } else if (elapsed.msec() >= 50) {
        // if total runtime for task >=50ms, log for debug
        DebugM(objectName(), " elapsed: ", elapsed.msecStr(), " msec");
    }

    if (notifyFlag.load() && !txsAffected.empty()) {
        // TODO here: emit signal related to txs added / removed...
    }
}

void SynchDSPsTask::process()
{
    switch (state) {
    case WaitingForDSPList: // this state is suprious, ignore
        DebugM("spurious WaitingForDSPList wakeup in ", __PRETTY_FUNCTION__);
        [[fallthrough]];
    case End: return; // end state means ignore further process() events coming in
    case GetDSPList: doGetDSPList(); break;
    case DownloadingNewDSPs: doDownloadNewDSPs(); break;
    case ProcessDownloads: doProcessDownloads(); break;
    case UpdatingExistingDSPs: doUpdateExistingDSPs(); break;
    }
}

void SynchDSPsTask::doGetDSPList()
{
    state = WaitingForDSPList;
    submitRequest("getdsprooflist", {0}, [this](const RPC::Message & resp){
        if (state != WaitingForDSPList) {
            Error() << "FIXME: Spurious getdsprooflist reply, ignoring... ";
            return;
        }
        const auto knownDSPs = Util::keySet<DSPs::DspHashSet>(storage->mempool().first.dsps.getAll()); // this is guarded access, lock held until statement end (C++ temporary lifetime rules)
        DSPs::DspHashSet droppedDSPs;
        if constexpr (DropsEnabled)
            // if drops are enabled: start off assuming *all* are dropped until proven otherwise
            droppedDSPs = knownDSPs;
        // scan thru all downloaded dsp hashes and figure out what's new and what needs refresh
        for (const auto & var : resp.result().toList()) {
            const DspHash hash = DspHash::fromHex(var.toString());
            if (!hash.isValid()) {
                // should never happen
                Warning() << "Got an invalid dsp hash from bitcoind: \"" << var.toString() << "\"";
                continue;
            }
            if (!knownDSPs.count(hash)) {
                auto [it, inserted] = dspsNeedingDownload.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple());
                if (!inserted) {
                    // should never happen
                    Warning() << "Got dupe dsp hash in results from bitcoin for dsp: " << hash.toHex();
                    continue;
                }
                DSProof & dspNew = it->second;
                dspNew.hash = it->first; // re-use same QByteArray memory (copy-on-write)
            } else {
                // flag this one for needing refresh now (but only if updating is enabled)
                if constexpr (UpdatingEnabled)
                    dspsNeedingUpdate.insert(hash);
                // remove from drop set
                if constexpr (DropsEnabled)
                    droppedDSPs.erase(hash);
            }
        }
        if constexpr (DropsEnabled) {
            // handle drops, if any
            if (!droppedDSPs.empty()) {
                DebugM("dropped dsps:", droppedDSPs.size());
                // flag them as dropped now -- remove from dsp store
                unsigned ctr = 0;
                {
                    auto [mempool, lock] = storage->mutableMempool(); // exclusive lock
                    for (const auto &hash : droppedDSPs) {
                        const auto *proof = mempool.dsps.get(hash);
                        if (!proof) { Error() << "FIXME: dsphash not found: " << hash.toHex(); continue; }
                        if constexpr (DropsNotifyEnabled) {
                            for (const auto & txhash : proof->descendants) {
                                txsAffected.insert(txhash);
                                ++ctr;
                            }
                        } else {
                            ctr += proof->descendants.size();
                        }
                        mempool.dsps.rm(hash); // `proof` pointer invalidated after this line
                    }
                }
                if constexpr (DropsNotifyEnabled)
                    DebugM("dsp<->tx links dropped: ", ctr, ", num txs: ", txsAffected.size());
                else
                    DebugM("dsp<->tx links dropped: ", ctr);
            }
        }
        // if we have any new dsps needing download, proceed to download state
        if (!dspsNeedingDownload.empty()) {
            //DebugM("new dsps: ", dspsNeedingDownload.size());
            dspDlsExpected = dspsNeedingDownload.size();
            state = DownloadingNewDSPs;
            AGAIN();
        } else if (!dspsNeedingUpdate.empty()) { // otherwise if we have dsps needing refresh, skip to that state
            //DebugM("no new dsps, refreshing existing: ", dspsNeedingUpdate.size());
            state = UpdatingExistingDSPs;
            AGAIN();
        } else {
            // dsp results from bitcoind is empty and our dsp set is empty, just end the task
            emit success();
        }
    });
}

void SynchDSPsTask::dlNext(bool phase2, std::shared_ptr<DSPs::DspMap::node_type> node)
{
    const auto &hash = node->key();
    submitRequest("getdsproof", {hash.toHex(), !phase2 ? 0 : 2}, [this, node, phase2](const RPC::Message &reply)  {
        const auto &hash = node->key();
        auto &proof = node->mapped();
        try {
            if (UNLIKELY(proof.hash != hash)) // paranoia to enforce invariant
                throw InternalError("INTERNAL ERROR: dsproof hash in proof doesn't match its onw map key! FIXME!");
            const QVariantMap vm = reply.result().toMap();
            if (!phase2) {
                // keys we are reading: "hex", "txid"
                const QByteArray &serdata = proof.serializedProof = Util::ParseHexFast(vm.value("hex").toString().toUtf8());
                const TxHash &txid = proof.txHash = Util::ParseHexFast(vm.value("txid").toString().toUtf8());
                const DspHash chk = DspHash::fromSerializedProof(serdata);
                if (chk != hash || !chk.isValid() || txid.length() != HashLen)
                    throw Exception("basic phase 1 sanity checks failed");
                // data ok, keep going to phase2
                dlNext(true, node);
            } else {
                // phase 2: keys we are reading: "dspid", "txid", "outpoint", "descendants"
                const DspHash chk = DspHash::fromHex(vm.value("dspid").toString());
                const TxHash txidChk = Util::ParseHexFast(vm.value("txid").toString().toUtf8());
                const auto op = vm.value("outpoint").toMap();
                proof.txo.txHash = Util::ParseHexFast(op.value("txid").toString().toUtf8());
                bool ok{};
                proof.txo.outN = op.value("vout").toUInt(&ok);;
                const auto descs = vm.value("descendants").toStringList();
                if (!ok || chk != hash || txidChk != proof.txHash || proof.txo.txHash.length() != HashLen || descs.isEmpty())
                    throw Exception(QString("basic phase 2 sanity checks failed: ok: %1, chk: %2, hash: %3, proofTxHash: %4, "
                                            "txidChk: %5, txoTxHash: %6, descs: %7")
                                    .arg(int(ok)).arg(QString(chk.toHex())).arg(QString(hash.toHex())).arg(QString(proof.txHash.toHex()))
                                    .arg(QString(txidChk.toHex())).arg(QString(proof.txo.txHash.toHex())).arg(descs.size()));
                // build descendants set
                for (const auto &desc : descs) {
                    const auto txid = Util::ParseHexFast(desc.toUtf8());
                    if (txid.length() != HashLen)
                        throw Exception(QString("bad txid \"%1\" in descendants set").arg(desc));
                    proof.descendants.insert(txid);
                }
                if (!proof.descendants.count(proof.txHash))
                    throw Exception(QString("missing proof's associated txid \"%1\" in the descendants set").arg(QString(proof.txHash.toHex())));
                DebugM("dsp ", hash.toHex(), " downloaded ok, descendants: ", proof.descendants.size());
                dspsDownloaded.insert(std::move(*node)); // success! phase2 complete...
                AGAIN();
            }
        } catch (const std::exception &e) {
            Warning() << "bad dsp " << hash.toHex() << ", (exc: " << e.what() << "), ignoring dsp ...";
            downloadsFailed.insert(hash);
            AGAIN();
        }
    },
    [this, hash, phase2](const RPC::Message &){
        // ignore errors, keep going
        DebugM("failed to download dsp ", hash.toHex(), " phase ", 1+int(phase2), ", ignoring dsp ...");
        downloadsFailed.insert(hash);
        AGAIN();
    });
}

void SynchDSPsTask::doDownloadNewDSPs()
{
    if (!dspsNeedingDownload.empty())
        dlNext(false, dspsNeedingDownload.extract(dspsNeedingDownload.begin()));
    else if (const auto sum = dspsDownloaded.size() + downloadsFailed.size(); sum == dspDlsExpected) {
        // end this state, move on to next
        state = UpdatingExistingDSPs;
        AGAIN();
    } else {
        // should never happen
        Error() << "INTERNAL ERROR: expceted to download " << dspDlsExpected << " dsps, instead downloaded: " << sum;
        emit errored();
    }
}

void SynchDSPsTask::doUpdateExistingDSPs()
{
    if (dspsNeedingUpdate.empty()) {
        // nothing left, proceed to next state
        state = ProcessDownloads;
        AGAIN();
        return;
    }

    const DspHash hash = dspsNeedingUpdate.extract(dspsNeedingUpdate.begin()).value();

    submitRequest("getdsproof", {hash.toHex(), 2}, [this, hash](const RPC::Message &reply)  {
        const QVariantMap vm = reply.result().toMap();
        const DspHash chk = DspHash::fromHex(vm.value("dspid").toString());
        const TxHash txidChk = Util::ParseHexFast(vm.value("txid").toString().toUtf8());
        const auto descs = vm.value("descendants").toStringList();
        unsigned ctrDescs = 0, ctrNewAffected = 0;
        // grab exclusive lock to do this
        try {
            auto [mempool, lock] = storage->mutableMempool();
            Tic t0;
            auto *dsp = mempool.dsps.get(hash);

            if (!dsp || chk != hash || txidChk != dsp->txHash || descs.isEmpty())
                throw Exception(QString("basic sanity check failed for update of dsp %1").arg(QString(hash.toHex())));
            for (const auto &desc : descs) {
                const TxHash txid = Util::ParseHexFast(desc.toUtf8());
                if (txid.length() != HashLen) {
                    Warning() << __func__ << ": txid \"" << desc << "\" is not valid, ignoring ...";
                    continue;
                }
                if (!dsp->descendants.count(txid) && mempool.txs.count(txid)) {
                    ++ctrDescs;
                    ctrNewAffected += txsAffected.insert(txid).second;
                    if (!mempool.dsps.addTx(hash, txid))
                        // this should never happen..
                        Warning() << "Failed to add txid " << txid.toHex() << " to dsp " << hash.toHex();
                }
            }
            if (ctrDescs) {
                dspsUpdated.insert(hash); // only add to dspsUpdated set if there was a change
                DebugM("updated dsp ", hash.toHex(), " new descendants: ", ctrDescs, ", new txids affected: ", ctrNewAffected,
                       ", descendants now: ", dsp->descendants.size(), " (exc. lock held for: ", t0.msecStr(), " msec)");
            }
        } catch (const std::exception &e) {
            DebugM("failed to update dsp ", hash.toHex(), "(exc: ", e.what(), ") ignoring error ...");
            updatesFailed.insert(hash);
        }
        AGAIN(); //< regrdless of success or failure, keep going...
    },
    [this, hash](const RPC::Message &){
        // ignore errors, keep going
        DebugM("failed to update dsp ", hash.toHex(), " ignoring error ...");
        updatesFailed.insert(hash);
        AGAIN();
    });
}

void SynchDSPsTask::doProcessDownloads()
{
    unsigned ctr = 0, notAdded = 0;
    {
        auto [mempool, lock] = storage->mutableMempool();
        for (auto & [hash, proof] : dspsDownloaded) {
            if (!mempool.txs.count(proof.txHash)) {
                // unknown txid (it's new and we haven't seen it in SynchMempoolTask yet!)
                DebugM("skipping dsp ", hash.toHex(), " because its associated txid ", proof.txHash.toHex(),
                       " is not yet known to us");
                ++notAdded;
                continue;
            }

            decltype(proof.descendants) skipped;
            for (const auto & txid : proof.descendants) {
                if (!mempool.txs.count(txid))
                    skipped.insert(txid);
                else
                    ctr += txsAffected.insert(txid).second; // flag txids affected
            }
            if (!skipped.empty()) {
                DebugM("skipped ", skipped.size(), " descendant txs for dsp ", hash.toHex(), " (unknown txids)");
                for (const auto &txid: skipped)
                    proof.descendants.erase(txid);
            }
            try {
                if (! mempool.dsps.add(std::move(proof)) ) // this itself may throw
                    throw InternalError("DSPs::add() returned false"); // but also we will throw if it returns false since it indicates a bug in code
            } catch (const std::exception &e) {
                // this should never happen, but since the above can throw, it's best to guard against it.
                Error() << "INTERNAL ERROR: failed to add dsp " << hash.toHex() << ", exception: " << e.what();
            }
        }
    }
    if (auto total = long(dspsDownloaded.size()) - long(notAdded); total > 0)
        DebugM("added ", total, " new dsps with ", ctr, " newly affected txs");
    emit success(); // final state
}
