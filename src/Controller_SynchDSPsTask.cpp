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

SynchDSPsTask::SynchDSPsTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag)
    : CtlTask(ctl_, "SynchDSPs"), storage(storage), notifyFlag(notifyFlag)
{
    // force emit of success or errored to lead to immediate state=End assignment as a side-effect
    connect(this, &CtlTask::success, this, [this]{state = End;});
    connect(this, &CtlTask::errored, this, [this]{state = End;});
}

SynchDSPsTask::~SynchDSPsTask() {
    stop();

    if (!dspsDownloaded.empty() || !dspsFailed.empty())
        DebugM(objectName(), ": downloaded: ", dspsDownloaded.size(), ", failed: ", dspsFailed.size(), " in ", elapsed.msecStr(), " msec");
    if (notifyFlag.load() /* && ... More stuff */) {
        // TODO here: emit signal related to txs added / removed...
    }

    //if (elapsed.secs() >= 1.0) {
    //    // if total runtime for task >1s, log for debug
    //    DebugM(objectName(), " elapsed total: ", elapsed.secsStr(), " secs");
    //}
}

void SynchDSPsTask::process()
{
    switch (state) {
    case End: return; // end state means ignore further process() events coming in
    case GetDSPList: doGetDSPList(); break;
    case DownloadingNewDSPs: doDownloadNewDSPs(); break;
    // all below are TODO
    case WaitingForDSPList:
    case WaitingforRefreshDSPInfo:
    case RefreshDSPInfo:
    case ProcessDownloads:
        emit success(); // TODO: this is temporary while testing
        break;
    }
}

void SynchDSPsTask::doGetDSPList()
{
    state = WaitingForDSPList;
    dspsNeedingDownload.clear(); // paranoia
    dspsNeedingRefresh.clear(); // paranoia
    submitRequest("getdsprooflist", {0}, [this](const RPC::Message & resp){
        if (state != WaitingForDSPList) {
            Error() << "FIXME: Spurious getdsprooflist reply, ignoring... ";
            return;
        }
        const auto knownDSPs = Util::keySet<DSPs::DspHashSet>(storage->mempool().first.dsps.getAll()); // this is guarded access, lock held until statement end (C++ temporary lifetime rules)
        auto droppedDSPs = knownDSPs; // start off assuming *all* are dropped until proven otherwise
        // scan thru all downloaded dsp hashes and figure out what's new and what needs refresh
        for (const auto & var : resp.result().toList()) {
            const DspHash hash = DspHash::fromHex(var.toString());
            if (!hash.isValid()) {
                // should never happen
                Warning() << "Got an invalid dsp hash from bitcoind: \"" << var.toString() << "\"";
                continue;
            }
            if (!knownDSPs.count(hash)) {
                auto [it, inserted] = dspsNeedingDownload.emplace(
                        std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple());
                if (!inserted) {
                    // should never happen
                    Warning() << "Got dupe dsp hash in results from bitcoin for dsp: " << hash.toHex();
                    continue;
                }
                DSProof & dspNew = it->second;
                dspNew.hash = it->first; // re-use same QByteArray memory (copy-on-write)
            } else {
                // flag this one for needing refresh now
                dspsNeedingRefresh.emplace(hash);
                droppedDSPs.erase(hash);
            }
        }
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
                    for (const auto & txhash : proof->descendants)
                    { txsLostDsp[txhash].emplace(hash); ++ctr; }
                    mempool.dsps.rm(hash); // `proof` pointer invalidated after this line
                }
            }
            DebugM("dsp<->tx links dropped: ", ctr, ", num txs: ", txsLostDsp.size());
        }
        // if we have any new dsps needing download, proceed to download state
        if (!dspsNeedingDownload.empty()) {
            DebugM("new dsps: ", dspsNeedingDownload.size());
            dspDlsExpected = dspsNeedingDownload.size();
            state = DownloadingNewDSPs;
            AGAIN();
        } else if (!dspsNeedingRefresh.empty()) { // otherwise if we have dsps needing refresh, skip to that state
            DebugM("no new dsps, refreshing existing: ", dspsNeedingRefresh.size());
            state = RefreshDSPInfo;
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
    submitRequest("getdsproof", {hash.toHex(), phase2 ? 2 : 0}, [this, node, phase2](const RPC::Message &reply)  {
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
            dspsFailed.insert(hash);
            AGAIN();
        }
    },
    [this, hash, phase2](const RPC::Message &){
        // ignore errors, keep going
        DebugM("failed to download dsp ", hash.toHex(), " phase ", phase2 ? "2" : "1", ", ignoring dsp ...");
        dspsFailed.insert(hash);
        AGAIN();
    });
}

void SynchDSPsTask::doDownloadNewDSPs()
{
    if (!dspsNeedingDownload.empty())
        dlNext(false, dspsNeedingDownload.extract(dspsNeedingDownload.begin()));
    else if (const auto sum = dspsDownloaded.size() + dspsFailed.size(); sum == dspDlsExpected) {
        // end state, move on
        if (!dspsNeedingRefresh.empty()) {
            state = RefreshDSPInfo;
            AGAIN();
        } else if (!dspsNeedingDownload.empty()){
            // finished downloading, move on to process downloads
            state = ProcessDownloads;
            AGAIN();
        } else {
            // nothing left to do, success!
            state = End;
            emit success();
        }
    } else if (sum > dspDlsExpected) {
        // should never happen
        Error() << "INTERNAL ERROR: expceted to download " << dspDlsExpected << " dsps, instead downloaded: " << sum;
        emit errored();
    }
}
