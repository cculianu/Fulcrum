//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Controller/SynchDSPsTask.h"
#include "SubsMgr.h"
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

    if (!dspsDownloaded.empty() || !downloadsFailed.empty() || !txsAffected.empty()) {
        DebugM(objectName(), ": downloaded: ", dspsDownloaded.size(),", failed: ", downloadsFailed.size(),
               ", txsAffecteed: ", txsAffected.size(), ", dsp count now: ", storage->mempool().first.dsps.size(),
               ", elapsed: ", elapsed.msecStr(), " msec");
    } else if (elapsed.msec() >= 50) {
        // if total runtime for task >=50ms, log for debug
        DebugM(objectName(), " elapsed: ", elapsed.msecStr(), " msec");
    }

    if (notifyFlag.load() && !txsAffected.empty()) {
        // tell any subscribed clients
        storage->dspSubs()->enqueueNotifications(std::move(txsAffected));
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
            }
        }
        // if we have any new dsps needing download, proceed to download state
        if (!dspsNeedingDownload.empty()) {
            //DebugM("new dsps: ", dspsNeedingDownload.size());
            dspDlsExpected = dspsNeedingDownload.size();
            state = DownloadingNewDSPs;
            AGAIN();
        } else {
            // dsp results from bitcoind -- no new dsps, just end the task
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
        state = ProcessDownloads;
        AGAIN();
    } else {
        // should never happen
        Error() << "INTERNAL ERROR: expceted to download " << dspDlsExpected << " dsps, instead downloaded: " << sum;
        emit errored();
    }
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
