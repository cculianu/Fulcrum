//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Mempool.h"
#include "Util.h"

#include <algorithm>
#include <cassert>
#include <functional>
#include <map>
#include <optional>
#include <utility>

Mempool::ConsistencyError::~ConsistencyError() {} // for vtable

void Mempool::clear() {
    txs.clear();
    hashXTxs.clear();
    dsps.clear(); // <-- this always frees capacity
    if (optPrefixTable) optPrefixTable->clear();
    txs.rehash(0); // this should free previous capacity
    hashXTxs.rehash(0);
}

auto Mempool::calcCompactFeeHistogram(unsigned binSizeBytes) const -> FeeHistogramVec
{
    // This algorithm is taken from:
    // https://github.com/spesmilo/electrumx/blob/bbd985a95db63cada13254bb766f174e9ab674d0/electrumx/server/mempool.py#L154
    FeeHistogramVec ret;
    std::map<unsigned, unsigned, std::greater<unsigned>> histogram; // sorted map, descending order by key

    for (const auto & [txid, tx] : txs) {
        if (tx->fee < bitcoin::Amount::zero()) continue; // skip negative fees (coinbase txn, etc)
        const auto feeRate = unsigned(tx->fee / bitcoin::Amount::satoshi()) // sats
                             / std::max(tx->vsizeBytes, 1u); // per vbyte
        histogram[feeRate] += tx->vsizeBytes; // accumulate size by feeRate
    }

    // Now, compact the bins
    ret.reserve(8);
    unsigned cumSize = 0;
    double binSize = static_cast<double>(binSizeBytes);
    std::optional<unsigned> prevFeeRate;

    for (const auto & [feeRate, size] : histogram) {
        // If there is a big lump of txns at this specific size,
        // add the previous item now (if not added already)
        if (double(size) > 2.0 * binSize && prevFeeRate && cumSize > 0) {
            ret.emplace_back(*prevFeeRate, cumSize);
            cumSize = 0;
            binSize *= 1.1;
        }
        // Now work on perhaps adding this item
        cumSize += size;
        if (cumSize > binSize) {
            ret.emplace_back(feeRate, cumSize);
            cumSize = 0;
            binSize *= 1.1;
        }
        prevFeeRate = feeRate;
    }
    ret.shrink_to_fit(); // save memory
    return ret;
}

auto Mempool::addNewTxs(ScriptHashesAffectedSet & scriptHashesAffected,
                        const NewTxsMap & txsNew,
                        const GetTXOInfoFromDBFunc & getTXOInfo,
                        bool TRACE) -> Stats
{
    const auto t0 = Tic();
    size_t rpaDupeCt = 0u;
    Stats ret;
    ret.oldSize = this->txs.size();
    ret.oldNumAddresses = this->hashXTxs.size();
    // first, do new outputs for all tx's, and put the new tx's in the mempool struct
    for (auto & [hash, pair] : txsNew) {
        auto & [tx, ctx] = pair;
        assert(hash == tx->hash);
        this->txs[tx->hash] = tx; // save tx right now to map, since we need to find it later for possible spends, etc if subsequent tx's refer to this tx.
        IONum n = 0;
        const auto numTxo = ctx->vout.size();
        if (LIKELY(tx->txos.size() != numTxo)) {
            // we do it this way (reserve then resize) to avoid the automatic 2^N prealloc of normal vector .resize()
            tx->txos.reserve(numTxo);
            tx->txos.resize(numTxo);
        }
        for (const auto & out : ctx->vout) {
            const auto & script = out.scriptPubKey;
            if (!BTC::IsOpReturn(script)) {
                // UTXO only if it's not OP_RETURN -- can't do 'continue' here as that would throw off the 'n' counter
                HashX sh = BTC::HashXFromCScript(out.scriptPubKey);
                // the below is a hack to save memory by re-using the same shallow copy of 'sh' each time
                auto hxit = this->hashXTxs.find(sh);
                if (hxit != this->hashXTxs.end()) {
                    // found existing, re-use sh as a shallow copy
                    sh = hxit->first;
                } else {
                    // new entry, insert, update hxit
                    auto pair = this->hashXTxs.emplace(std::piecewise_construct,
                                                       std::forward_as_tuple(sh), std::forward_as_tuple());
                    hxit = pair.first;
                }
                // end memory saving hack
                TXOInfo &txoInfo = tx->txos[n];
                txoInfo = TXOInfo{out.nValue, sh, {}, {}, out.tokenDataPtr};
                auto & utxoset = tx->hashXs[sh].utxo;
                utxoset.emplace_hint(utxoset.end(), n);
                hxit->second.push_back(tx); // save tx to hashx -> tx vector (amortized constant time insert at end -- we will sort and uniqueify this at end of this function)
                scriptHashesAffected.insert(sh);
                assert(txoInfo.isValid());
            }
            tx->fee -= out.nValue; // update fee (fee = ins - outs, so we "add" the outs as a negative)
            ++n;
        }
        assert(n == numTxo);
        // . <-- at this point the .txos vec is built, with everything isValid() except for the OP_RETURN outs, which are all !isValid()
    }

    std::unordered_map<TxHash, TxHashSet, HashHasher> newTxsNewParents; // only used if !dsps.empty(). Contains all in-mempool parents of txs from txsNew that are themselves in txsNew

    // next, do new inputs for all tx's, debiting/crediting either a mempool tx or querying db for the relevant utxo
    for (auto & [hash, pair] : txsNew) {
        auto & [tx, ctx] = pair;
        assert(hash == tx->hash);
        IONum inNum = 0;
        TxHashSet seenParents; // DSP handling, otherwise unused if no dsp
        for (const auto & in : ctx->vin) {
            const IONum prevN = IONum(in.prevout.GetN());
            const TxHash prevTxId = BTC::Hash2ByteArrayRev(in.prevout.GetTxId());
            const TXO prevTXO{prevTxId, prevN};
            std::optional<TXOInfo> optTXOInfo;
            const TXOInfo *pprevInfo{}; // points to either a TXOInfo from a prevTxRef, or to &*optTXOInfo
            QByteArray sh; // shallow copy of prevInfo.hashX
            if (auto it = this->txs.find(prevTxId); it != this->txs.end()) {
                // prev is a mempool tx
                auto prevTxRef = it->second;
                assert(bool(prevTxRef));
                if (prevN >= prevTxRef->txos.size()
                        || !(pprevInfo = &prevTxRef->txos[prevN])->isValid())
                    // defensive programming paranoia
                    throw ConsistencyError(QString("FAILED TO FIND A VALID PREVIOUS TXOUTN %1:%2 IN MEMPOOL for TxHash: %3 (input %4)")
                                           .arg(QString(prevTxId.toHex())).arg(prevN).arg(QString(hash.toHex())).arg(inNum));
                sh = pprevInfo->hashX;
                const auto & refPrevInfo = tx->hashXs[sh].unconfirmedSpends[prevTXO] = *pprevInfo;
                auto prevHashXIt = prevTxRef->hashXs.find(sh);
                if (prevHashXIt == prevTxRef->hashXs.end())
                    throw ConsistencyError(QString("PREV OUT %1 IS MISSING ITS HASHX ENTRY FOR HASHX %2 (txid: %3)")
                                           .arg(prevTXO.toString(), QString(sh.toHex()), QString(tx->hash.toHex())));
                prevHashXIt->second.utxo.erase(prevN); // remove this spend from utxo set for prevTx in mempool
                if (TRACE) {
                    Debug() << hash.toHex() << " unconfirmed spend: " << prevTXO.toString() << " " << refPrevInfo.amount.ToString().c_str()
                            << (refPrevInfo.tokenDataPtr ? (" " + refPrevInfo.tokenDataPtr->ToString()).c_str() : "");
                }

                // link parent to child and child to parent
                Tx::linkChild(prevTxRef, tx);

                // DSP handling (BCH only)
                if (!dsps.empty() && !seenParents.contains(prevTxId)) {
                    if (!txsNew.contains(prevTxId)) { // parent was an old in-mempool tx, check if it had dsps and assign them to this child
                        if (const auto *dspHashes = dsps.dspHashesForTx(prevTxId)) {
                            for (const auto &dspHash : *dspHashes) {
                                if (dsps.addTx(dspHash, hash)) {
                                    ret.dspTxsAffected.insert(hash);
                                    DebugM(__func__, ": added tx ", hash.toHex(), " to descendants for dsp ", dspHash.toHex());
                                } else if (Debug::isEnabled() || inNum == 0) {
                                    // This may happen rarely. Even though this is a new txid, if there is a diamond
                                    // pattern with the prevTxId's, then this tx may have already been added as a
                                    // descendant tx for this dspHash by one of our other inputs.
                                    //
                                    // Note that an invariant is maintained in SynchDSPsTask that only "known" txids
                                    // are ever added, so this branch *must* be the result of a different previous
                                    // input having already added us in the enclosing for() loop. (We warn if that
                                    // is not the case as it would indicate a bug in this code.)
                                    QString msg("%1: dsp addTx returned false for dspHash: %2, txid: %3.");
                                    msg = msg.arg(__func__, dspHash.toHex(), hash.toHex());
                                    if (LIKELY(inNum > 0))
                                        Debug() << msg;
                                    else
                                        Warning() << msg << " This should never happen! FIXME!";
                                }
                            }
                        }
                    } else {
                        // parent was a tx in the new set, so we must process further at end of function to figure
                        // out if this childtx has associated dsps...
                        newTxsNewParents[hash].insert(prevTxId);
                    }
                    seenParents.insert(prevTxId);
                }
                // /DSP handling
            } else {
                // prev is a confirmed tx
                optTXOInfo = getTXOInfo(prevTXO); // this may also throw on low-level db error
                if (UNLIKELY(!optTXOInfo.has_value())) {
                    // Uh oh. If it wasn't in the mempool or in the db.. something is very wrong with our code...
                    // (or there maybe was a race condition and a new block came in while we were doing this).
                    // We will throw if missing, and the synch process aborts and hopefully we recover with a reorg
                    // or a new block or somesuch.
                    throw ConsistencyError(QString("FAILED TO FIND PREVIOUS TX %1 IN EITHER MEMPOOL OR DB for TxHash: %2 (input %3)")
                                           .arg(prevTXO.toString()).arg(QString(hash.toHex())).arg(inNum));
                }
                pprevInfo = &*optTXOInfo;
                sh = pprevInfo->hashX;
                // hack to save memory by re-using existing sh QByteArray and/or forcing a shallow-copy
                auto hxit = tx->hashXs.find(sh);
                if (hxit != tx->hashXs.end()) {
                    // existing found, re-use same unerlying QByteArray memory for sh
                    sh = optTXOInfo->hashX = hxit->first;
                } else {
                    // new entry, insert, update hxit
                    auto pair = tx->hashXs.emplace(std::piecewise_construct, std::forward_as_tuple(sh), std::forward_as_tuple());
                    hxit = pair.first;
                }
                // end memory saving hack
                const auto & refPrevInfo = hxit->second.confirmedSpends[prevTXO] = *pprevInfo;
                if (TRACE) {
                    Debug() << hash.toHex() << " confirmed spend: " << prevTXO.toString() << " " << refPrevInfo.amount.ToString().c_str();
                }
            }
            tx->fee += pprevInfo->amount;
            assert(sh == pprevInfo->hashX);
            this->hashXTxs[sh].push_back(tx); // mark this hashX as having been "touched" because of this input (note we push dupes here out of order but sort and uniqueify at the end)
            scriptHashesAffected.insert(sh);

            // RPA handling (if enabled), and if input number is below 30
            if (inNum < Rpa::InputIndexLimit && optPrefixTable) {
                if (!tx->optRpaPrefixSet) tx->optRpaPrefixSet.emplace(); // ensure set exists
                auto & txPrefixSet = *tx->optRpaPrefixSet;
                const Rpa::Hash inputHash{in}; // hash the input
                const auto [it, inserted] = txPrefixSet.emplace(inputHash);
                if (inserted) {
                    // new prefix <-> txHash association, mark it in the class-level table
                    const Rpa::Prefix & prefix = *it;
                    optPrefixTable->addForPrefix(prefix, tx->hash);
                } else {
                    // Dupe prefix <-> txHash association (prefix collision within same txn can happen every so often),
                    // indicate this for Debug purposes, unless inNum == 0 which indicates some programming error.
                    ++rpaDupeCt;
                    if (Debug::isEnabled() || inNum == 0u) {
                        (inNum == 0u ? static_cast<Log &&>(Error()) // log as Error if inNum == 0
                                     : static_cast<Log &&>(Debug())) // otherwise log to Debug
                            ("addNewTxs: txInput ", Util::ToHexFast(tx->hash), ":", inNum,
                             " has dupe prefix already in table: '", it->toHex(), "' (dupeCt for this invocation: ",
                             rpaDupeCt, ")", (inNum != 0u ? "; safely ignoring dupe." : ""));
                    }
                }
            }

            ++inNum;
        }

        // Now, compactify some data structures to take up less memory by rehashing thier unordered_maps/unordered_sets..
        // we do this once for each new tx we see.. and it can end up saving tons of space. Note the below structures
        // are either fixed in size or will only ever shrink as the mempool evolves so this is a good time to do this.
        tx->hashXs.rehash(tx->hashXs.size());
    }

    // now, sort and uniqueify data structures made temporarily inconsistent above (have dupes, are out-of-order)
    for (const auto & sh : scriptHashesAffected) {
        if (auto it = this->hashXTxs.find(sh); LIKELY(it != this->hashXTxs.end()))
            Util::sortAndUniqueify<Mempool::TxRefOrdering>(it->second);
        //else {}
        // Note: It's possible for the scriptHashesAffected set to refer to sh's no longer in the mempool because
        // we sometimes retry this task when we detect mempool drops, with the scriptHasesAffected set containing
        // the dropped address hashes.  This is why the if conditional above exists.
    }

    // DSP handling (BCH only)
    if (!dsps.empty() && !newTxsNewParents.empty() && !ret.dspTxsAffected.empty()) {
        Tic t0;
        unsigned addCt, iters = 0, innerIters = 0, addsTotal = 0;
        do {
            // Keep looping and adding dsp<->txid associations (this keeps expanding the dsp->descendant sets for each
            // dsp) until nothing new is added, in which case we are done.
            //
            // This loop is guaranteed to terminate but only if DSPs::addTx returns an accurate bool about whether an
            // insertion took place or not (it currently does). That invariant needs to be maintained.  A note was also
            // added to DSPs::addTx to warn of this.
            addCt = 0;
            for (const auto & [hash, parentSet] : newTxsNewParents) {
                ++innerIters;
                for (const auto & prevTxId : parentSet) {
                    ++innerIters;
                    if (const auto *dspHashes = dsps.dspHashesForTx(prevTxId)) {
                        for (const auto &dspHash : *dspHashes) {
                            ++innerIters;
                            if (dsps.addTx(dspHash, hash)) {
                                ++addCt;
                                ++addsTotal;
                                ret.dspTxsAffected.insert(hash);
                                DebugM(__func__, ": added tx ", hash.toHex(), " to descendants for dsp ", dspHash.toHex());
                            }
                        }
                    }
                }
            }
            ++iters;
        } while (addCt);
        DebugM(__func__, ": (unconf. parent chain) dspTx adds: ", addsTotal, ", iters: ", iters, ", innerIters: ",
               innerIters, ", elapsed: ", t0.msecStr(), " msec");
    }
    if (!ret.dspTxsAffected.empty())
        // this grows the set to encompass all txids now linked by common dsproofs
        ret.dspTxsAffected = dsps.txsLinkedToTxs(ret.dspTxsAffected);
    // /DSP handling

    ret.newSize = this->txs.size();
    ret.newNumAddresses = this->hashXTxs.size();
    ret.elapsedMsec = t0.msec<decltype(ret.elapsedMsec)>();
    return ret;
}

std::size_t Mempool::growTxHashSetToIncludeDescendants(const char *const logpfx, TxHashSet &txids, const bool TRACE) const
{
    if (txids.empty())
        return 0;

    std::size_t iterct = 0u, numAdds = 0u;

    const auto t0 = Tic();
    TxHashSet workQueue = txids;
    // "recursively" add children to the txids in the source set. Implicitly keeps adding to the resulting set until
    // all descendant txs in mempool are covered.
    while (!workQueue.empty()) {
        ++iterct;
        const TxHash txid = *workQueue.begin();
        workQueue.erase(workQueue.begin());
        if (const auto it = txs.find(txid); it != txs.end()) {
            const TxRef &tx = it->second;
            for (const auto & [childTxid, _] : tx->children) {
                if (txids.insert(childTxid).second) {
                    workQueue.insert(childTxid);
                    ++numAdds;
                    if (TRACE)
                        DebugM(logpfx, ": additonal tx ", Util::ToHexFast(childTxid), " added to set because it spends from ",
                               Util::ToHexFast(txid));
                }
            }
        }
    }
    using Util::Pluralize;
    DebugM(logpfx, ": iterated ", iterct, Pluralize(" time", iterct), " to add ", numAdds,
           Pluralize(" additional child tx", numAdds), " in ", t0.msecStr(2), " msec");
    return numAdds;
}

std::size_t Mempool::growTxHashSetToIncludeDescendants(TxHashSet &txids, const bool TRACE) const
{
    return growTxHashSetToIncludeDescendants("txDescendants", txids, TRACE);
}

/* static */
void Mempool::Tx::linkChild(const TxRef &parent, const TxRef &child)
{
    parent->children.emplace(child->hash, child);
    child->parents.emplace(parent->hash, parent);
}

void Mempool::Tx::unlinkFromParentsAndChildren()
{
    for (auto & [_, pwtx] :  parents) if (auto ptx = pwtx.lock()) ptx->children.erase(this->hash);
    for (auto & [_, cwtx] : children) if (auto ctx = cwtx.lock()) ctx-> parents.erase(this->hash);
}

auto Mempool::dropTxs(ScriptHashesAffectedSet & scriptHashesAffectedOut, TxHashSet & txids, bool TRACE,
                      std::optional<float> rehashMaxLoadFactor) -> Stats
{
    const auto t0 = Tic();
    // also drop txs that spend from the txids in the above set as well -- since we
    // cannot drop tx's in the middle of a chain of spends due to the inconsistency
    // that would lead to (possible spends of non-existant outputs).
    growTxHashSetToIncludeDescendants("dropTxs", txids, TRACE);

    Stats ret;
    ScriptHashesAffectedSet scriptHashesAffected;
    int skipPrevCt = 0;
    ret.oldSize = this->txs.size();
    ret.oldNumAddresses = this->hashXTxs.size();

    // first, undo unconfirmed spends -- find the parent txs and credit back the IOInfos for corresponding scripthashes
    for (const auto & txid : txids) {
        auto it = txs.find(txid);
        if (UNLIKELY(it == txs.end())) {
            // Note that it's ok to call this function for non-existant tx's -- if we call it when adding new blocks
            // then it's possible for txids in blocks to not be in mempool. Only print a message in debug mode.
            DebugM("dropTxs: tx ", Util::ToHexFast(txid), " not found in mempool");
            continue;
        }
        auto & tx = it->second;
        // for each hashX this tx affects, look for unconfirmed spends
        for (const auto & [hashX, ioinfo]: tx->hashXs) {
            // update affected set with all addresses involved with this tx (spends, outs, etc)
            scriptHashesAffected.insert(hashX);
            // for each unconfirmed spend, go to the previous tx in mempool and add back the utxo to ioinfo.utxo
            // for the parent tx hashx entry
            for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                assert(txoinfo.hashX == hashX);
                if (txids.contains(txo.txHash)) {
                    // prev tx will be (or has already been) removed, no sense in doing any utxo crediting for a tx
                    // that will disappear shortly
                    ++skipPrevCt;
                    continue;
                }
                auto prevIt = txs.find(txo.txHash);
                if (LIKELY(prevIt != txs.end())) {
                    auto & prevTx = prevIt->second;
                    if (LIKELY(txo.outN < prevTx->txos.size())) {
                        auto & prevTxoInfo = prevTx->txos[txo.outN];
                        if (UNLIKELY(txoinfo != prevTxoInfo)) {
                            Error() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
                                    << "expected TXOInfo for this tx to match with spending tx " << txid.toHex()
                                    << "'s TXOInfo! FIXME!";
                        }
                        if (UNLIKELY(prevTxoInfo.hashX != hashX)) {
                            Error() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
                                    << "expected TXOInfo for this tx to have hashX " << hashX.toHex()
                                    << ", but it did not! FIXME!";
                        }
                        auto prevHashXsIt = prevTx->hashXs.find(hashX);
                        if (LIKELY(prevHashXsIt != prevTx->hashXs.end())) {
                            auto & previoinfo = prevHashXsIt->second;
                            // this does the actual "crediting" back of the spend to the parent tx
                            assert(txo.isValid());
                            previoinfo.utxo.insert(txo.outN);
                            if (TRACE)
                                Debug() << "dropTxs: for txid " << Util::ToHexFast(txid) << " crediting "
                                        << txo.txHash.toHex() << ":" << txo.outN << " amount "
                                        << QString::fromStdString(txoinfo.amount.ToString()) << " back to hashX "
                                        << Util::ToHexFast(hashX);
                        } else {
                            Error() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
                                    << "cannot find hashX " << hashX.toHex() << " in tx map! FIXME!";
                        }
                    } else {
                        Error() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " is "
                                << " invalid (this output is spent by the dropped tx " << txid.toHex() << ")! FIXME!";
                    }
                } else {
                    Error() << "dropTxs: Previous tx " << txo.txHash.toHex() << " which has outputs spent by "
                            << "(dropped) tx " << txid.toHex() << " is not found in mempool! This is unexpected! FIXME!";
                }
            }
        }

        ret.rpaRmCt += rmTxRpaAssociations(tx);

        // unlink parent/child relationships
        tx->unlinkFromParentsAndChildren();

        // and finally remove this tx from `txs` now, while we have its iterator .. this is faster
        // than doing the remove later, since we already have the iterator now!
        txs.erase(it);
    }

    if (skipPrevCt)
        DebugM("dropTxs: previous tx \"crediting\" skipped due to being in drop set: ", skipPrevCt);

    // next, scan hashXs, removing entries for the txids in question
    // -- note this helper function doesn't look at `txs` so it's fine that we removed already in the loop above.
    rmTxsInHashXTxs(txids, scriptHashesAffected, TRACE);

    // next, remove txids from dsproof data structure (BCH only)
    if (!dsps.empty()) { // fast path for common case of no dsproofs in most mempools, or for BTC mempools where the dsproof feature does not exist
        const Tic trm;
        const auto b4 = dsps.size(), txb4 = dsps.numTxDspLinks();
        TxHashSet txids2rm;
        for (const auto & txid : txids) {
            if (dsps.dspHashesForTx(txid)) // <-- this is O(1) fast lookup by txid
                txids2rm.insert(txid); // enqueue for removal in next loop below (must do this after growing the dsps.dspHashesForTx set)
        }
        if (!txids2rm.empty()) {
            // tell caller about all the dsps that are linked and may have lost descendants (for notifications)
            ret.dspTxsAffected = dsps.txsLinkedToTxs(txids2rm);
            // do the rm now
            for (const auto & txid : txids2rm) {
                dsps.rmTx(txid);
                if (dsps.empty()) break; // short circuit loop end in case we emptied it out
            }
        }
        const auto after = dsps.size(), txafter = dsps.numTxDspLinks();
        ret.dspRmCt = b4 > after ? b4 - after : 0;
        ret.dspTxRmCt = txb4 > txafter ? txb4 - txafter : 0;
        if (ret.dspTxRmCt || ret.dspRmCt)
            DebugM("dropTxs: removed ", ret.dspTxRmCt, " dsproof <-> tx associations (", ret.dspRmCt, " dsps) in ",
                   trm.msecStr(), " msec");
    }

    // finally, update scriptHashesAffectedOut
    scriptHashesAffectedOut.merge(std::move(scriptHashesAffected));

    // update returned stats
    ret.newSize = this->txs.size();
    ret.newNumAddresses = this->hashXTxs.size();

    if (rehashMaxLoadFactor) {
        if (txs.load_factor() <= *rehashMaxLoadFactor)
            txs.rehash(0); // shrink to fit
        if (hashXTxs.load_factor() <= *rehashMaxLoadFactor)
            hashXTxs.rehash(0);  // shrink to fit
        if (dsps.load_factor() <= *rehashMaxLoadFactor)
            dsps.shrink_to_fit();
    }
    ret.elapsedMsec = t0.msec<decltype(ret.elapsedMsec)>();
    return ret;
}

size_t Mempool::rmTxRpaAssociations(const TxRef &tx)
{
    size_t rmct = 0u;
    if (tx->optRpaPrefixSet) {
        if (LIKELY(optPrefixTable)) {
            for (const auto & prefix : *tx->optRpaPrefixSet) {
                rmct += optPrefixTable->removeForPrefixAndHash(prefix, tx->hash);
            }
            if (rmct == 0u || rmct > Rpa::InputIndexLimit) {
                (rmct == 0u ? static_cast<Log &&>(Error()) : static_cast<Log &&>(Warning()))
                    << "rmTxRpaAssociation: removed " << rmct << " prefix <-> txHash associations for tx: "
                    << Util::ToHexFast(tx->hash) << ". This is unexpected; FIXME!";
            }
        } else {
            Warning() << "Tx: " << Util::ToHexFast(tx->hash) << " has an RPA prefix set (size: " << tx->optRpaPrefixSet->size() << ")"
                      << ", but Mempool has optPrefixTable disabled. This is unexpected; FIXME!";
        }
        tx->optRpaPrefixSet->clear();
    }
    return rmct;
}

template <typename SetLike> requires std::is_same_v<SetLike, Mempool::TxHashSet> || std::is_same_v<SetLike, Mempool::TxHashNumMap>
std::size_t Mempool::rmTxsInHashXTxs_impl(const SetLike &txids, const ScriptHashesAffectedSet &scriptHashesAffected,
                                          bool TRACE, const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort)
{
    Tic t0;
    std::size_t ct = 0, sortCt = 0;
    qint64 sortTimeNanos = 0;

    // next, scan hashXs, removing entries for the txids in question
    for (const auto & hashX : scriptHashesAffected) {
        auto it = hashXTxs.find(hashX);
        if (UNLIKELY(it == hashXTxs.end())) {
            Error() << "rmTxsInHashXTxs: Could not find scripthash " << hashX.toHex() << " in hashXTxs map! FIXME!";
            continue;
        }
        auto & txvec = it->second;
        if (UNLIKELY(txvec.empty()))
            Error() << "rmTxsInHashXTxs: txvec for scripthash " << hashX.toHex() << " is empty! This should never happen! FIXME!";
        std::vector<TxRef> newvec;
        newvec.reserve(txvec.size());
        for (auto &txref : txvec) {
            // filter out txids in the set
            if (! txids.contains(txref->hash))
                // not in txid set; copy it to newvec
                newvec.push_back(txref);
            else
                ++ct; // will be removed, tally count
        }
        if (!newvec.empty() && newvec.size() != txvec.size()) {
            // swap the vectors with the one not containing the affected txids
            if (TRACE) {
                const auto oldsz = txvec.size(), newsz = newvec.size();
                if (TRACE)
                    Debug() << "rmTxsInHashXTxs: Shrunk hashX " << Util::ToHexFast(hashX) << " txvec from size " << oldsz
                            << " to size " << newsz;
            }
            txvec.swap(newvec);
            txvec.shrink_to_fit();
        } else if (newvec.empty()) {
            // if the new vector is empty meaning this hashX should disappear from the hashXTxs map!
            hashXTxs.erase(it);
            if (TRACE) Debug() << "rmTxsInHashXTxs: Removed hashX " << Util::ToHexFast(hashX) << " which now has no txs in mempool";
            continue; // removed; ensure we skip the below potential sort
        }
        // if sorting specified, sort if in set (and if not removed 2 lines above)
        if (hashXsNeedingSort && hashXsNeedingSort->count(hashX)) {
            Tic t1;
            std::sort(txvec.begin(), txvec.end(), Mempool::TxRefOrdering{});
            ++sortCt;
            sortTimeNanos += t1.nsec();
        }
    }
    DebugM("rmTxsInHashXTxs: removed ", ct, " entries in ", t0.msecStr(), " msec",
           (sortCt ? QString(" sorted %1 entries").arg(sortCt) : ""),
           (sortTimeNanos ? QString(" (sort time: %1 msec)").arg(QString::number(sortTimeNanos/1e6, 'f', 3)) : ""));
    return ct;
}

std::size_t Mempool::rmTxsInHashXTxs(const TxHashSet &txids, const ScriptHashesAffectedSet &scriptHashesAffected,
                                     const bool TRACE, const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort)
{
    return rmTxsInHashXTxs_impl(txids, scriptHashesAffected, TRACE, hashXsNeedingSort);
}

std::size_t Mempool::rmTxsInHashXTxs(const TxHashNumMap &txidMap, const ScriptHashesAffectedSet &scriptHashesAffected,
                                     bool TRACE, const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort)
{
    return rmTxsInHashXTxs_impl(txidMap, scriptHashesAffected, TRACE, hashXsNeedingSort);
}

auto Mempool::confirmedInBlock(ScriptHashesAffectedSet & scriptHashesAffectedOut,
                               const TxHashNumMap & txidMap, const BlockHeight confirmedHeight,
                               bool TRACE, std::optional<float> rehashMaxLoadFactor) -> Stats
{
    const auto t0 = Tic();

    ScriptHashesAffectedSet scriptHashesAffected;
    std::optional<ScriptHashesAffectedSet> hashXTxsEntriesNeedingSort;
    hashXTxsEntriesNeedingSort.emplace();

    auto recategorizeSpendsForChild = [&scriptHashesAffected, &hashXTxsEntriesNeedingSort, &confirmedHeight, &TRACE,
                                       &txidMap] (TxRef &child, size_t &spendsRecategorizedCount) {
        // Scan all the unconfirmned spends for this child tx and find the ones spending from txids in `txidMap`,
        // and recategorize them as "confirmed spends".
        std::size_t nUnconfs = 0;
        for (auto & [sh, ioinfo] : child->hashXs) {
            unsigned ctr = 0u;
            for (auto itUS = ioinfo.unconfirmedSpends.begin(); itUS != ioinfo.unconfirmedSpends.end(); /* see below */) {
                const auto &txo = itUS->first; // take ref for readability (pointers/refs are not invalidated, even after extract)
                if (auto itTxIdMap = txidMap.find(txo.txHash); itTxIdMap != txidMap.end()) {
                    // and voila! This tx spends from a confirmed parent we are going to remove. Recategorize unconf -> conf.
                    auto it2move = itUS++;  // first make `it` point to `it` + 1, making `it2move` be previous value `it`
                    // transfer node from unconfirmed spends -> confirmed spends
                    auto res = ioinfo.confirmedSpends.insert(ioinfo.unconfirmedSpends.extract(it2move)); // does not invalidate refs
                    if (LIKELY(res.inserted)) {
                        // update node data -- (confirmedHeight and txNum need to be updated for confirmed spend)
                        auto & txoinfo = res.position->second;
                        txoinfo.confirmedHeight = confirmedHeight;
                        txoinfo.txNum = itTxIdMap->second; /* confirmed parent txNum */
                        ++ctr;
                        ++spendsRecategorizedCount;
                        if (TRACE)
                            DebugM("confirmedInBlock: TXO ", txo.toString(), " now recategorized under ",
                                   "\"confirmedSpends\" for txid ", child->hash.toHex());
                    } else {
                        // this should never happen
                        Error() << "confirmedInBlock: TXO " << txo.toString() << " could not be inserted into "
                                << "\"confirmedSpends\" for txid: " << child->hash.toHex() << ". This should never "
                                << "happen! FIXME!";
                    }
                } else
                    // prevout txid is not in the confirmed map, keep moving
                    ++itUS;
            }
            // sum up final size, so we can detect when there are no more unconf spends for this tx
            // (this unconf spends map for this sh may have gone from N -> N-1, or N -> N-2, etc, or may now be empty)
            nUnconfs += ioinfo.unconfirmedSpends.size();
            if (ctr && TRACE)
                DebugM("confirmedInBlock: txid ", child->hash.toHex(), ", scripthash ", sh.toHex(), " removed ", ctr,
                       " unconf spends (unconf map size for this txid+sh now: ", ioinfo.unconfirmedSpends.size(), ")");
        }
        // check if no more unconf spends now for this tx; if so, notify all sh's for this tx
        if (!nUnconfs) {
            for (const auto & [sh, _] : child->hashXs) {
                // We also need to add to affected set since clients use the "height" info for status -- and this
                // tx went from height == -1 -> height == 0 now.
                //
                // Note: this casts a slightly wide net because it informs all the scripthashes in child txs of this
                // tx -- which is what we want.  But it also means the debug log will show a larger address count
                // for this operation than the address count of the block itself.
                scriptHashesAffected.insert(sh);
                // We also flag it as needing sort because its sorting criteria changed.
                hashXTxsEntriesNeedingSort->insert(sh);
            }
            if (TRACE)
                DebugM("confirmedInBlock: txid ", child->hash.toHex(), " now recategorized as not spending any unconfirmed parents");
        }
    };

    Stats ret;
    ret.oldSize = this->txs.size();
    ret.oldNumAddresses = this->hashXTxs.size();
    const std::size_t dspCtBefore = dsps.size();
    const std::size_t dspTxCtBefore = dsps.numTxDspLinks();
    TxHashSet dspTxids;
    TxHashSet childrenThatWeRecategorized;
    size_t unknownTxidCt{}, spendsRecategorizedCt{};

    // - Remove all txids in txidMap from this->txs, recategorizing child txns still in mempool as having "confirmed spends"
    // - Tag any DSPs to be removed for confirmed txs
    // - Remove tx<->rpa associations for each confirmed tx
    // - Unlink each confirmed tx from its parent(s)/child(ren)
    // - Lastly, erase each confirmed tx altogether from `txs`
    for (const auto & [txid, txnum] : txidMap) {
        auto it = txs.find(txid);
        if (it == txs.end()) { ++unknownTxidCt; continue; }
        auto & tx = it->second;
        // this txid is to be removed from mempool, tally its scripthashes as affected by the removal
        for (const auto & [sh, _] : tx->hashXs)
            scriptHashesAffected.insert(sh);
        if (dsps.dspHashesForTx(txid)) { // <-- this is O(1) fast lookup by txid
            // add to dspTxids so we can call dsps.rmTx() on this txid after this loop finishes -- we must do that
            // at the end after this loop is done, so that we can get an aggregate set of dspTxsAffected
            // from the list of dspTxids we plan on removing, before we remove them.
            dspTxids.insert(txid);
        }
        ret.rpaRmCt += rmTxRpaAssociations(tx);

        // handle children
        for (const auto &[ctxid, cwtx] : it->second->children) {
            if (!txidMap.contains(ctxid)) { // only re-categorize if this child is not to be removed
                if (auto ctx = cwtx.lock()) {
                    if (childrenThatWeRecategorized.insert(ctxid).second) // guard against processing same child tx more than once
                        recategorizeSpendsForChild(ctx, spendsRecategorizedCt);
                } else
                    // This should never happen
                    Error() << "confirmedInBlock: child txid " << ctxid.toHex() << " has a NULL weakptr in the child table for " << tx->hash.toHex() << ". FIXME!";
            } else if (TRACE) {
                DebugM("confirmedInBlock: Skipping recategorization for child tx ", ctxid.toHex(), " (for parent tx ",
                       tx->hash.toHex(), ") because the child tx is in the removal set.");
            }
        }

        // unlink parent/child relationships
        tx->unlinkFromParentsAndChildren();
        // erase this entry
        txs.erase(it);
    }

    if (unknownTxidCt)
        DebugM("confirmedInBlock: Skipped ", unknownTxidCt, " \"unknown\" txids that were not in mempool but were in a block");
    if (!childrenThatWeRecategorized.empty() || spendsRecategorizedCt > 0u)
        DebugM("confirmedInBlock: Recategorized ", spendsRecategorizedCt, " unconf -> conf ",
               Util::Pluralize("spend", spendsRecategorizedCt), " in ",
               childrenThatWeRecategorized.size(), Util::Pluralize(" child tx", childrenThatWeRecategorized.size()),
               " (elapsed so far: ", t0.msecStr(), " msec)");

    // now, update hashXTxs as well
    rmTxsInHashXTxs(txidMap, scriptHashesAffected, TRACE, hashXTxsEntriesNeedingSort);

    // now, do dsps.rmTx for any txids that we removed that happened to have dsps associated (BCH only)
    if (!dspTxids.empty()) {
        ret.dspTxsAffected = dsps.txsLinkedToTxs(dspTxids);
        for (const auto &txid : dspTxids)
            dsps.rmTx(txid); // may end up deleting dspHashes as well if the primary txid goes away
    }

    // finally, update scriptHashesAffectedOut
    scriptHashesAffectedOut.merge(std::move(scriptHashesAffected));

    // update returned stats
    ret.newSize = this->txs.size();
    ret.newNumAddresses = this->hashXTxs.size();

    if (rehashMaxLoadFactor) {
        if (txs.load_factor() <= *rehashMaxLoadFactor)
            txs.rehash(0); // shrink to fit
        if (hashXTxs.load_factor() <= *rehashMaxLoadFactor)
            hashXTxs.rehash(0);  // shrink to fit
        if (dsps.load_factor() <= *rehashMaxLoadFactor)
            dsps.shrink_to_fit();
    }
    if (const auto dspCtAfter = dsps.size(); dspCtBefore > dspCtAfter)
        ret.dspRmCt = dspCtBefore - dspCtAfter;
    if (const auto dspTxCtAfter = dsps.numTxDspLinks(); dspTxCtBefore > dspTxCtAfter)
        ret.dspTxRmCt = dspTxCtBefore - dspTxCtAfter;
    ret.elapsedMsec = t0.msec<decltype(ret.elapsedMsec)>();
    return ret;
}

/* static */
QVariantMap Mempool::dumpTx(const TxRef &tx)
{
    QVariantMap m;
    if (tx) {
        m["hash"] = tx->hash.toHex();
        m["sizeBytes"] = tx->sizeBytes;
        m["fee"] = tx->fee.ToString().c_str();
        QVariantList l;
        for (const auto & [txid, wtx] : tx->parents) {
            if (auto tx = wtx.lock()) l.push_back(Util::ToHexFast(tx->hash));
            else l.push_back(QVariant{});
        }
        m["unconfirmedParents"] = l;
        l.clear();
        for (const auto & [txid, wtx] : tx->children) {
            if (auto tx = wtx.lock()) l.push_back(Util::ToHexFast(tx->hash));
            else l.push_back(QVariant{});
        }
        m["unconfirmedChildren"] = l;
        static const auto TXOInfo2Map = [](const TXOInfo &info) -> QVariantMap {
            QVariantMap ret{
                { "amount", QString::fromStdString(info.amount.ToString()) },
                { "scriptHash", info.hashX.toHex() },
                // NEW -- it's useful to see this info in mempool debug to catch bugs
                { "confirmedHeight", info.confirmedHeight ? QVariant(qlonglong(*info.confirmedHeight)) : QVariant()},
                { "txNum", qlonglong(info.txNum)},
            };
            if (info.tokenDataPtr) {
                QByteArray ba;
                BTC::SerializeTokenDataWithPrefix(ba, info.tokenDataPtr.get());
                ret.insert("tokenData", ba.toHex());
            }
            return ret;
        };
        QVariantMap txos;
        IONum num = 0;
        for (const auto & info : tx->txos) {
            QVariantMap infoMap;
            if (info.isValid())
                infoMap = TXOInfo2Map(info);
            else
                infoMap = QVariantMap{
                    { "amount" , QVariant() },
                    { "scriptHash", QVariant() },
                    { "comment", "OP_RETURN output not indexed"},
                };
            txos[QString::number(num++)] = infoMap;
        }
        m["txos"] = txos;
        QVariantMap hxs;
        static const auto IOInfo2Map = [](const Mempool::Tx::IOInfo &inf) -> QVariantMap {
            QVariantMap ret;
#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
            const auto vl = QVariantList::fromStdList( Util::toList<std::list<QVariant>>(inf.utxo) );
#else
            const auto vl = Util::toList<QVariantList>(inf.utxo);
#endif
            ret["utxos"] = vl;
            QVariantMap cs;
            for (const auto & [txo, info] : inf.confirmedSpends)
                cs[txo.toString()] = TXOInfo2Map(info);
            ret["confirmedSpends"] = cs;
            QVariantMap us;
            for (const auto & [txo, info] : inf.unconfirmedSpends)
                us[txo.toString()] = TXOInfo2Map(info);
            ret["unconfirmedSpends"] = us;
            return ret;
        };
        for (const auto & [sh, ioinfo] : tx->hashXs)
            hxs[sh.toHex()] = IOInfo2Map(ioinfo);
        m["hashXs"] = hxs;
        m["hashXs (LoadFactor)"] = QString::number(double(tx->hashXs.load_factor()), 'f', 4);
        m["hashXs (BucketCount)"] = qulonglong(tx->hashXs.bucket_count());

        if (tx->optRpaPrefixSet) {
            QVariantList prefixes;
            for (const auto & prefix : *tx->optRpaPrefixSet)
                prefixes.push_back(prefix.toHex());
            m["rpaPrefixes"] = prefixes;
        }
    }
    return m;
}

QVariantMap Mempool::dump() const
{
    QVariantMap mp, txMap;
    for (const auto & [hash, tx] : txs) {
        txMap[QString(Util::ToHexFast(hash))] = dumpTx(tx);
    }
    mp["txs"] = txMap;
    mp["txs (LoadFactor)"] = QString::number(double(txs.load_factor()), 'f', 4);
    mp["txs (BucketCount)"] = qulonglong(txs.bucket_count());
    qulonglong collisions, largestBucket, medianBucket, medianNonzero;
    std::tie(collisions, largestBucket, medianBucket, medianNonzero) = Util::bucketStats(txs);
    mp["txs (BucketCollisions)"] = collisions;
    mp["txs (BucketLargest)"] = largestBucket;
    mp["txs (BucketMedian)"] = medianBucket;
    mp["txs (BucketMedianNonzero)"] = medianNonzero;
    QVariantMap hxs;
    for (const auto & [sh, txset] : hashXTxs) {
        QVariantList l;
        for (const auto & tx : txset)
            if (tx) l.push_back(tx->hash.toHex());
        hxs[sh.toHex()] = l;
    }
    mp["hashXTxs"] = hxs;
    mp["hashXTxs (LoadFactor)"] = QString::number(double(hashXTxs.load_factor()), 'f', 4);
    mp["hashXTxs (BucketCount)"] = qulonglong(hashXTxs.bucket_count());
    std::tie(collisions, largestBucket, medianBucket, medianNonzero) = Util::bucketStats(hashXTxs);
    mp["hashXTxs (BucketCollisions)"] = collisions;
    mp["hashXTxs (BucketLargest)"] = largestBucket;
    mp["hashXTxs (BucketMedian)"] = medianBucket;
    mp["hashXTxs (BucketMedianNonzero)"] = medianNonzero;

    QVariantMap dm;
    for (const auto & [hash, dsp] : dsps.getAll())
        dm[hash.toHex()] = dsp.toVarMap();
    mp["dsps"] = dm;

    if (optPrefixTable) {
        QVariantMap pt;
        const unsigned elementCount = optPrefixTable->elementCount();
        pt["total element count"] = elementCount;
        if (elementCount != 0u) {
            QVariantMap pt2;
            for (size_t i = 0u; i < optPrefixTable->numRows(); ++i) {
                const Rpa::Prefix pfx(uint16_t(i), 16);
                const auto & hashSet = optPrefixTable->searchPrefix(pfx);
                if (!hashSet.empty()) {
                    QVariantList l;
                    for (const auto & txHash : hashSet)
                        l.append(Util::ToHexFast(txHash));
                    pt2[pfx.toHex()] = l;
                }
            }
            pt["prefix entries"] = pt2;
            pt["prefix entry count"] = pt2.size();
        }
        mp["RPA Prefix Table"] = pt;
    }

    return mp;
}

bool Mempool::Tx::deepEqual(const Tx &o) const noexcept {
    const bool ok1 =     std::tie(  hash,   fee,   sizeBytes,   vsizeBytes,   txos,   hashXs,   optRpaPrefixSet)
                      == std::tie(o.hash, o.fee, o.sizeBytes, o.vsizeBytes, o.txos, o.hashXs, o.optRpaPrefixSet);
    if (!ok1) return false;
    // now, deep compare the parents and children sets
    if (parents.size() != o.parents.size() || children.size() != o.children.size()) return false;
    for (const auto & [txid, pwtx] : parents) {
        auto it = o.parents.find(txid);
        if (it == o.parents.end()) return false;
        const auto &opwtx = it->second;
        auto ptx = pwtx.lock();
        auto optx = opwtx.lock();
        if (bool(ptx) != bool(optx)) return false;
    }
    for (const auto & [txid, cwtx] : children) {
        auto it = o.children.find(txid);
        if (it == o.children.end()) return false;
        const auto &ocwtx = it->second;
        auto ctx = cwtx.lock();
        auto octx = ocwtx.lock();
        if (bool(ctx) != bool(octx)) return false;
    }
    return true;
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "BitcoinD.h"
#include "BTC.h"
#include "Json/Json.h"
#include "Options.h"
#include "RPC.h"
#include "Util.h"

#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"

#include <QThread>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <future>
#include <set>
#include <vector>

bool Mempool::deepCompareEqual(const Mempool &o, QString *estr) const
{
    if (estr) estr->clear();
    if (this == &o)
        return true;
    if (txs.size() != o.txs.size()) {
        if (estr) *estr = QString("txs.size() mismatch, %1 != %2").arg(txs.size()).arg(o.txs.size());
        return false;
    }
    if (hashXTxs.size() != o.hashXTxs.size()) {
        if (estr) *estr = QString("hashXTxs.size() mismatch, %1 != %2").arg(hashXTxs.size()).arg(o.hashXTxs.size());
        return false;
    }
    long ct = 0;
    Defer d([&ct]{ Debug() << "deepCompareEqual: iterated over " << ct << Util::Pluralize(" item", ct); });
    for (const auto & [txid, tx] : txs) {
        ++ct;
        auto it = o.txs.find(txid);
        if (it == o.txs.end()) {
            if (estr) *estr = QString("txid: %1 not found in other txs map").arg(QString(txid.toHex()));
            return false;
        }
        // compare first the shared_ptr (for short-circuit pointer equality) and if that fails, do actual deep compare of Tx object
        const auto & otx = it->second;
        if (tx != otx && !tx->deepEqual(*otx)) {
            if (estr) {
                *estr = QString("txid: %1 not equal in the two mempools\n---- Tx1 ----\n%2\n---- Tx2 ----\n%3")
                        .arg(QString(txid.toHex()), QString(Json::toUtf8(dumpTx(tx))), QString(Json::toUtf8(dumpTx(otx))));
            }
            return false;
        }
        // otherwise equal so far...
    }
    // compare each of the hashXTxs
    for (const auto & [sh, vec] : hashXTxs) {
        ++ct;
        auto it = o.hashXTxs.find(sh);
        if (it == o.hashXTxs.end()) {
            if (estr) *estr = QString("sh: %1 not found in other hashXTxs").arg(QString(sh.toHex()));
            return false;
        }
        const auto & ovec = it->second;
        if (vec.size() != ovec.size()) {
            if (estr) *estr = QString("sh: %1 txVecs disagree").arg(QString(sh.toHex()));
            return false;
        }
        for (std::size_t i = 0; i < vec.size(); ++i) {
            ++ct;
            // compare first the shared_ptr (for short-circuit pointer equality) and if that fails, do actual deep compare of Tx object
            if (vec[i] != ovec[i] && *vec[i] != *ovec[i]) {
                if (estr) *estr = QString("sh: %1 txs disagree for txid %2").arg(QString(sh.toHex()), QString(vec[i]->hash.toHex()));
                return false;
            }
        }
        // otherwise equal so far...
    }
    if (dsps != o.dsps) {
        if (estr) *estr = "DSPs members differ";
        return false;
    }
    static_assert(std::is_same_v<std::optional<Rpa::MempoolPrefixTable>, decltype(optPrefixTable)>, "Below line of code assumpes this");
    if (optPrefixTable != o.optPrefixTable) {
        if (estr) *estr = "MempoolPrefixTable members differ";
        return false;
    }
    // couldn't find an inequality, return true
    return true;
}

namespace {
    std::atomic_bool interrupted = false;
    using MPData = Mempool::NewTxsMap;
    using TXOMap = std::unordered_map<TXO, TXOInfo>;

    std::pair<MPData, bool> loadMempoolDat(const QString &fname) {
        // Below code taken from BCHN validation.cpp, but adopted to also support segwit
        FILE *pfile = std::fopen(fname.toUtf8().constData(), "rb");
        bitcoin::CAutoFile file(pfile, bitcoin::SER_DISK, bitcoin::PROTOCOL_VERSION | bitcoin::SERIALIZE_TRANSACTION_USE_WITNESS | bitcoin::SERIALIZE_TRANSACTION_USE_CASHTOKENS);
        if (file.IsNull())
            throw Exception(QString("Failed to open mempool file '%1'").arg(fname));

        std::size_t dataTotal = 0;
        const Tic t0;

        MPData ret;
        bool isSegWit = false;
        try {
            uint64_t version;
            file >> version;
            constexpr uint64_t BCHN_BTC_VERSION = 1, BU_VERSION = 1541030400, BTC_VERSION_XOR_KEY = 2;
            if (!std::set<uint64_t>({BCHN_BTC_VERSION, BU_VERSION, BTC_VERSION_XOR_KEY}).contains(version))
                throw Exception(QString("Unknown mempool.dat version: %1").arg(qulonglong(version)));
            if (version == BTC_VERSION_XOR_KEY) {
                std::vector<std::byte> xor_key;
                file >> xor_key;
                file.SetXor(std::move(xor_key));
            }

            uint64_t num;
            file >> num;
            Log("Loading %llu mempool transactions from file...", static_cast<unsigned long long>(num));

            while (num--) {
                if (interrupted) throw Exception("Interrupted");
                bitcoin::CTransactionRef ctx;
                int64_t nTime;
                int64_t nFeeDelta;
                file >> ctx;
                file >> nTime;
                file >> nFeeDelta;
                if (!isSegWit && ctx->HasWitness())
                    isSegWit = true;

                auto rtx = std::make_shared<Mempool::Tx>();
                rtx->hash = BTC::Hash2ByteArrayRev(ctx->GetHashRef());
                dataTotal += rtx->sizeBytes = ctx->GetTotalSize(isSegWit, false);
                rtx->vsizeBytes = isSegWit ? ctx->GetVirtualSize(rtx->sizeBytes) : rtx->sizeBytes;
                ret.emplace(std::piecewise_construct,
                            std::forward_as_tuple(rtx->hash),
                            std::forward_as_tuple(std::move(rtx), std::move(ctx)));
            }
        } catch (const std::exception &e) {
            throw Exception(QString("Failed to deserialize mempool data: %1").arg(e.what()));
        }
        Log("Imported mempool: %d txs, %1.2f MB in %1.3f msec", int(ret.size()), dataTotal / 1e6, t0.msec<double>());
        return {std::move(ret), isSegWit};
    }

    // given a set of root txids, adds all the txids for every tx involved in the full descendant and sibling dag
    // of `txidsIn`
    Mempool::TxHashSet makeFullPackages(const Mempool &pool, const Mempool::TxHashSet &txidsIn)
    {
        auto txids = txidsIn;
        // returns all the descendant tx's given a txid. includes txid itself in the resultant set.
        auto getDescendants = [&pool](const TxHash &txid) {
            Mempool::TxHashSet ret, workQueue;
            workQueue.insert(txid);
            while (!workQueue.empty()) {
                const auto txhash = *workQueue.begin();
                workQueue.erase(workQueue.begin());
                if (!ret.insert(txhash).second) continue; // already seen, skip
                if (auto it = pool.txs.find(txhash); it != pool.txs.end()) {
                    for (const auto & [childtxid, _] : it->second->children)
                        workQueue.insert(childtxid);
                } else throw Exception("getDescendants: Unexpected state; a txid is missing from the mempool. FIXME!");
            }
            return ret;
        };
        // expands txid's that spend unconfirmed txos from other tx's not in the set txids
        auto mogrifyToPackage = [&pool, &txids, &getDescendants] {
            Mempool::TxHashSet seen;
        start:
            for (const auto & txid : txids) {
                if (!seen.insert(txid).second) continue; // already seen, skip
                const auto it = pool.txs.find(txid);
                if (it == pool.txs.end()) throw Exception("Unexpected: a txid is missing from the mempool. FIXME!");
                const auto & tx = it->second;
                const auto beforeSize = txids.size();
                for (const auto & [ptxid, _] : tx->parents)
                    txids.merge(getDescendants(ptxid));
                if (txids.size() != beforeSize) goto start; // `txids` grew, must break loop and start again
            }
        };
        for (const auto & txid : txidsIn) {
            if (interrupted) throw Exception("Interrupted");
            txids.merge(getDescendants(txid));
        }
        mogrifyToPackage();
        return txids;
    }

    TXOMap getCoinsFromBitcoinD(const QString &bitciondEnvSpec, const MPData &mpd) {
        TXOMap ret;
        // format is: user:pass@ip:port
        const auto sl = bitciondEnvSpec.split('@');
        constexpr auto *msg = "Excpected BITCOIND user:pass@ip:port";
        if (sl.size() != 2) throw Exception(msg);
        const auto upl = sl.front().split(':');
        if (upl.size() != 2) throw Exception(msg);
        const QString user = upl.front(), pass = upl.back();
        const auto hostPort = Util::ParseHostPortPair(sl.back(), true);
        Debug() << "BitcoinD host:port: " << hostPort.first << ":" << hostPort.second;
        BitcoinD_RPCInfo info;
        info.setStaticUserPass(user, pass);
        info.hostPort = hostPort;
        QThread dummyThr;
        Defer d([&dummyThr]{
            dummyThr.quit();
            Debug() << "Waiting for thread ...";
            dummyThr.wait();
        });
        BitcoinDMgr bitcoindMgr(Options::defaultBdNClients, info);
        dummyThr.start();
        std::promise<bool> promise;
        auto future = promise.get_future();
        QObject context;
        context.moveToThread(&dummyThr);
        bitcoindMgr.connect(&bitcoindMgr, &BitcoinDMgr::gotFirstGoodConnection, &context, [&promise]{ promise.set_value(true); });
        bitcoindMgr.connect(&bitcoindMgr, &BitcoinDMgr::allConnectionsLost, &context, [&promise]{ promise.set_value(false); });
        Debug() << "Starting BitcoinDMgr ...";
        bitcoindMgr.startup();
        if (auto res = future.wait_for(std::chrono::seconds{5}); res != std::future_status::ready)
            throw Exception("No BitcoinD connections are ready after 5 seconds");
        else if (!future.get())
            throw Exception("Failed to connect to BitcoinD at " + bitciondEnvSpec);
        using PrevTxMap = std::unordered_map<bitcoin::uint256, bitcoin::CTransactionRef, BTC::uint256HashHasher>;
        PrevTxMap prevTxs;
        std::mutex mutPrevTxs;
        Log() << "Retrieving coins from bitcoind for " << mpd.size() << " txns ...";
        Tic t0;
        std::atomic_size_t totalBytes = 0u, txnsDld = 0u;
        size_t ctr = 0u, lastPrt = 0u;
        auto add = [&ret, &ctr](const TXO &txo, const bitcoin::CTransactionRef &prevTx) {
            const auto & [it, inserted] = ret.try_emplace(txo);
            ctr += inserted;
            TXOInfo & info = it->second;
            const auto & txout = prevTx->vout.at(txo.outN);
            info.hashX = BTC::HashXFromCScript(txout.scriptPubKey);
            info.amount = txout.nValue;
            info.tokenDataPtr = txout.tokenDataPtr;
            // NB: we leave .txNum and .confirmedHeight blank for now...
        };
        using PairFutureAndTXOs = std::pair<std::future<QString>, std::vector<TXO>>;
        using InTransitTxMap = std::unordered_map<bitcoin::uint256, PairFutureAndTXOs, BTC::uint256HashHasher>;
        InTransitTxMap inTransit;
        auto waitForFutures = [&inTransit, &prevTxs, &mutPrevTxs, &add] {
            for (auto it = inTransit.begin(); it != inTransit.end(); it = inTransit.erase(it)) {
                const auto & txId = it->first;
                auto & [future, txoVec] = it->second;
                if (!future.valid())
                    throw Exception("Invalid future for " + QString::fromStdString(txId.ToString()));
                if (auto res = future.wait_for(std::chrono::seconds{10}); res != std::future_status::ready)
                    throw Exception("Timeout waiting for tx for " + QString::fromStdString(txId.ToString()));
                else if (const QString errStr = future.get(); !errStr.isEmpty())
                    throw Exception("Failed to get tx for " + QString::fromStdString(txId.ToString()) + ": " + errStr);
                bitcoin::CTransactionRef prevTx;
                {
                    std::unique_lock g(mutPrevTxs);
                    if (const auto it = prevTxs.find(txId); it != prevTxs.end())
                        prevTx = it->second;
                }
                if (!prevTx) throw Exception("Could not find prevtx for " + QString::fromStdString(txId.ToString()));
                for (const auto & txo : txoVec)
                    add(txo, prevTx);
            }
            qApp->processEvents();
        };
        for (const auto & [txHash, item] : mpd) {
            if (interrupted) throw Exception("Interrupted");
            const auto & [mtx, tx] = item;
            for (const auto & in : tx->vin) {
                TXO txo;
                const auto &prevoutTxId = in.prevout.GetTxId();
                txo.txHash = BTC::Hash2ByteArrayRev(prevoutTxId);
                if (mpd.contains(txo.txHash)) continue; // mempool txn, no need to retrieve anything
                txo.outN = in.prevout.GetN();
                bitcoin::CTransactionRef prevTx;
                {
                    std::unique_lock g(mutPrevTxs);
                    if (auto it = prevTxs.find(in.prevout.GetTxId()); it != prevTxs.end())
                        prevTx = it->second;
                }
                if (!prevTx) {
                    // retrieve from bitcoind
                    if (auto it = inTransit.find(prevoutTxId); it != inTransit.end()) {
                        if (!it->second.first.valid()) Error() << "Expected valid future for txId: " << prevoutTxId.ToString();
                        it->second.second.push_back(std::move(txo));
                    } else {
                        auto & [future, txoVec] = inTransit[prevoutTxId];
                        if (future.valid()) Error() << "Expected invalid future for txId: " << prevoutTxId.ToString();
                        if (!txoVec.empty()) Error() << "Expected empty txoVec for txId: " << prevoutTxId.ToString();
                        auto promiseRef = std::make_shared<std::promise<QString>>();
                        future = promiseRef->get_future();
                        const auto hashHex = QString::fromLatin1(Util::ToHexFast(txo.txHash));
                        txoVec.push_back(std::move(txo));
                        bitcoindMgr.submitRequest(
                            &context, ::app()->newId(), "getrawtransaction", {hashHex, false},
                            [&totalBytes, &prevTxs, &mutPrevTxs, &txnsDld, promiseRef] (const RPC::Message &msg) mutable {
                                ++txnsDld;
                                try {
                                    const auto bytes = Util::ParseHexFast(msg.result().toString().toLatin1());
                                    totalBytes += bytes.length();
                                    bitcoin::CMutableTransaction mtx;
                                    BTC::Deserialize(mtx, bytes, 0, true);
                                    auto txref = bitcoin::MakeTransactionRef(std::move(mtx));
                                    {
                                        std::unique_lock g(mutPrevTxs);
                                        prevTxs.try_emplace(txref->GetHashRef(), std::move(txref));
                                    }
                                    promiseRef->set_value(QStringLiteral(""));
                                } catch (const std::exception &e) {
                                    promiseRef->set_value(QString("Exception: ") + QString::fromUtf8(e.what()));
                                }
                            },
                            [promiseRef](const RPC::Message &m) {
                                promiseRef->set_value("BitcoinD Error result: " + m.errorMessage());
                            },
                            [promiseRef](const RPC::Message::Id &, const QString & failureReason){
                                promiseRef->set_value("BitcoinD Failure: " + failureReason);
                            }
                        );
                    }
                } else { /* prevTx != nullptr */
                    // already have the tx, add the coin we need from it
                    add(txo, prevTx);
                }
                if ((ctr - lastPrt) >= 1000u) {
                    Debug() << (lastPrt = ctr) << " inputs, " << txnsDld.load() << " txns, "
                            << QString::number(totalBytes.load() / 1e6, 'f', 3) << " MB, " << t0.secsStr() << " secs";
                    qApp->processEvents();
                }
                if (inTransit.size() >= 16)
                    waitForFutures();
            }
        }
        waitForFutures();
        Log() << "Got " << ret.size() << " coins, " << txnsDld.load() << " txns, in " << t0.secsStr() << " secs";
        return ret;
    }

    void bench() {
        /* This bench/test is VERY long... TODO: Refactor this someday... */

        Debug::forceEnable = true;
        const char * const mpdat = std::getenv("MPDAT");
        if (!mpdat) {
            throw Exception("Mempool benchmark requires the MPDAT environment variable, which should be a path to a "
                            "mempool.dat taken from either BCHN, BU, or a BTC (Core) bitcoind..");
        }

        // If user hits CTRL-C, exit gracefully
        const auto prevHandler = std::signal(SIGINT, [](int sig) {
            if (bool expected = false; interrupted.compare_exchange_strong(expected, true))
                Util::AsyncSignalSafe::writeStdErr(Util::AsyncSignalSafe::SBuf("\n--- Caught signal ", sig, ", exiting ..."));
        });
        Defer d([prevHandler]{
            std::signal(SIGINT, prevHandler);
            interrupted = false; // reset
        });

        const auto mem0 = Util::getProcessMemoryUsage();
        Log() << "Mem usage: physical " << QString::number(mem0.phys / 1024.0, 'f', 1)
              << " KiB, virtual " << QString::number(mem0.virt / 1024.0, 'f', 1) << " KiB";


        const auto && [mpd, isSegWit] = loadMempoolDat(mpdat);

        if (isSegWit) bitcoin::SetCurrencyUnit("BTC");

        TXOMap realCoins;

        if (auto const * envbdinfo = std::getenv("BITCOIND"))
            // may throw, otherwise will reach out to bitcoin daemon for prevtxs to populate coin map
            realCoins = getCoinsFromBitcoinD(QString::fromUtf8(envbdinfo), mpd);

        static const auto deepCopyMPD = [](const MPData &other) -> MPData {
            MPData ret;
            for (const auto & [txid, pair] : other) {
                const auto & [tx, ctx] = pair;
                // we only copy the TxRef; the CTransactionRef is immutable and it doesn't need to be copied
                auto txCopy = std::make_shared<Mempool::Tx>(*tx);
                ret.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(txCopy, ctx));
            }
            return ret;
        };

        enum IterMode { DropOnlyLeaves, DropAnyTx, ConfirmOnlyRoots, ConfirmAnyTx, ConfirmPackages, };
        constexpr IterMode iterModes[] = { DropOnlyLeaves, ConfirmOnlyRoots, ConfirmPackages, ConfirmAnyTx, DropAnyTx };

        for (const auto iterMode : iterModes) { // try all modes

            Mempool::TxHashNumMap txNumMap;
            const BlockHeight confirmedHeightStart = 2 + QRandomGenerator::global()->generate() % 1'000'000; // random blockHeight for conf
            std::unordered_set<BlockHeight> okConfHeights; okConfHeights.insert(confirmedHeightStart);
            TXOMap confirmedTXOInfos = realCoins; // realCoins is empty unless we got them from bitcoind via (BITCOIND env var)
            TxNum txNumLast = 0;
            BlockHeight confirmedHeightCur = confirmedHeightStart;

            auto getTxNum = [&txNumLast, &txNumMap](const TxHash &txHash, bool create) -> std::optional<TxNum> {
                auto it = txNumMap.find(txHash);
                if (it == txNumMap.end()) {
                    if (!create)
                        return std::nullopt;
                    it = txNumMap.emplace(txHash, ++txNumLast).first;
                }
                return it->second;
            };
            auto getTXOInfo = [&getTxNum, &confirmedHeightCur, &confirmedTXOInfos](const TXO &txo) -> std::optional<TXOInfo> {
                // Return a "unique" but deterministic TXOInfo based on the txo's prevout:n.
                // Note the amount here is totally wrong (and leads to txs that print money out of thin air),
                // but for this test this is ok, since we care more about properly debiting/crediting spends
                // and keeping track of utxos when testing Mempool.
                TXOInfo ret;
                if (auto it = confirmedTXOInfos.find(txo); it != confirmedTXOInfos.end()) {
                    // use cached
                    auto & txoInfo = it->second;
                    if (!txoInfo.confirmedHeight) {
                        // needs a confirmedHeight, update
                        txoInfo.confirmedHeight = confirmedHeightCur;
                        txoInfo.txNum = *getTxNum(txo.txHash, true);
                    }
                    return txoInfo;
                }
                ret.amount = 546 * bitcoin::Amount::satoshi();
                ret.confirmedHeight = confirmedHeightCur;
                // set of 50 unique hashx's, based upon the txo's hash value
                constexpr int64_t NAddressTarget = 50;
                const bitcoin::CScriptNum scriptNum{int64_t(1 + std::hash<TXO>{}(txo) % NAddressTarget)};
                ret.hashX = BTC::HashXFromCScript(bitcoin::CScript() << scriptNum);
                //ret.hashX = BTC::HashXFromCScript(bitcoin::CScript() << Util::toVec<std::vector<uint8_t>>(txo.toBytes(false)));
                ret.txNum = *getTxNum(txo.txHash, true);
                // cache
                confirmedTXOInfos.emplace(txo, ret);
                return ret;
            };

            Log() << QString(79, QChar{'-'});
            Mempool mempool;
            mempool.optPrefixTable.emplace(); // enable RPA indexing
            {
                Mempool::ScriptHashesAffectedSet shset;
                auto t0 = Tic();
                const auto stats = mempool.addNewTxs(shset, deepCopyMPD(mpd), getTXOInfo);
                t0.fin();
                Log() << "Added to mempool in " << t0.msecStr() << " msec."
                      << " Scripthashes: " << shset.size() << ", size: " << stats.newSize << ", addresses " << stats.newNumAddresses;
                shset.clear();
                const auto mem = Util::getProcessMemoryUsage();
                Log() << "Mem usage: physical " << QString::number(mem.phys / 1024.0, 'f', 1)
                      << " KiB, virtual " << QString::number(mem.virt / 1024.0, 'f', 1) << " KiB";
                Log() << "Delta phys: " << QString::number((mem.phys - mem0.phys) / 1024.0, 'f', 1) << " KiB";
            }

            Log() << QString(79, QChar{'-'});
            Log();
            switch (iterMode) {
            case DropOnlyLeaves:
                Log() << "Running \"drop leaves\" test ...";
                break;
            case DropAnyTx:
                Log() << "Running \"drop any\" test (this test is slow, please be patient) ...";
                break;
            case ConfirmOnlyRoots:
                Log() << "Running \"confirm only non-unconf-parent\" test (this test is slow, please be patient) ...";
                break;
            case ConfirmPackages:
                Log() << "Running \"confirm packages\" test (this test is slow, please be patient) ...";
                break;
            case ConfirmAnyTx:
                Log() << "Running \"confirm any\" test ...";
                break;
            }
            Log();

            {
                auto t0 = Tic();
                qint64 actualTimeCost = 0;
                bool dumped = false;
                // iterate each time, dropping leaves from mempool
                for (int iterCt = 1; !mempool.txs.empty(); ++iterCt) {
                    if (interrupted) throw Exception("Interrupted");
                    Mempool::TxHashSet txids;
                    Mempool::TxHashNumMap txidMap;
                    if (iterMode == DropOnlyLeaves) {
                        for (const auto & [txHash, tx] : mempool.txs) {
                            std::unordered_set<IONum> ionums;
                            for (const auto & [hashX, ioinfo] : tx->hashXs) {
                                for (const auto & n : ioinfo.utxo)
                                    ionums.insert(n);
                            }
                            // drop only leaves mode
                            std::size_t validSize = 0;
                            for (const auto & txo : tx->txos)
                                validSize += txo.isValid();
                            if (ionums.size() == validSize) {
                                // this is a leaf
                                txids.insert(txHash);
                            }
                        }
                    } else if (iterMode == ConfirmOnlyRoots || iterMode == ConfirmPackages) {
                        for (const auto & [txHash, tx] : mempool.txs) {
                            if (!tx->hasUnconfirmedParents()) {
                                // no unconf parent -- eligible this iteration!
                                txids.insert(txHash);
                            }
                        }
                    } else {
                        // other iterations drop/confirm anything not just leaf or root! (slower)
                        txids = Util::keySet<decltype(txids)>(mempool.txs);
                    }
                    if (txids.empty())
                        throw InternalError("Expected to find at least 1 leaf tx! This should not happen! FIXME!");

                    // do at most 250 drops each iter, randomizing which get dropped
                    constexpr std::size_t iterLimit = 250;
                    if (txids.size() > iterLimit) {
                        auto tvec = Util::toVec(txids);
                        Util::shuffle(tvec.begin(), tvec.end());
                        tvec.resize(iterLimit);
                        txids = Util::toCont<decltype(txids)>(tvec);
                    }

                    const bool isConfirmMode = iterMode == ConfirmAnyTx || iterMode == ConfirmOnlyRoots
                                               || iterMode == ConfirmPackages;

                    if (isConfirmMode) { // this input mode expects a txhash -> txnum map so build one
                        if (iterMode == ConfirmPackages) {
                            // special mode, add all descendants (and siblings) to set as a "package"
                            txids = makeFullPackages(mempool, txids);
                        }
                        for (const auto & txid : txids)
                            txidMap.emplace(txid, *getTxNum(txid, true));
                    }

                    struct Expected {
                        TXOMap unconfUtxos;
                        bitcoin::Amount unconfUtxoValue;
                        Mempool::ScriptHashesAffectedSet affected;
                    } expected;

                    const auto getUnconfUtxos = [&mempool]() -> std::pair<TXOMap, bitcoin::Amount> {
                        TXOMap ret;
                        ret.reserve(mempool.txs.size() * 4); // rough guess
                        bitcoin::Amount value;
                        for (const auto &[txid, tx] : mempool.txs) {
                            for (const auto &[sh, ioinfo] : tx->hashXs) {
                                for (const auto &ionum : ioinfo.utxo) {
                                    const TXO txo{txid, ionum};
                                    const bool isnew = ret.emplace(txo, tx->txos[ionum]).second;
                                    if (isnew)
                                        value += tx->txos[ionum].amount;
                                    else
                                        throw Exception(QString("getUnconfUtxos: non-unique utxo encountered %1! FIXME!").arg(txo.toString()));
                                    //Log() << "Added: " << txo.toString();
                                }
                            }
                        }
                        return {std::move(ret), value};
                    };

                    bitcoin::Amount beforeAmt;
                    std::size_t beforeSize{};

                    // build expected set to verify the results of calling dropTxs() (works only in leaf mode (iter == 0)
                    if (iterMode == DropOnlyLeaves) {

                        // build utxo set we have now
                        std::tie(expected.unconfUtxos, expected.unconfUtxoValue) = getUnconfUtxos();

                        beforeSize = expected.unconfUtxos.size();
                        beforeAmt = expected.unconfUtxoValue;

                        for (const auto &txid : txids) {
                            const auto &tx = mempool.txs[txid];
                            for (const auto &[sh, ioinfo] : tx->hashXs) {
                                expected.affected.insert(sh);
                                for (const auto &[txo, txoinfo] : ioinfo.unconfirmedSpends) {
                                    const bool isnew = expected.unconfUtxos.emplace(txo, txoinfo).second;
                                    if (!isnew) throw Exception(QString("Non-unique utxo encountered %1! FIXME!").arg(txo.toString()));
                                    expected.unconfUtxoValue += txoinfo.amount;
                                    auto it = mempool.txs.find(txo.txHash);
                                    if (it == mempool.txs.end())
                                        throw Exception(QString("Could not find prev out %1 for unconfirmed spend for txid %2")
                                                        .arg(txo.toString(), QString(txid.toHex())));
                                    if ( ! it->second->hashXs.contains(txoinfo.hashX))
                                        throw Exception(QString("Coult not find prev out %1 hashx %2 for unfonfirmed spend for txid %3")
                                                        .arg(txo.toString(), QString(txoinfo.hashX.toHex()), QString(txid.toHex())));
                                    expected.affected.insert(txoinfo.hashX);
                                }
                            }
                            // delete existing, subtracting utxo value for each
                            int i = -1;
                            for (const auto &txoinfo : tx->txos) {
                                ++i;
                                if (!txoinfo.isValid()) continue;
                                const TXO txo{txid, IONum(i)};
                                expected.unconfUtxoValue -= txoinfo.amount;
                                expected.unconfUtxos.erase(txo);
                            }
                        }
                    }


                    QVariantMap dumpBefore;
                    if constexpr (false) {
                        if (!dumped && mempool.txs.size() < 20) {
                            // dump once when we reach 20
                            dumped = true;
                            dumpBefore = mempool.dump();
                        }
                    }

                    if (isConfirmMode)
                        confirmedHeightCur = confirmedHeightStart + iterCt;

                    if (iterMode == ConfirmOnlyRoots || iterMode == ConfirmPackages) {
                        // must add txidMap tx's to the confirmed set. Since in this mode we verify by building a dupe
                        // mempool; everything must compare the same -- so we must cache the txoioinfo now for later,
                        // this simulates natural confirmation of tx's ... and getting from db later for addTxs
                        for (const auto & [txid, txnum] : txidMap) {
                            auto it = mempool.txs.find(txid);
                            if (it == mempool.txs.end()) throw Exception("Unexpected state: txid in txidMap has not tx in mempool.txs");
                            const auto & tx = it->second;
                            IONum n = 0;
                            for (const auto & txoinfo : tx->txos) {
                                if (txoinfo.isValid()) {
                                    const TXO txo{txid, n};
                                    TXOInfo infoConfirmed(txoinfo);
                                    // overwrite with the confirmed info now for the cache
                                    infoConfirmed.confirmedHeight = confirmedHeightCur;
                                    infoConfirmed.txNum = txnum;
                                    if (!confirmedTXOInfos.try_emplace(txo, infoConfirmed).second)
                                        throw Exception("Unexpected state: a mempool txo is in the confirmed txo's set already!");
                                }
                                ++n;
                            }
                            // extra sanity check
                            if (iterMode == ConfirmPackages) {
                                for (const auto & [sh, ioinfo] : tx->hashXs) {
                                    for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                                        if (!txidMap.contains(txo.txHash))
                                            throw Exception(QString("Unexpected: txid %1 spends unconfirmed parent txo "
                                                                    "%2 which is not in the confirm set!")
                                                            .arg(QString(txid.toHex()), txo.toString()));
                                    }
                                }
                            }
                        }
                    }

                    Mempool::ScriptHashesAffectedSet shset;
                    auto t1 = Tic();
                    const auto stats = isConfirmMode
                                       ? okConfHeights.insert(confirmedHeightCur),
                                         mempool.confirmedInBlock(shset, txidMap, confirmedHeightCur, false)
                                       : mempool.dropTxs(shset, std::as_const(txids), false);
                    t1.fin();
                    actualTimeCost += t1.usec();

                    // sanity check to catch bugs in this very test... since this code is now long. :)
                    if (isConfirmMode && txids != Util::keySet<decltype(txids)>(txidMap))
                        throw InternalError("Expected to build the corresponding txidMap for txidSet! FIXME!");

                    const auto [utxos, value] = getUnconfUtxos();
                    if (iterMode == DropOnlyLeaves) {
                        Log() << "Iter " << iterCt << ": oldSize: " << stats.oldSize << " newSize: " << stats.newSize
                              << " oldNumAddresses: " << stats.oldNumAddresses << " newNumAddresses: " << stats.newNumAddresses
                              << " shsaffected: " << shset.size()  << " utxoSetSize: " << beforeSize << " -> " << utxos.size()
                              << " value: " << QString::fromStdString(beforeAmt.ToString()) << " -> " << QString::fromStdString(value.ToString())
                              << " (" << QString::fromStdString((value - beforeAmt).ToString()) << ")"
                              << " in " << t1.msecStr(1) << " msec";
                    } else {
                        Log() << "Iter " << iterCt << ": oldSize: " << stats.oldSize << " newSize: " << stats.newSize
                              << " oldNumAddresses: " << stats.oldNumAddresses << " newNumAddresses: " << stats.newNumAddresses
                              << " shsaffected: " << shset.size()  << " utxoSetSize: " << utxos.size()
                              << " value: " << QString::fromStdString(value.ToString())
                              << " in " << t1.msecStr(1) << " msec";
                    }
                    if (!dumpBefore.isEmpty()) {
                        const QVariantMap dumpAfter = mempool.dump();
                        Log() << QString(79, QChar{'-'});
                        Log() << "Dump, before:";
                        Log() << Json::toUtf8(dumpBefore);
                        Log() << "Dump, after:";
                        Log() << Json::toUtf8(dumpAfter);
                        Log() << QString(79, QChar{'-'});
                    }

                    // general sanity checks
                    {
                        // check the sanity of the unconf flag, among other things
                        for (const auto & [txid, tx] : mempool.txs) {
                            std::size_t nUnconf = 0;
                            for (const auto & [sh, ioinfo] : tx->hashXs) {
                                nUnconf += ioinfo.unconfirmedSpends.size();
                                for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                                    if (!mempool.txs.contains(txo.txHash))
                                        throw Exception("A scripthash now refers to an unconfirmed spend that no longer exists");
                                    if (txoinfo.confirmedHeight)
                                        throw Exception("An unconfirmed spend has a confirmedHeight");
                                    if (txoinfo.txNum != 0)
                                        throw Exception("An unconfirmed spend has a confirmed txNum");
                                }
                                // check sanity of confirmedSpends
                                for (const auto & [txo, txoinfo] : ioinfo.confirmedSpends) {
                                    if (mempool.txs.contains(txo.txHash))
                                        throw Exception("A scripthash now refers to a \"confirmed spend\" that is still in mempool");
                                    if (!txoinfo.confirmedHeight.has_value())
                                        throw Exception("A \"confirmed spend\" has no confirmedHeight");
                                    if (!okConfHeights.contains(*txoinfo.confirmedHeight))
                                        throw Exception("A \"confirmed spend\" has unexpected/junk confirmedHeight");
                                    if (auto optNum = getTxNum(txo.txHash, false); !optNum || *optNum != txoinfo.txNum)
                                        throw Exception("A \"confirmed spend\" has invalid txNum");
                                    if (const auto it = txidMap.find(txo.txHash);
                                            it != txidMap.end() && txoinfo.txNum != it->second)
                                        throw Exception("A \"confirmed spend\" has unexpected txNum");
                                }
                            }
                            if (bool(nUnconf) != tx->hasUnconfirmedParents())
                                throw Exception("A tx has bad \"hasUnconfirmedParentTx\" flag now!");
                        }
                        // check that hashXTxs doesn't refer to anything that has been removed and that hashXTxs
                        // order is correct
                        std::set<TxHash> setInVecs;
                        for (const auto & [sh, txvec] : mempool.hashXTxs) {
                            std::set<TxHash> setInVecsThisSh;
                            const Mempool::TxRef *pprev = nullptr;
                            for (const auto & tx : txvec) {
                                if (!tx)
                                    throw Exception("Encountered a nullptr txvec entry!");
                                if (pprev && !(**pprev < *tx))
                                    throw Exception("Encountered bad txvec ordering!");
                                if (pprev && *pprev == tx)
                                    throw Exception("Encountered dupe tx entry in a txvec!");
                                pprev = &tx;
                                if (!mempool.txs.contains(tx->hash))
                                    throw Exception("Encountered a txvec entry pointing to a tx not in mempool!");
                                if (!setInVecsThisSh.insert(tx->hash).second)
                                    throw Exception("Dupe txhash in a txvec encountered");
                            }
                            setInVecs.merge(std::move(setInVecsThisSh));
                        }
                        if (Util::keySet(mempool.txs) != setInVecs)
                            throw Exception("Some txs in mempool.txs are not in txvecs!");
                    }
                    if (iterMode == DropOnlyLeaves || isConfirmMode) {
                        if (stats.oldSize - stats.newSize != txids.size())
                            throw Exception("New tx counts are not as expected!");
                    }
                    if (iterMode == DropOnlyLeaves) {
                        // For now we do these sanity checks only on "leaf" mode (first iteratiorn)
                        if (shset != expected.affected)
                            throw Exception("ScriptHashes affected is not as expected!");
                        if (utxos != expected.unconfUtxos)
                            throw Exception("Resultant utxo set is not as expected!");
                        if (value != expected.unconfUtxoValue)
                            throw Exception("Resultant utxo totals are not as expected!");
                    }
                    if (iterMode == DropAnyTx || iterMode == ConfirmOnlyRoots || iterMode == ConfirmPackages) {
                        // In these modes we do a special verify by building a second mempool with the same txid set
                        // as the first -- this checks that spends and everything else is consistent.
                        // This of course assumes that the "addTxs" code is bug-free and always leads to consistency
                        // (whcih is the case since the addTxs code is very mature at this point).
                        // Note: The below is very *very* slow.
                        Log() << "Verifying resultant mempool (this may take a while) ...";
                        Mempool mempool2;
                        mempool2.optPrefixTable.emplace(); // enable RPA index
                        Mempool::NewTxsMap adds;
                        auto t0 = Tic();
                        auto mpd2 = deepCopyMPD(mpd); // take a deep copy of the original mempool to get unique "untouched" TxRefs
                        Debug() << "Deep copied txs in " << t0.msecStr() << " msec";
                        for (const auto & [txid, xx] : mempool.txs) {
                            auto it = mpd2.find(txid);
                            if (it == mpd2.end())
                                throw InternalError(QString("TxId %1 not found. This should never happen.").arg(QString(txid.toHex())));
                            if (txids.contains(txid))
                                throw Exception("Drop/Confirm verification failed -- a txid in the drop set is still in the mempool structure!");
                            adds.insert(*it);
                        }
                        Mempool::ScriptHashesAffectedSet xx;
                        auto t1 = Tic();
                        mempool2.addNewTxs(xx, adds, getTXOInfo);
                        Debug() << "Added to a dupe mempool in " << t1.msecStr() << " msec";
                        if (QString estr; !mempool.deepCompareEqual(mempool2, &estr)) {
                            const QStringList lines = estr.split("\n");
                            if (lines.size() > 1) {
                                Log(Log::Color::Cyan) << "Difference info:\n" << lines.mid(1).join("\n");
                            }
                            throw Exception(QString("Drop/Confirm verification failed -- mempool != mempool2: %1").arg(lines.front()));
                        }
                        Log() << "Verified ok in " << t0.secsStr() << " secs";
                    }
                }
                t0.fin();
                Log() << "Dropped all from mempool in " << t0.msecStr()
                      << " msec, actual \"non-verification\" processing time was " << QString::number(actualTimeCost / 1e3, 'f', 3) << " msec";
                const auto mem = Util::getProcessMemoryUsage();
                Log() << "Mem usage: physical " << QString::number(mem.phys / 1024.0, 'f', 1)
                      << " KiB, virtual " << QString::number(mem.virt / 1024.0, 'f', 1) << " KiB";
            }
        }
    }

    static const auto bench_ = App::registerBench("mempool", &bench);
}
#endif
