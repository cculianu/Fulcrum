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
#include "Mempool.h"
#include "Util.h"

#include <algorithm>
#include <cassert>
#include <functional>
#include <map>

void Mempool::clear() {
    txs.clear();
    hashXTxs.clear();
    txs.rehash(0); // this should free previous capacity
    hashXTxs.rehash(0);
}

auto Mempool::calcCompactFeeHistogram(double binSize) const -> FeeHistogramVec
{
    // this algorithm is taken from:
    // https://github.com/Electron-Cash/electrumx/blob/fbd00416d804c286eb7de856e9399efb07a2ceaf/electrumx/server/mempool.py#L139
    FeeHistogramVec ret;
    std::map<unsigned, unsigned, std::greater<unsigned>> histogram; // sorted map, descending order by key

    for (const auto & [txid, tx] : txs) {
        const auto feeRate = unsigned(tx->fee / bitcoin::Amount::satoshi()) // sats
                             /  std::max(tx->sizeBytes, 1u); // per byte
        histogram[feeRate] += tx->sizeBytes; // accumulate size by feeRate
    }

    // now, compact the bins
    ret.reserve(8);
    unsigned cumSize = 0;
    double r = 0.;

    for (const auto & [feeRate, size] : histogram) {
        cumSize += size;
        if (cumSize + r > binSize) {
            ret.push_back(FeeHistogramItem{feeRate, cumSize});
            r += double(cumSize) - binSize;
            cumSize = 0;
            binSize *= 1.1;
        }
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
    Stats ret;
    auto & [oldSize, newSize, oldNumAddresses, newNumAddresses, elapsedMsec] = ret;
    oldSize = this->txs.size();
    oldNumAddresses = this->hashXTxs.size();
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
                txoInfo = TXOInfo{out.nValue, sh, {}, {}};
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
    // next, do new inputs for all tx's, debiting/crediting either a mempool tx or querying db for the relevant utxo
    for (auto & [hash, pair] : txsNew) {
        auto & [tx, ctx] = pair;
        assert(hash == tx->hash);
        IONum inNum = 0;
        for (const auto & in : ctx->vin) {
            const IONum prevN = IONum(in.prevout.GetN());
            const TxHash prevTxId = BTC::Hash2ByteArrayRev(in.prevout.GetTxId());
            const TXO prevTXO{prevTxId, prevN};
            TXOInfo prevInfo;
            QByteArray sh; // shallow copy of prevInfo.hashX
            if (auto it = this->txs.find(prevTxId); it != this->txs.end()) {
                // prev is a mempool tx
                tx->hasUnconfirmedParentTx = true; ///< mark the current tx we are processing as having an unconfirmed parent (this is used for sorting later and by the get_mempool & listUnspent code)
                auto prevTxRef = it->second;
                assert(bool(prevTxRef));
                if (prevN >= prevTxRef->txos.size()
                        || !(prevInfo = prevTxRef->txos[prevN]).isValid())
                    // defensive programming paranoia
                    throw InternalError(QString("FAILED TO FIND A VALID PREVIOUS TXOUTN %1:%2 IN MEMPOOL for TxHash: %3 (input %4)")
                                        .arg(QString(prevTxId.toHex())).arg(prevN).arg(QString(hash.toHex())).arg(inNum));
                sh = prevInfo.hashX;
                tx->hashXs[sh].unconfirmedSpends[prevTXO] = prevInfo;
                auto prevHashXIt = prevTxRef->hashXs.find(sh);
                if (prevHashXIt == prevTxRef->hashXs.end())
                    throw InternalError(QString("PREV OUT %1 IS MISSING ITS HASHX ENTRY FOR HASHX %2 (txid: %3)")
                                        .arg(prevTXO.toString(), QString(sh.toHex()), QString(tx->hash.toHex())));
                prevHashXIt->second.utxo.erase(prevN); // remove this spend from utxo set for prevTx in mempool
                if (TRACE) Debug() << hash.toHex() << " unconfirmed spend: " << prevTXO.toString() << " " << prevInfo.amount.ToString().c_str();
            } else {
                // prev is a confirmed tx
                const auto optTXOInfo = getTXOInfo(prevTXO); // this may also throw on low-level db error
                if (UNLIKELY(!optTXOInfo.has_value())) {
                    // Uh oh. If it wasn't in the mempool or in the db.. something is very wrong with our code...
                    // (or there maybe was a race condition and a new block came in while we were doing this).
                    // We will throw if missing, and the synch process aborts and hopefully we recover with a reorg
                    // or a new block or somesuch.
                    throw InternalError(QString("FAILED TO FIND PREVIOUS TX %1 IN EITHER MEMPOOL OR DB for TxHash: %2 (input %3)")
                                        .arg(prevTXO.toString()).arg(QString(hash.toHex())).arg(inNum));
                }
                prevInfo = *optTXOInfo;
                sh = prevInfo.hashX;
                // hack to save memory by re-using existing sh QByteArray and/or forcing a shallow-copy
                auto hxit = tx->hashXs.find(sh);
                if (hxit != tx->hashXs.end()) {
                    // existing found, re-use same unerlying QByteArray memory for sh
                    sh = prevInfo.hashX = hxit->first;
                } else {
                    // new entry, insert, update hxit
                    auto pair = tx->hashXs.emplace(std::piecewise_construct, std::forward_as_tuple(sh), std::forward_as_tuple());
                    hxit = pair.first;
                }
                // end memory saving hack
                hxit->second.confirmedSpends[prevTXO] = prevInfo;
                if (TRACE) Debug() << hash.toHex() << " confirmed spend: " << prevTXO.toString() << " " << prevInfo.amount.ToString().c_str();
            }
            tx->fee += prevInfo.amount;
            assert(sh == prevInfo.hashX);
            this->hashXTxs[sh].push_back(tx); // mark this hashX as having been "touched" because of this input (note we push dupes here out of order but sort and uniqueify at the end)
            scriptHashesAffected.insert(sh);
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

    newSize = this->txs.size();
    newNumAddresses = this->hashXTxs.size();
    elapsedMsec = t0.msec<decltype(elapsedMsec)>();
    return ret;
}

std::size_t Mempool::growTxHashSetToIncludeDescendants(const char *const logpfx, TxHashSet &txids, const bool TRACE) const
{
    if (txids.empty())
        return 0;

    std::size_t added = 0, iterct = 0;
    bool found;

    // "recursively" find txids spending from a source set. Implicitly keeps adding
    // to the resulting set until all dependant txs in mempool are covered.
    const auto t0 = Tic();
    do {
        ++iterct;
        found = false;
        for (const auto & [txid, tx] : txs) {
            if (!tx->hasUnconfirmedParentTx || txids.count(txid))
                continue; // no unconf. parents or already added
            for (const auto & [sh, ioinfo] : tx->hashXs) {
                for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                    if (txids.count(txo.txHash)) {
                        // this spends one of the ones in our set! add it since it's a child of something we want to remove.
                        txids.emplace(txid);
                        ++added;
                        if (TRACE)
                            DebugM(logpfx, ": additonal tx ", Util::ToHexFast(txid), " added to set because it spends ",
                                   txo.toString(), " which is already in our removal set");
                        found = true;
                        goto next_txid;
                    }
                }
            }
        next_txid:
            continue;
        }
    } while (found);

    using Util::Pluralize;
    DebugM(logpfx, ": iterated ", iterct, Pluralize(" time", iterct), " to add ", added, Pluralize(" additional child tx", added),
           " in ", t0.msecStr(2), " msec");
    return added;
}

std::size_t Mempool::growTxHashSetToIncludeDescendants(TxHashSet &txids, const bool TRACE) const
{
    return growTxHashSetToIncludeDescendants("txDescendants", txids, TRACE);
}

auto Mempool::dropTxs(ScriptHashesAffectedSet & scriptHashesAffectedOut, const TxHashSet & txidsIn, bool TRACE,
                      std::optional<float> rehashMaxLoadFactor) -> Stats
{
    const auto t0 = Tic();
    auto txids = txidsIn;
    // also drop txs that spend from the txids in the above set as well -- since we
    // cannot drop tx's in the middle of a chain of spends due to the inconsistency
    // that would lead to (possible spends of non-existant outputs).
    growTxHashSetToIncludeDescendants("dropTxs", txids, TRACE);

    Stats ret;
    ScriptHashesAffectedSet scriptHashesAffected;
    int skipPrevCt = 0;
    auto & [oldSize, newSize, oldNumAddresses, newNumAddresses, elapsedMsec] = ret;
    oldSize = this->txs.size();
    oldNumAddresses = this->hashXTxs.size();

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
                if (txids.count(txo.txHash)) {
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
                            Warning() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
                                      << "expected TXOInfo for this tx to match with spending tx " << txid.toHex()
                                      << "'s TXOInfo! FIXME!";
                        }
                        if (UNLIKELY(prevTxoInfo.hashX != hashX)) {
                            Warning() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
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
                            Warning() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " -- "
                                      << "cannot find hashX " << hashX.toHex() << " in tx map! FIXME!";
                        }
                    } else {
                        Warning() << "dropTxs: Previous out " << txo.txHash.toHex() << ":" << txo.outN << " is "
                                  << " invalid (this output is spent by the dropped tx " << txid.toHex() << ")! FIXME!";
                    }
                } else {
                    Warning() << "dropTxs: Previous tx " << txo.txHash.toHex() << " which has outputs spent by "
                              << "(dropped) tx " << txid.toHex() << " is not found in mempool! This is unexpected! FIXME!";
                }
            }
        }

        // and finally remove this tx from `txs` now, while we have its iterator .. this is faster
        // than doing the remove later, since we already have the iterator now!
        txs.erase(it);
    }

    if (skipPrevCt)
        DebugM("dropTxs: previous tx \"crediting\" skipped due to being in drop set: ", skipPrevCt);

    // next, scan hashXs, removing entries for the txids in question
    // -- note this helper function doesn't look at `txs` so it's fine that we removed already in the loop above.
    rmTxsInHashXTxs(txids, scriptHashesAffected, TRACE);

    // finally, update scriptHashesAffectedOut
    scriptHashesAffectedOut.merge(std::move(scriptHashesAffected));

    // update returned stats
    newSize = this->txs.size();
    newNumAddresses = this->hashXTxs.size();

    if (rehashMaxLoadFactor) {
        if (txs.load_factor() <= *rehashMaxLoadFactor)
            txs.rehash(0); // shrink to fit
        if (hashXTxs.load_factor() <= *rehashMaxLoadFactor)
            hashXTxs.rehash(0);  // shrink to fit
    }
    elapsedMsec = t0.msec<decltype(elapsedMsec)>();
    return ret;
}

std::size_t Mempool::rmTxsInHashXTxs(const TxHashSet &txids, const ScriptHashesAffectedSet &scriptHashesAffected, const bool TRACE,
                                     const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort)
{
    Tic t0;
    std::size_t ct = 0, sortCt = 0;
    qint64 sortTimeNanos = 0;

    // next, scan hashXs, removing entries for the txids in question
    for (const auto & hashX : scriptHashesAffected) {
        auto it = hashXTxs.find(hashX);
        if (UNLIKELY(it == hashXTxs.end())) {
            Warning() << "rmTxsInHashXTxs: Could not find scripthash " << hashX.toHex() << " in hashXTxs map! FIXME!";
            continue;
        }
        auto & txvec = it->second;
        if (UNLIKELY(txvec.empty()))
            Warning() << "rmTxsInHashXTxs: txvec for scripthash " << hashX.toHex() << " is empty! This should never happen! FIXME!";
        std::vector<TxRef> newvec;
        newvec.reserve(txvec.size());
        for (auto &txref : txvec) {
            // filter out txids in the set
            if (txids.count(txref->hash) == 0)
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

auto Mempool::confirmedInBlock(ScriptHashesAffectedSet & scriptHashesAffectedOut, const TxHashSet & txids, bool TRACE,
                               std::optional<float> rehashMaxLoadFactor) -> Stats
{
    const auto t0 = Tic();

    Stats ret;
    ScriptHashesAffectedSet scriptHashesAffected;
    std::optional<ScriptHashesAffectedSet> hashXTxsEntriesNeedingSort;
    hashXTxsEntriesNeedingSort.emplace();
    auto & [oldSize, newSize, oldNumAddresses, newNumAddresses, elapsedMsec] = ret;
    oldSize = this->txs.size();
    oldNumAddresses = this->hashXTxs.size();

    // iterate through all txs in mempool
    for (auto itTxs = txs.begin(); itTxs != txs.end(); /* may delete during iteration, see below */) {
        const auto & [txid, tx] = *itTxs; // take refs for convenience (note they are invalidated after if erase(itTxs) )
        const bool inRmSet = txids.count(txid);
        if (inRmSet) {
            // this txid is to be removed from mempool, tally its scripthashes as affected by the removal
            for (const auto & [sh, _] : tx->hashXs)
                scriptHashesAffected.insert(sh);
            // and erase NOW!
            itTxs = txs.erase(itTxs); // in this branch: removed, take next it and continue
            continue;
        } else if (tx->hasUnconfirmedParentTx) {
            // This txid is *not* to be removed, but MAY possibly be spending from a tx we are going to remove.
            // Scan all of its unconfirmed spends to see if they spend from a tx in the removal set, and if so,
            // recategorize those spends as confirmed spends.
            std::size_t nUnconfs = 0;
            for (auto & [sh, ioinfo] : tx->hashXs) {
                int ctr = 0;
                for (auto itUS = ioinfo.unconfirmedSpends.begin(); itUS != ioinfo.unconfirmedSpends.end(); /* see below */) {
                    const auto & [txo, _] = *itUS; // take refs for readibility below
                    if (txids.count(txo.txHash)) {
                        // and voila! This tx spends from one of the tx's we are going to remove. Recategorize unconf -> conf.
                        auto it2move = itUS++;  // first make `it` point to `it` + 1, making `it2move` be previous value `it`
                        // transfer from unconfirmed spends -> confirmed spends
                        ioinfo.confirmedSpends.insert(ioinfo.unconfirmedSpends.extract(it2move)); // does not invalidate refs
                        ++ctr;
                        if (TRACE)
                            DebugM("confirmedInBlock: TXO ", txo.toString(), " now recategorized under \"confirmedSpends\" for txid ", tx->hash.toHex());
                    } else
                        // prevout txid not in rm set, keep moving
                        ++itUS;
                }
                // sum up final size, so we can detect when there are no more unconf spends for this tx
                // (this unconf spends map for this sh may have gone from N -> N-1, or N -> N-2, etc, or may now be empty)
                nUnconfs += ioinfo.unconfirmedSpends.size();
                if (ctr && TRACE)
                    DebugM("confirmedInBlock: txid ", tx->hash.toHex(), ", scripthash ", sh.toHex(), " removed ", ctr,
                           " unconf spends (unconf map size for this txid+sh now: ", ioinfo.unconfirmedSpends.size(), ")");
            }
            // check if no more unconf spends now for this tx; if so, reset flag & notify all sh's for this tx
            if (!nUnconfs) {
                tx->hasUnconfirmedParentTx = false;
                for (const auto & [sh, _] : tx->hashXs) {
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
                    DebugM("confirmedInBlock: txid ", tx->hash.toHex(), " now recategorized as not spending any unconfirmed parents");
            }
        }
        ++itTxs; // in this branch: nothing removed, keep iterating
    }

    // now, update hashXTxs as well
    rmTxsInHashXTxs(txids, scriptHashesAffected, TRACE, hashXTxsEntriesNeedingSort);

    // finally, update scriptHashesAffectedOut
    scriptHashesAffectedOut.merge(std::move(scriptHashesAffected));

    // update returned stats
    newSize = this->txs.size();
    newNumAddresses = this->hashXTxs.size();

    if (rehashMaxLoadFactor) {
        if (txs.load_factor() <= *rehashMaxLoadFactor)
            txs.rehash(0); // shrink to fit
        if (hashXTxs.load_factor() <= *rehashMaxLoadFactor)
            hashXTxs.rehash(0);  // shrink to fit
    }
    elapsedMsec = t0.msec<decltype(elapsedMsec)>();
    return ret;
}

QVariantMap Mempool::dump() const
{
    QVariantMap mp, txMap;
    for (const auto & [hash, tx] : txs) {
        if (!tx) continue;
        QVariantMap m;
        m["hash"] = tx->hash.toHex();
        m["sizeBytes"] = tx->sizeBytes;
        m["fee"] = tx->fee.ToString().c_str();
        m["hasUnconfirmedParentTx"] = tx->hasUnconfirmedParentTx;
        static const auto TXOInfo2Map = [](const TXOInfo &info) -> QVariantMap {
            return QVariantMap{
                { "amount", QString::fromStdString(info.amount.ToString()) },
                { "scriptHash", info.hashX.toHex() },
            };
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

        txMap[hash.toHex()] = m;
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

    return mp;
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "BTC.h"
#include "Json/Json.h"
#include "Util.h"

#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"

#include <cstdio>
#include <set>

bool Mempool::deepCompareEqual(const Mempool &o) const noexcept
{
    if (this == &o)
        return true;
    if (txs.size() != o.txs.size())
        return false;
    if (hashXTxs.size() != o.hashXTxs.size())
        return false;
    long ct = 0;
    Defer d([&ct]{ Debug() << "deepCompareEqual: iterated over " << ct << Util::Pluralize(" item", ct); });
    for (const auto & [txid, tx] : txs) {
        ++ct;
        auto it = o.txs.find(txid);
        if (it == o.txs.end()) return false;
        // compare first the shared_ptr (for short-circuit pointer equality) and if that fails, do actual deep compare of Tx object
        const auto & otx = it->second;
        if (tx != otx && *tx != *otx) return false;
        // otherwise equal so far...
    }
    // compare each of the hashXTxs
    for (const auto & [sh, vec] : hashXTxs) {
        ++ct;
        auto it = o.hashXTxs.find(sh);
        if (it == o.hashXTxs.end()) return false;
        const auto & ovec = it->second;
        if (vec.size() != ovec.size()) return false;
        for (std::size_t i = 0; i < vec.size(); ++i) {
            ++ct;
            // compare first the shared_ptr (for short-circuit pointer equality) and if that fails, do actual deep compare of Tx object
            if (vec[i] != ovec[i] && *vec[i] != *ovec[i])
                return false;
        }
        // otherwise equal so far...
    }
    // couldn't find an inequality, return true
    return true;
}

namespace {
    using MPData = Mempool::NewTxsMap;

    std::pair<MPData, bool> loadMempoolDat(const QString &fname) {
        // Below code taken from BCHN validation.cpp
        FILE *pfile = std::fopen(fname.toUtf8().constData(), "rb");
        bitcoin::CAutoFile file(pfile, bitcoin::SER_DISK, bitcoin::PROTOCOL_VERSION | bitcoin::SERIALIZE_TRANSACTION_USE_WITNESS);
        if (file.IsNull())
            throw Exception(QString("Failed to open mempool file '%1'").arg(fname));

        std::size_t dataTotal = 0;
        const Tic t0;

        MPData ret;
        bool isSegWit = false;
        try {
            uint64_t version;
            file >> version;
            constexpr uint64_t BCHN_BTC_VERSION = 1, BU_VERSION = 1541030400;
            if (!std::set<uint64_t>({BCHN_BTC_VERSION, BU_VERSION}).count(version))
                throw Exception(QString("Unknown mempool.dat version: %1").arg(qulonglong(version)));

            uint64_t num;
            file >> num;
            while (num--) {
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
                dataTotal += rtx->sizeBytes = ctx->GetTotalSize(true);
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

    void bench() {
        Debug::forceEnable = true;
        const char * const mpdat = std::getenv("MPDAT");
        if (!mpdat) {
            throw Exception("Mempool benchmark requires the MPDAT environment variable, which should be a path to a "
                            "mempool.dat taken from either BCHN, BU, or a BTC (Core) bitcoind..");
        }

        const auto mem0 = Util::getProcessMemoryUsage();
        Log() << "Mem usage: physical " << QString::number(mem0.phys / 1024.0, 'f', 1)
              << " KiB, virtual " << QString::number(mem0.virt / 1024.0, 'f', 1) << " KiB";


        const auto && [mpd, isSegWit] = loadMempoolDat(mpdat);

        if (isSegWit) bitcoin::SetCurrencyUnit("BTC");

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

        enum IterMode { DropOnlyLeaves = 0, DropAnyTx = 1, ConfirmAnyTx = 2, };
        static constexpr std::array<IterMode, 3> iterModes = { DropOnlyLeaves, ConfirmAnyTx, DropAnyTx, };

        for (const auto iterMode : iterModes) { // we iterate twice. first iteraton is "leaf" mode, second is "drop any tx!!" mode.
            static const Mempool::GetTXOInfoFromDBFunc getTXOInfo = [](const TXO &txo) -> std::optional<TXOInfo> {
                // Return a "unique" but deterministic TXOInfo based on the txo's prevout:n.
                // Note the amount here is totally wrong (and leads to txs that print money out of thin air),
                // but for this test this is ok, since we care more about properly debiting/crediting spends
                // and keeping track of utxos when testing Mempool.
                TXOInfo ret;
                ret.amount = 546 * bitcoin::Amount::satoshi();
                ret.confirmedHeight = 1;
                ret.hashX = BTC::HashXFromCScript(bitcoin::CScript() << Util::toVec<std::vector<uint8_t>>(txo.toBytes(false)));
                return ret;
            };

            Log() << QString(79, QChar{'-'});
            Mempool mempool;
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
                for (int ct = 1; !mempool.txs.empty(); ++ct) {
                    Mempool::TxHashSet txids;
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
                    } else {
                        // second iteration drop anything not just leaf! (slower)
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

                    using UTXOMap = std::map<TXO, TXOInfo>;
                    struct Expected {
                        UTXOMap unconfUtxos;
                        bitcoin::Amount unconfUtxoValue;
                        Mempool::ScriptHashesAffectedSet affected;
                    } expected;

                    const auto getUnconfUtxos = [&mempool]() -> std::pair<UTXOMap, bitcoin::Amount> {
                        UTXOMap ret;
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
                                    if (it->second->hashXs.count(txoinfo.hashX) == 0)
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

                    Mempool::ScriptHashesAffectedSet shset;
                    auto t1 = Tic();
                    const auto stats = iterMode == ConfirmAnyTx
                                       ? mempool.confirmedInBlock(shset, txids, false)
                                       : mempool.dropTxs(shset, txids, false);
                    t1.fin();
                    actualTimeCost += t1.usec();
                    const auto [utxos, value] = getUnconfUtxos();
                    if (iterMode == DropOnlyLeaves) {
                        Log() << "Iter " << ct << ": oldSize: " << stats.oldSize << " newSize: " << stats.newSize
                              << " oldNumAddresses: " << stats.oldNumAddresses << " newNumAddresses: " << stats.newNumAddresses
                              << " shsaffected: " << shset.size()  << " utxoSetSize: " << beforeSize << " -> " << utxos.size()
                              << " value: " << QString::fromStdString(beforeAmt.ToString()) << " -> " << QString::fromStdString(value.ToString())
                              << " (" << QString::fromStdString((value - beforeAmt).ToString()) << ")"
                              << " in " << t1.msecStr(1) << " msec";
                    } else {
                        Log() << "Iter " << ct << ": oldSize: " << stats.oldSize << " newSize: " << stats.newSize
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
                                for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends)
                                    if (!mempool.txs.count(txo.txHash))
                                        throw Exception("A scripthash now refers to an unconfirmed spend that no longer exists");
                                for (const auto & [txo, txoinfo] : ioinfo.confirmedSpends)
                                    if (mempool.txs.count(txo.txHash))
                                        throw Exception("A scripthash now refers to an \"confirmed spend\" that is still in mempool");
                            }
                            if (bool(nUnconf) != tx->hasUnconfirmedParentTx)
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
                                if (!mempool.txs.count(tx->hash))
                                    throw Exception("Encountered a txvec entry pointing to a tx not in mempool!");
                                if (!setInVecsThisSh.insert(tx->hash).second)
                                    throw Exception("Dupe txhash in a txvec encountered");
                            }
                            setInVecs.merge(std::move(setInVecsThisSh));
                        }
                        if (Util::keySet(mempool.txs) != setInVecs)
                            throw Exception("Some txs in mempool.txs are not in txvecs!");
                    }
                    if (iterMode == DropOnlyLeaves || iterMode == ConfirmAnyTx) {
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
                    if (iterMode == DropAnyTx) {
                        // In this mode the only way to verify is to build a second mempool with the same txid set
                        // as the first -- this checks that spends and everything else is consistent.
                        // This of course assumes that the "addTxs" code is bug-free and always leads to consistency
                        // (whcih is the case since the addTxs code is very mature at this point).
                        // Note: The below is very *very* slow.
                        Log() << "Verifying resultant mempool (this may take a while) ...";
                        Mempool mempool2;
                        Mempool::NewTxsMap adds;
                        auto t0 = Tic();
                        auto mpd2 = deepCopyMPD(mpd); // take a deep copy of the original mempool to get unique "untouched" TxRefs
                        Debug() << "Deep copied txs in " << t0.msecStr() << " msec";
                        for (const auto & [txid, _] : mempool.txs) {
                            auto it = mpd2.find(txid);
                            if (it == mpd2.end())
                                throw InternalError(QString("TxId %1 not found. This should never happen.").arg(QString(txid.toHex())));
                            if (txids.count(txid))
                                throw Exception("Drop verification failed -- a txid in the drop set is still in the mempool structure!");
                            adds.insert(*it);
                        }
                        Mempool::ScriptHashesAffectedSet _;
                        auto t1 = Tic();
                        mempool2.addNewTxs(_, adds, getTXOInfo);
                        Debug() << "Added to a dupe mempool in " << t1.msecStr() << " msec";
                        if (!mempool.deepCompareEqual(mempool2))
                            throw Exception("Drop verification failed -- mempool != mempool2");
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
