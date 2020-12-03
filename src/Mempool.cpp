//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
    txs.reserve(0); // this should free previous capacity
    hashXTxs.reserve(0);
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
                        const NewTxsMap & txsDownloaded,
                        const GetTXOInfoFromDBFunc & getTXOInfo,
                        bool TRACE) -> Stats
{
    Stats ret;
    auto & [oldSize, newSize, oldNumAddresses, newNumAddresses] = ret;
    oldSize = this->txs.size();
    oldNumAddresses = this->hashXTxs.size();
    // first, do new outputs for all tx's, and put the new tx's in the mempool struct
    for (auto & [hash, pair] : txsDownloaded) {
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
                tx->hashXs[sh].utxo.insert(n);
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
    for (auto & [hash, pair] : txsDownloaded) {
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
                    // Uh oh. If it wasn't in the mempool or in the db.. something is very wrong with our code.
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
                    auto pair = tx->hashXs.insert({sh, decltype(hxit->second)()});
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
        for (auto & [sh, ioinfo] : tx->hashXs) {
            ioinfo.confirmedSpends.rehash(ioinfo.confirmedSpends.size());  // this is fixed once built
            ioinfo.unconfirmedSpends.rehash(ioinfo.unconfirmedSpends.size()); // this is fixed once built
            ioinfo.utxo.rehash(ioinfo.utxo.size()); // this may shrink but we rehash it once now to the largest size it will ever have
        }
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
    return ret;
}

auto Mempool::dropTxs(ScriptHashesAffectedSet & scriptHashesAffectedOut, const TxHashSet & txidsIn, bool TRACE,
                      std::optional<float> rehashMaxLoadFactor) -> Stats
{
    auto txids = txidsIn;
    // also drop txs that spend from the txids in the above set as well -- since we
    // cannot drop tx's in the middle of a chain of spends due to limitations in how
    // we model the mempool
    {
        int iterct = 0, added = 0;
        const auto t0 = Debug::isEnabled() ? Util::getTimeMicros() : 0;
        while (txids.size() && ++iterct) {
            for (const auto & [txid, tx] : txs) {
                if (!tx->hasUnconfirmedParentTx || txids.count(txid))
                    continue; // no unconf. parents or already added
                for (const auto & [sh, ioinfo] : tx->hashXs) {
                    for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                        if (txids.count(txo.txHash)) {
                            // this spends one of the ones in our set! add it since it's a child of something we want to remove.
                            txids.emplace(txid);
                            ++added;
                            DebugM("addBlock: additonal tx ", Util::ToHexFast(txid), " added to set because it spends ",
                                   txo.toString(), " which is already in our removal set");
                            goto outer_loop_iterate_again;
                        }
                    }
                }
            }
            break;
        outer_loop_iterate_again:
            continue;
        }
        DebugM("dropTxs: iterated ", iterct, " time(s) to add ", added, " additional child tx(s) in ",
               QString::number((Util::getTimeMicros()-t0)/1e3, 'f', 2), " msec");
    }

    Stats ret;
    ScriptHashesAffectedSet scriptHashesAffected;
    auto & [oldSize, newSize, oldNumAddresses, newNumAddresses] = ret;
    oldSize = this->txs.size();
    oldNumAddresses = this->hashXTxs.size();

    // first, undo unconfirmed spends -- find the parent txs and credit back the IOInfos for corresponding scripthashes
    for (const auto & txid : txids) {
        auto it = txs.find(txid);
        if (UNLIKELY(it == txs.end())) {
            // Note that it's ok to call this function for non-existant tx's -- we call it when adding new blocks
            // and it's possible for txids in blocks to not be in mempool. Only print a message in debug mode.
            DebugM("dropTxs: tx ", Util::ToHexFast(txid), " not found in mempool");
            continue;
        }
        auto & tx = it->second;
        // for each hashX this tx affects, look for unconfirmed spends
        for (const auto & [hashX, ioinfo]: tx->hashXs) {
            scriptHashesAffected.insert(hashX); // update affected set with all addresses for this tx
            // for each unconfirmed spend, go to the previous tx in mempool and add back the utxo to ioinfo.utxo for the parent tx hashx entry
            for (const auto & [txo, txoinfo] : ioinfo.unconfirmedSpends) {
                scriptHashesAffected.insert(txoinfo.hashX); // updated affected set with address of txo we spent as well
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
    }

    // next, scan hashXs, removing entries for the txids in question
    for (const auto & hashX : scriptHashesAffected) {
        auto it = hashXTxs.find(hashX);
        if (UNLIKELY(it == hashXTxs.end())) {
            Warning() << "dtopTxs: Could not find hashX " << hashX.toHex() << " in hashXTxs map! FIXME!";
            continue;
        }
        auto & txvec = it->second;
        std::vector<TxRef> newvec;
        newvec.reserve(txvec.size());
        for (auto &txref : txvec) {
            // filter out txids in the set
            if (txids.count(txref->hash) == 0)
                // not in txid set; copy it to newvec
                newvec.push_back(txref);
        }
        if (!newvec.empty() && newvec.size() != txvec.size()) {
            // swap the vectors with the one not containing the affected txids
            if (TRACE) {
                const auto oldsz = txvec.size(), newsz = newvec.size();
                if (TRACE)
                    Debug() << "dropTxs: Shrunk hashX " << Util::ToHexFast(hashX) << " txvec from size " << oldsz
                            << " to size " << newsz;
            }
            txvec.swap(newvec);
            txvec.shrink_to_fit();
        } else if (newvec.empty()){
            // if the new vector is empty meaning this hashX should disappear from the hashXTxs map!
            hashXTxs.erase(it);
            if (TRACE) Debug() << "dropTxs: Removed hashX " << Util::ToHexFast(hashX) << " which now has no txs in mempool";
        }
    }

    // next, erase the txid's in question from the txs map
    for (const auto & txid : txids) {
        txs.erase(txid);
    }

    // finally, update scriptHashesAffectedOut
    scriptHashesAffectedOut.merge(scriptHashesAffected);

    // update returned stats
    newSize = this->txs.size();
    newNumAddresses = this->hashXTxs.size();

    if (rehashMaxLoadFactor) {
        if (txs.load_factor() <= *rehashMaxLoadFactor)
            txs.rehash(0); // shrink to fit
        if (hashXTxs.load_factor() <= *rehashMaxLoadFactor)
            hashXTxs.rehash(0);  // shrint to fit
    }
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
            ret["utxos (BucketCount)"] = qlonglong(inf.utxo.bucket_count());
            ret["utxos (LoadFactor)"] = QString::number(double(inf.utxo.load_factor()), 'f', 4);
            QVariantMap cs;
            for (const auto & [txo, info] : inf.confirmedSpends)
                cs[txo.toString()] = TXOInfo2Map(info);
            ret["confirmedSpends"] = cs;
            ret["confirmedSpends (LoadFactor)"] = QString::number(double(inf.confirmedSpends.load_factor()), 'f', 4);
            QVariantMap us;
            for (const auto & [txo, info] : inf.unconfirmedSpends)
                us[txo.toString()] = TXOInfo2Map(info);
            ret["unconfirmedSpends"] = us;
            ret["unconfirmedSpends (LoadFactor)"] = QString::number(double(inf.unconfirmedSpends.load_factor()), 'f', 4);
            return ret;
        };
        for (const auto & [sh, ioinfo] : tx->hashXs)
            hxs[sh.toHex()] = IOInfo2Map(ioinfo);
        m["hashXs"] = hxs;
        m["hashXs (LoadFactor)"] = QString::number(double(tx->hashXs.load_factor()), 'f', 4);

        txMap[hash.toHex()] = m;
    }
    mp["txs"] = txMap;
    mp["txs (LoadFactor)"] = QString::number(double(txs.load_factor()), 'f', 4);
    QVariantMap hxs;
    for (const auto & [sh, txset] : hashXTxs) {
        QVariantList l;
        for (const auto & tx : txset)
            if (tx) l.push_back(tx->hash.toHex());
        hxs[sh.toHex()] = l;
    }
    mp["hashXTxs"] = hxs;
    mp["hashXTxs (LoadFactor)"] = QString::number(double(hashXTxs.load_factor()), 'f', 4);

    return mp;
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "BTC.h"
#include "Json/Json.h"
#include "Util.h"

#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"
#include "robin_hood/robin_hood.h"

#include <cstdio>
#include <set>

namespace {
    using MPData = Mempool::NewTxsMap;

    std::pair<MPData, bool> loadMempoolDat(const QString &fname) {
        // Below code taken from BCHN validation.cpp
        FILE *pfile = std::fopen(fname.toUtf8().constData(), "rb");
        bitcoin::CAutoFile file(pfile, bitcoin::SER_DISK, bitcoin::PROTOCOL_VERSION | bitcoin::SERIALIZE_TRANSACTION_USE_WITNESS);
        if (file.IsNull())
            throw Exception(QString("Failed to open mempool file '%1'").arg(fname));

        std::size_t dataTotal = 0;
        const auto t0 = Util::getTimeMicros();

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
        Log("Imported mempool: %d txs, %1.2f MB in %1.3f msec", int(ret.size()), dataTotal / 1e6, (Util::getTimeMicros()-t0)/1e3);
        return {std::move(ret), isSegWit};
    }

    void bench() {
        Debug::forceEnable = true;
        const char * const mpdat = std::getenv("MPDAT");
        if (!mpdat) {
            Warning() << "Mempool benchmark requires the MPDAT environment variable, which should be a path to a "
                         "mempool.dat taken from either BCHN, BU, or a BTC (Core) bitcoind..";
            throw Exception("No MPDAT specified");
        }

        const auto mem0 = Util::getProcessMemoryUsage();
        Log() << "Mem usage: physical " << QString::number(mem0.phys / 1024.0, 'f', 1)
              << " KiB, virtual " << QString::number(mem0.virt / 1024.0, 'f', 1) << " KiB";


        auto && [mpd, isSegWit] = loadMempoolDat(mpdat);

        if (isSegWit) bitcoin::SetCurrencyUnit("BTC");

        for (int iter = 0; iter < 2; ++iter) { // we iterate twice. first iteraton is "leaf" mode, second is "drop any tx!!" mode.
            Log() << QString(79, QChar{'-'});
            Mempool mempool;
            {
                static const Mempool::GetTXOInfoFromDBFunc getTXOInfo = [](const TXO &txo) -> std::optional<TXOInfo> {
                    TXOInfo ret;
                    ret.amount = 546 * bitcoin::Amount::satoshi();
                    ret.confirmedHeight = 1;
                    ret.hashX = BTC::HashXFromCScript(bitcoin::CScript() << Util::toVec<std::vector<uint8_t>>(txo.toBytes()));
                    return ret;
                };
                Mempool::ScriptHashesAffectedSet shset;
                const auto t0 = Util::getTimeMicros();
                const auto stats = mempool.addNewTxs(shset, mpd, getTXOInfo);
                const auto tf = Util::getTimeMicros();
                Log() << "Added to mempool in " << QString::number((tf-t0)/1e3, 'f', 3) << " msec."
                      << " Scripthashes: " << shset.size() << ", size: " << stats.newSize << ", addresses " << stats.newNumAddresses;
                shset.clear();
                const auto mem = Util::getProcessMemoryUsage();
                Log() << "Mem usage: physical " << QString::number(mem.phys / 1024.0, 'f', 1)
                      << " KiB, virtual " << QString::number(mem.virt / 1024.0, 'f', 1) << " KiB";
                Log() << "Delta phys: " << QString::number((mem.phys - mem0.phys) / 1024.0, 'f', 1) << " KiB";
            }


            Log() << QString(79, QChar{'-'});

            {
                const auto t0 = Util::getTimeMicros();
                decltype(Util::getTimeMicros()) actualTimeCost = 0;
                bool dumped = false;
                // iterate each time, dropping leaves from mempool
                for (int ct = 1; !mempool.txs.empty(); ++ct) {
                    Mempool::TxHashSet txids;
                    for (const auto & [txHash, tx] : mempool.txs) {
                        std::unordered_set<IONum> ionums;
                        for (const auto & [hashX, ioinfo] : tx->hashXs) {
                            for (const auto & n : ioinfo.utxo)
                                ionums.insert(n);
                        }
                        if (iter == 0) {
                            // drop only leaves mode
                            std::size_t validSize = 0;
                            for (const auto & txo : tx->txos)
                                validSize += txo.isValid();
                            if (ionums.size() == validSize) {
                                // this is a leaf
                                txids.insert(txHash);
                            }
                        } else {
                            // second iteration drop anything not just leaf! (slower)
                            txids.insert(txHash);
                        }
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
                    std::size_t beforeSize;

                    { // build expected set to verify the results of calling dropTxs()

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
                    const auto t1 = Util::getTimeMicros();
                    const auto stats = mempool.dropTxs(shset, txids, false);
                    const auto t2 = Util::getTimeMicros();
                    actualTimeCost += t2 - t1;
                    const auto [utxos, value] = getUnconfUtxos();
                    Log() << "Iter " << ct << ": oldSize: " << stats.oldSize << " newSize: " << stats.newSize
                          << " oldNumAddresses: " << stats.oldNumAddresses << " newNumAddresses: " << stats.newNumAddresses
                          << " shsaffected: " << shset.size()  << " utxoSetSize: " << beforeSize << " -> " << utxos.size()
                          << " value: " << QString::fromStdString(beforeAmt.ToString()) << " -> " << QString::fromStdString(value.ToString())
                          << " (" << QString::fromStdString((value - beforeAmt).ToString()) << ")"
                          << " in " << QString::number((t2-t1)/1e3, 'f', 1) << " msec";
                    if (!dumpBefore.isEmpty()) {
                        const QVariantMap dumpAfter = mempool.dump();
                        Log() << QString(79, QChar{'-'});
                        Log() << "Dump, before:";
                        Log() << Json::toUtf8(dumpBefore);
                        Log() << "Dump, after:";
                        Log() << Json::toUtf8(dumpAfter);
                        Log() << QString(79, QChar{'-'});
                    }
                    if (iter == 0) {
                        // For now we do this sanity check only on "leaf" mode (first iteratiorn)
                        // TODO: do some sanity checking for the "drop anything" mode as well.
                        if (stats.oldSize - stats.newSize != txids.size())
                            throw Exception("New tx counds are not as expected!");
                        if (shset != expected.affected)
                            throw Exception("ScriptHashes affected is not as expected!");
                        if (utxos != expected.unconfUtxos)
                            throw Exception("Resultant utxo set is not as expected!");
                        if (value != expected.unconfUtxoValue)
                            throw Exception("Resultant utxo totals are not as expected!");
                    }
                }
                const auto tf = Util::getTimeMicros();
                Log() << "Dropped all from mempool in " << QString::number((tf-t0)/1e3, 'f', 3)
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
