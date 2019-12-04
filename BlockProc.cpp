#include "BlockProc.h"
#include "BTC.h"
#include "Util.h"

#include "bitcoin/transaction.h"

#include <QTextStream>

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

/* static */ const TxHash BlockProcBase::nullhash;

/// fill this struct's data with all the txdata, etc from a bitcoin CBlock. Alternative to using the second c'tor.
void PreProcessedBlock::fill(BlockHeight blockHeight, size_t blockSize, const bitcoin::CBlock &b) {
    if (!header.IsNull() || !txInfos.empty())
        clear();
    height = blockHeight;
    sizeBytes = blockSize;
    header = b.GetBlockHeader();
    estimatedThisSizeBytes = sizeof(*this) + size_t(BTC::GetBlockHeaderSize());
    txInfos.reserve(b.vtx.size());
    std::unordered_map<TxHash, unsigned, HashHasher> txHashToIndex;
    std::unordered_map<HashX, std::vector<unsigned>, HashHasher> hashXOuts, hashXIns;
    std::unordered_set<HashX, HashHasher> hashXsSeen;
    // run through all tx's, build inputs and outputs lists
    size_t txIdx = 0;
    for (const auto & tx : b.vtx) {
        // copy tx hash data for the tx
        TxInfo info;
        info.hash = BTC::Hash2ByteArrayRev(tx->GetHash());
        info.nInputs = IONum(tx->vin.size());
        info.nOutputs = IONum(tx->vout.size());
        // remember the tx hash -> index association for use later in this function
        txHashToIndex[info.hash] = unsigned(txIdx); // cheap copy + cheap hash func. should make this fast.

        // process outputs for this tx
        if (!tx->vout.empty())
            // remember output0 index for this txindex
            info.output0Index.emplace( unsigned(outputs.size()) );

        uint16_t outN = 0;
        for (const auto & out : tx->vout) {
            // save the outputs seen
            outputs.emplace_back(
                OutPt{ unsigned(txIdx), outN, out.nValue }
            );
            estimatedThisSizeBytes += sizeof(OutPt);
            const size_t outputIdx = outputs.size()-1;
            if (const auto cscript = out.scriptPubKey;
                    cscript.size() && !BTC::IsOpReturn(cscript))  ///< skip OP_RETURN
            {
                const HashX hashX = cscript;
                // add this output to the hashX -> outputs association for later
                hashXOuts[ hashX ].emplace_back( outputIdx );
                hashXsSeen.insert(hashX);
            } /*else {
                // OpReturn tracking...
                opreturns.emplace_back(OpReturn{unsigned(outputIdx), cscript});
            }*/
            ++outN;
        }

        // process inputs
        if (!tx->vin.empty())
            // remember input0Index position for this tx
            info.input0Index.emplace( unsigned(inputs.size()) );

        for (const auto & in : tx->vin) {
            // note we do place the coinbase tx here even though we ignore it later on -- we keep it to have accurate indices
            inputs.emplace_back(InputPt{
                    unsigned(txIdx),
                    BTC::Hash2ByteArrayRev(in.prevout.GetTxId()),  // .prevoutHash
                    uint16_t(in.prevout.GetN()), // .prevoutN
                    {}, // .parentTxOutIdx (start out undefined)
            });
            estimatedThisSizeBytes += sizeof(InputPt);
        }
        estimatedThisSizeBytes += sizeof(info) + size_t(info.hash.size());
        txInfos.emplace_back(std::move(info));
        ++txIdx;
    }

    // shrink inputs/outputs to fit now to conserve memory
    inputs.shrink_to_fit();
    outputs.shrink_to_fit();

    // at this point we have a partially constructed object. we must run through all the inputs again
    // and figure out which if any refer to tx's in this block, and assign those to our hashXIns.
    // Also: to save memory on txhash's for such inputs, we make sure the txhash refers to the same underlying
    // QByteArray data.
    size_t inIdx = 0;
    for (auto & inp : inputs) {
        if (const auto it = txHashToIndex.find(inp.prevoutHash); it != txHashToIndex.end()) {
            // this input refers to a tx in this block!
            const auto txIdx = it->second;
            assert(txIdx < txInfos.size() && txIdx < b.vtx.size());
            const TxInfo & info = txInfos[txIdx];
            inp.prevoutHash = info.hash; //<--- ensure shallow copy that points to same underlying data (saves memory)
            if (info.output0Index.has_value())
                inp.parentTxOutIdx.emplace( info.output0Index.value() + inp.prevoutN ); // save the index into the `outputs` array where the parent tx to this spend occurred
            else { assert(0); }
            const auto & tx = b.vtx[txIdx];
            assert(inp.prevoutN < tx->vout.size());
            if (const auto cscript = tx->vout[inp.prevoutN].scriptPubKey;
                    !BTC::IsOpReturn(cscript))
            {
                // mark this input as touching this hashX
                const HashX hashX = cscript;
                hashXIns[ hashX ].emplace_back(inIdx);
                hashXsSeen.insert(hashX);
            }
        }
        ++inIdx;
    }

    hashXAggregated.reserve(hashXsSeen.size());
    for (const auto & hashX : hashXsSeen ) {
        HashXAggregated ag;
        ag.hashX = hashX;
        if (auto it = hashXIns.find(hashX); it != hashXIns.end())
            ag.ins.swap(it->second);
        if (auto it = hashXOuts.find(hashX); it != hashXOuts.end())
            ag.outs.swap(it->second);

        ag.ins.shrink_to_fit();
        ag.outs.shrink_to_fit();
        estimatedThisSizeBytes += sizeof(ag) + size_t(ag.hashX.size()) + ag.ins.size() * sizeof(decltype(ag.ins)::value_type) + ag.outs.size() * sizeof(decltype(ag.outs)::value_type);
        hashXAggregated.emplace_back(std::move(ag));
    }

    sortHashXAggregated(inputs);
}

QString PreProcessedBlock::toDebugString() const
{
    QString ret;
    {
        QTextStream ts(&ret, QIODevice::ReadOnly|QIODevice::Truncate|QIODevice::Text);
        ts << "<PreProcessedBlock --"
           << " height: " << height << " " << " size: " << sizeBytes << " header_nTime: " << header.nTime << " hash: " << header.GetHash().ToString().c_str()
           << " nTx: " << txInfos.size() << " nIns: " << inputs.size() << " nOuts: " << outputs.size() << " nScriptHash: " << hashXAggregated.size();
        int i = 0;
        for (const auto & ag : hashXAggregated) {
            ts << " (#" << i << " - " << ag.hashX.toHex() << " - nIns: " << ag.ins.size() << " nOuts: " << ag.outs.size();
            for (size_t j = 0; j < ag.ins.size(); ++j) {
                const auto idx = ag.ins[j];
                const auto & theInput [[maybe_unused]] = inputs[idx];
                assert(theInput.parentTxOutIdx.has_value() && txHashForOutputIdx(theInput.parentTxOutIdx.value()) == theInput.prevoutHash);
                ts << " {in# " << j << " - " << inputs[idx].prevoutHash.toHex() << ":" << inputs[idx].prevoutN
                   << ", spent in " << txHashForInputIdx(inputs, idx).toHex() << ":" << numForInputIdx(inputs, idx).value_or(999999) << " }";
            }
            for (size_t j = 0; j < ag.outs.size(); ++j) {
                const auto idx = ag.outs[j];
                ts << " {out# " << j << " - " << txHashForOutputIdx(idx).toHex() << ":" << outputs[idx].outN << " amt: " << outputs[idx].amount.ToString().c_str() << " }";
            }
            ts << ")";
            ++i;
        }
        /*
        ts << " opreturns: " << opreturns.size();
        i = 0;
        for (const auto & op : opreturns) {
            ts << " (#" << i << " - " << txInfos[outputs[op.outIdx].txIdx].hash.toHex() << ")";
            ++i;
        }*/
        ts << " >";
    }
    return ret;
}

/// convenience factory static method: given a block, return a shard_ptr instance of this struct
/*static*/
PreProcessedBlockPtr PreProcessedBlock::makeShared(unsigned height_, size_t size, const bitcoin::CBlock &block)
{
    return std::make_shared<PreProcessedBlock>(height_, size, block);
}

/* ---- ProcessedBlock ---- */
ProcessedBlock::CannotResolveInputError::~CannotResolveInputError() {} // for weak vtable warning


/// convenience factory static method: given a block, return a shard_ptr instance of this struct
/*static*/
ProcessedBlockPtr ProcessedBlock::makeShared(TxNum txBaseNum, const PreProcessedBlock &ppb, const TxHash2NumResolver &resolverFunc, const UTXOSet &uset) // may throw
{
    auto rawPtr = new ProcessedBlock(txBaseNum, ppb, resolverFunc, uset); // may throw
    return ProcessedBlockPtr(rawPtr); // didn't throw, return shared_ptr
}

ProcessedBlock::ProcessedBlock(TxNum txBaseNum, const PreProcessedBlock &ppb, const TxHash2NumResolver &resolverFunc, const UTXOSet &uset)
    : BlockProcBase(ppb), txNum0(txBaseNum)
{
    inputs.reserve(ppb.inputs.size());
    estimatedThisSizeBytes -= ppb.inputs.size() * sizeof(PreProcessedBlock::InputPt); // reduce the size estimate because we will recompute it below
    std::unordered_map<HashX, std::optional<unsigned>, HashHasher> hashXRevMap; // index HashX -> its HashXAggregated index

    unsigned i = 0;
    // build hashX -> ag quick lookup map
    for (auto & ag: hashXAggregated) {
        hashXRevMap[ag.hashX] = i++;
    }

    // run through all of the inputs and resolve them to a HashX by consuling the utxo set and the resolverFunc
    i = 0;
    for (const auto & inp : ppb.inputs) {
        TXO txo;
        txo.u.prevout.n = inp.prevoutN;
        if (inp.parentTxOutIdx.has_value()) {
            assert(inp.parentTxOutIdx.value() < outputs.size());
            // prevout was in this block, grab txNum quickly
            const auto & prevout = outputs[inp.parentTxOutIdx.value()];
            txo.u.prevout.txNum = txIdx2Num(prevout.txIdx);
            // at this point we know the input in question was already pre-populated in the hashXAggregated structure,
        } else if (i == 0) {
            // coinbase input.. skip the scripthash stuff
            txo = TXO(); // mark prevout as "invalid"
        } else {
            // prevout was not in this block, call the resolverFunc to figure out the 'txNum'
            auto opt = resolverFunc(inp.prevoutHash);
            if (UNLIKELY(!opt.has_value())) {
                throw CannotResolveInputError(
                    QString("Unable to resolve prevoutHash %1 for input# %2 of txid %3")
                            .arg(QString(inp.prevoutHash.toHex()))
                            .arg(ppb.numForInputIdx(ppb.inputs, i).value_or(9999))
                            .arg(QString(ppb.txHashForInputIdx(ppb.inputs, i).toHex())));
            }
            txo.u.prevout.txNum = opt.value();
            // look for utxo in utxo set to find the HashX and Amount.
            if (auto it = uset.find(txo); UNLIKELY(it == uset.end())) {
                throw CannotResolveInputError(
                    QString("Unable to resolve utxo %1:%2 in utxo set for input# %3 of txid %4")
                            .arg(QString(inp.prevoutHash.toHex()))
                            .arg(txo.u.prevout.n)
                            .arg(ppb.numForInputIdx(ppb.inputs, i).value_or(9999))
                            .arg(QString(ppb.txHashForInputIdx(ppb.inputs, i).toHex())));
            } else {
                // at this point we know the input in question was from a previous block so we need to populate the
                // hashXAggregated structure now.  Either by pushing an 'ins' to the end of an existing struct's
                // vector, or creating a new
                const auto & info = it->second;
                auto & opt = hashXRevMap[info.hashX];
                if (!opt.has_value()) {
                    // did not exist -- new hashX
                    hashXAggregated.emplace_back(HashXAggregated{
                        info.hashX, //
                        {}, // outs
                        {i}, // ins
                    });
                    opt = hashXAggregated.size()-1; // mark new hashX in aggregated structure
                    estimatedThisSizeBytes += sizeof(HashXAggregated);
                } else {
                    hashXAggregated[opt.value()].ins.push_back(i);
                }
                estimatedThisSizeBytes += sizeof(i);
            }
        }

        // now, push the input into our concrete class's inputs array
        inputs.emplace_back(InputPt{
            inp.txIdx, // .txIdx
            txo, // .prevOut
        });

        estimatedThisSizeBytes += sizeof(InputPt);
        ++i;
    }

    // all inputs are pushed, we need to update the hashXAggregated structure by sorting it an making sure indices
    // are unique
    hashXAggregated.shrink_to_fit(); // shrink capacity -> size
    for (auto & ag : hashXAggregated) {
        // sort each ag structure again
        std::sort(ag.ins.begin(), ag.ins.end());
        // make sure inputs are unique
        auto last = std::unique(ag.ins.begin(), ag.ins.end());
        ag.ins.erase(last, ag.ins.end());
        ag.ins.shrink_to_fit(); // just in case we grew its capacity too large
    }
    sortHashXAggregated(inputs); // sort by txid/output
}

// very much a work in progress. this needs to also consult the UTXO set to be complete. For now we just
// have this here for reference.
std::vector<std::unordered_set<HashX, HashHasher>>
ProcessedBlock::hashXTouchedByTx() const
{
    std::vector<std::unordered_set<HashX, HashHasher>> ret(txInfos.size());
    for (const auto & ag : hashXAggregated) {
        // scan all outputs and add this hashX
        for (const auto outIdx : ag.outs) {
            ret[outputs[outIdx].txIdx].insert(ag.hashX); // cheap shallow copy
        }
        // scan all inputs and add this hashX
        for (const auto inIdx : ag.ins) {
            ret[inputs[inIdx].txIdx].insert(ag.hashX);
        }
    }
    return ret;
}

QString ProcessedBlock::toDebugString(const Num2TxHashResolver &resolver, const UTXOSet &uset) const
{
    // TODO: implement...
    QString ret;
    {
        QTextStream ts(&ret, QIODevice::ReadOnly|QIODevice::Truncate|QIODevice::Text);
        ts << "<ProcessedBlock --"
           << " height: " << height << " " << " size: " << sizeBytes << " header_nTime: " << header.nTime << " hash: " << header.GetHash().ToString().c_str()
           << " nTx: " << txInfos.size() << " nIns: " << inputs.size() << " nOuts: " << outputs.size() << " nScriptHash: " << hashXAggregated.size();
        int i = 0;
        for (const auto & ag : hashXAggregated) {
            ts << " (#" << i << " - " << ag.hashX.toHex() << " - nIns: " << ag.ins.size() << " nOuts: " << ag.outs.size();
            for (size_t j = 0; j < ag.ins.size(); ++j) {
                const auto idx = ag.ins[j];
                const auto & theInput [[maybe_unused]] = inputs[idx];
                const auto & inp = inputs[idx];
                QByteArray h = resolver(inp.prevOut.txNum()).value_or("").toHex();
                QString amt = "prevOutAmount: ???";
                if (h.isEmpty()) {
                    h = QString("<NOTFOUND TxNum: %1>").arg(inp.prevOut.txNum()).toUtf8();
                }
                if (auto it = uset.find(inp.prevOut); it != uset.end()) {
                    amt = QString("prevOutAmount: %1 height: %2").arg(it->second.amount.ToString().c_str()).arg(int(it->second.confirmedHeight.value_or(0))-1);
                }
                ts << " {in# " << j << " - " << h << ":" << inp.prevOut.N()
                   << ", spent in " << txHashForInputIdx(inputs, idx).toHex() << ":" << numForInputIdx(inputs, idx).value_or(999999) << " }";
            }
            for (size_t j = 0; j < ag.outs.size(); ++j) {
                const auto idx = ag.outs[j];
                ts << " {out# " << j << " - " << txHashForOutputIdx(idx).toHex() << ":" << outputs[idx].outN << " amt: " << outputs[idx].amount.ToString().c_str() << " }";
            }
            ts << ")";
            ++i;
        }
        /*
        ts << " opreturns: " << opreturns.size();
        i = 0;
        for (const auto & op : opreturns) {
            ts << " (#" << i << " - " << txInfos[outputs[op.outIdx].txIdx].hash.toHex() << ")";
            ++i;
        }*/
        ts << " >";
    }
    return ret;
}
