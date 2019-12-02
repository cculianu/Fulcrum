#include "BlockProc.h"
#include "BTC.h"
#include "Util.h"

#include "bitcoin/transaction.h"

#include <QTextStream>

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>


/*static*/ const QByteArray PreProcessedBlock::staticnull;

/// fill this struct's data with all the txdata, etc from a bitcoin CBlock. Alternative to using the second c'tor.
void PreProcessedBlock::fill(unsigned blockHeight, size_t blockSize, const bitcoin::CBlock &b) {
    if (!header.IsNull() || !txInfos.empty())
        clear();
    height = blockHeight;
    sizeBytes = blockSize;
    header = b.GetBlockHeader();
    estimatedThisSizeBytes = sizeof(*this) + BTC::GetBlockHeaderSize();
    txInfos.reserve(b.vtx.size());
    using HashHasher = BTC::QByteArrayHashHasher;
    std::unordered_map<QByteArray, unsigned, HashHasher> txHashToIndex;
    std::unordered_map<HashX, std::vector<unsigned>, HashHasher> hashXOuts, hashXIns;
    std::unordered_set<HashX, HashHasher> hashXsSeen;
    // run through all tx's, build inputs and outputs lists
    size_t txIdx = 0;
    for (const auto & tx : b.vtx) {
        // copy tx hash data for the tx
        TxInfo info;
        info.hash = BTC::Hash2ByteArrayRev(tx->GetHash());
        info.nInputs = unsigned(tx->vin.size());
        info.nOutputs = unsigned(tx->vout.size());
        // remember the tx hash -> index association for use later in this function
        txHashToIndex[info.hash] = unsigned(txIdx); // cheap copy + cheap hash func. should make this fast.

        // process outputs for this tx
        if (!tx->vout.empty())
            // remember output0 index for this txindex
            info.output0Index = unsigned(outputs.size());

        unsigned outN = 0;
        for (const auto & out : tx->vout) {
            // save the outputs seen
            outputs.emplace_back(
                OutPt{ unsigned(txIdx), outN, out.nValue }
            );
            estimatedThisSizeBytes += sizeof(OutPt);
            const size_t outputIdx = outputs.size()-1;
            if (const auto cscript = out.scriptPubKey;
                    !BTC::IsOpReturn(cscript))  ///< skip OP_RETURN
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
            info.input0Index = unsigned(inputs.size());

        unsigned inN = 0;
        for (const auto & in : tx->vin) {
            inputs.emplace_back(InputPt{
                    unsigned(txIdx),
                    BTC::Hash2ByteArrayRev(in.prevout.GetTxId()),  // .prevoutHash
                    unsigned(in.prevout.GetN()), // .prevoutN
                    {}, // .parentTxOutIdx (start out undefined)
            });
            estimatedThisSizeBytes += sizeof(InputPt);
            ++inN;
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
                inp.parentTxOutIdx = info.output0Index.value() + inp.prevoutN; // save the index into the `outputs` array where the parent tx to this spend occurred
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

    // sort hashXAggregated by outputIdx,inputIdx
    std::sort(hashXAggregated.begin(), hashXAggregated.end(), [](const HashXAggregated &a, const HashXAggregated &b) -> bool {
        return std::make_pair(a.outs.empty() ? 0 : a.outs.front()+1, a.ins.empty() ? 0 : a.ins.front()+1 )
                < std::make_pair(b.outs.empty() ? 0 : b.outs.front()+1, b.ins.empty() ? 0 : b.ins.front()+1 );
    });
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
                   << ", spent in " << txHashForInputIdx(idx).toHex() << ":" << numForInputIdx(idx).value_or(999999) << " }";
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
PreProcessedBlockPtr
/*static*/ PreProcessedBlock::makeShared(unsigned height, size_t size, const bitcoin::CBlock &block)
{
    return std::make_shared<PreProcessedBlock>(height, size, block);
}
