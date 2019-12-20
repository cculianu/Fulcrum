#include "Merkle.h"
#include "Util.h"

#include <algorithm>
#include <list>

namespace Merkle {

    BranchAndRootPair branchAndRoot(const HashVec &hashVec, unsigned index, const std::optional<unsigned> & optLen)
    {
        BranchAndRootPair ret;
        const unsigned hvsz = unsigned(hashVec.size());
        if (!hvsz || index >= hvsz) {
            Error() << __PRETTY_FUNCTION__ << ": Misused. Please specify a non-empty hash vector as well as an in-range index. FIXME!";
            return ret;
        }
        const unsigned natLen = branchLength(unsigned(hvsz));
        const unsigned length = optLen.value_or(natLen);
        if (length < natLen) {
            Error() << __PRETTY_FUNCTION__ << ": Misused. Must specify a length argument that is >= " << natLen << " for a vector of size " << hvsz << ". FIXME!";
            return ret;
        }
        HashVec branch;
        branch.reserve(length);
        HashVec hashes;
        hashes.reserve(hvsz+1);

        // copy all hashes to our working vector, which mutates as we iterate below
        for (const auto & h : hashVec) hashes.emplace_back(h);

        for (unsigned i = 0; i < length; ++i) {
            if (hashes.size() & 0x1) // is odd, add the end twice
                hashes.emplace_back(hashes.back());

            branch.push_back(hashes[index ^ 1]);
            index >>= 1;
            constexpr auto recomputeHashes = [](HashVec & hashes) {
                HashVec hv;
                const unsigned sz = unsigned(hashes.size());
                hv.reserve( (sz / 2) + 1 );
                for (unsigned i = 0; i < sz; i+=2) {
                    hv.emplace_back(BTC::Hash(hashes[i] + hashes[i+1]));
                }
                hashes.swap(hv);
            };
            recomputeHashes(hashes); // makes hashes be 1/2 the size each time
        }
        if (UNLIKELY(hashes.empty())) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. Output hashes vector is empty! FIXME!";
            return ret;
        }
        ret = { std::move(branch), hashes.front() };
        return ret;
    }

    Hash rootFromProof(const Hash & hashIn, const HashVec &branch, unsigned index)
    {
        Hash hash = hashIn; // shallow copy, working hash
        for (const auto & h : branch) {
            if (index & 1) // odd
                hash = BTC::Hash(h + hash);
            else
                hash = BTC::Hash(hash + h);
            index >>= 1;
        }
        if (index) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. Passed-in index is out of range! FIXME!";
            hash.clear();
        }
        return hash;
    }

    HashVec level(const HashVec &hashes, unsigned depthHigher)
    {
        HashVec ret;
        if (depthHigher >= 32) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. depthHigher is too large " << depthHigher << " >= 32. FIXME!";
            return ret;
        }
        if (hashes.empty()) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. empty hashes vector! FIXME!";
            return ret;
        }
        const unsigned hsz = unsigned(hashes.size());
        const unsigned size = 1 << depthHigher;
        ret.reserve(hsz/size + 1);
        for (unsigned i = 0; i < hsz; i += size) {
            const auto endIndex = std::min(i+size, hsz); // ensure we don't go past end of array
            ret.emplace_back(
                root(HashVec(hashes.begin()+i, hashes.begin()+endIndex), depthHigher)
            );
        }
        return ret;
    }

    BranchAndRootPair branchAndRootFromLevel(const HashVec & level, const HashVec & leafHashes, unsigned index, unsigned depthHigher)
    {
        BranchAndRootPair ret;
        if (level.empty() || leafHashes.empty() || depthHigher >= 32) {
            Error() << __PRETTY_FUNCTION__ << ": Invalid args";
            return ret;
        }
        const unsigned leafIndex = (index >> depthHigher) << depthHigher; // funny way to make 0's on the right.
        auto leafPair = branchAndRoot(leafHashes, index - leafIndex, depthHigher);
        auto & [leafBranch, leafRoot] = leafPair;
        index >>= depthHigher;
        const auto levelPair = branchAndRoot(level, index);
        const auto & [levelBranch, root] = levelPair;
        if (index >= level.size() || leafRoot != level[index]) {
            Error() << __PRETTY_FUNCTION__ << ": leaf hashes inconsistent with level. FIXME!";
            return ret;
        }
        auto & outVec (leafBranch); // we concatenate to the end of this vector
        outVec.reserve(outVec.size() + levelBranch.size()); // make room
        // concatenate leaf hash vector and level hash vector together (back into our leafBranch vector to save on redundant copies)
        std::move(levelBranch.begin(), levelBranch.end(), std::back_inserter(outVec));
        ret = { std::move(outVec), root };
        return ret;
    }

    void test() {
        Merkle::HashVec txs = {
            "5b357a2f1f18955e8fd08dc2d8443b0806cbbe6d60b29a7370844e4815ff0efb",
            "001dd1663f777a646190959122bcfd69ad6160c28bc3e99e3df65b1cb26bcc6d",
            "036ec76bdcd873d70f31c95637624c9ec975622cd2a7f34ff0130b36f51f87bb",
            "9e7ea0aa7df987ebafa2d392bee9bd5076a7b787bd450295cbcfc029224ed5e7",
            "e92c4f0a7e04ef1e65141c59343006f384a91b79605ca98dfe5caef7404481d5",
            "fdc2657742610dbc3dbea05f3e072b33811248b01a1b8de397fb68b0d67af4be",
            "768df8f9ef6226f3dddb2f532c28565b5d4f4d3e575d88f0cf7df8e3bf76a9b3",
            "590b32aaefb8ddf113ad6be70934381b951931a3076fa82ab199416eb01dcb48",
            "00000000f8bf61018ddd77d23c112e874682704a290252f635e7df06c8a317b8",
        };
        for (auto & tx : txs) tx = QByteArray::fromHex(tx);
        auto pair = Merkle::branchAndRoot(txs, 0);
        static const auto ba2quoted = [](const auto &b){return QString("'%1'").arg(QString::fromUtf8(b.toHex()));};
        Log() << "Txs: [ " << Util::Stringify(txs, ba2quoted) << " ]";
        Log() << "Branch: [ " << Util::Stringify(pair.first, ba2quoted) << " ]";
        Log() << "Root: '" << pair.second.toHex() << "'";
        Log() << "Level1: [ " << Util::Stringify(Merkle::level(txs, 1), ba2quoted) << " ]";
    }

} // end namespace Merkle

