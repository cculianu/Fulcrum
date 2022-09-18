//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Merkle.h"
#include "Util.h"

#include "bitcoin/hash.h"
#include "bitcoin/uint256.h"

#include <algorithm>
#include <cstring>
#include <list>

namespace Merkle {

    BranchAndRootPair branchAndRoot(const HashVec &hashVec, unsigned index, const std::optional<unsigned> & optLen)
    {
        BranchAndRootPair ret;
        const unsigned hvsz = unsigned(hashVec.size());
        if (!hvsz || index >= hvsz) {
            Error() << __PRETTY_FUNCTION__ << ": Misused. Please specify a non-empty hash vector as well as an in-range index. FIXME!";
            throw BadArgs(QString("Bad args to %1").arg(__func__));
        }
        const unsigned natLen = branchLength(unsigned(hvsz));
        const unsigned length = optLen.value_or(natLen);
        if (length < natLen) {
            Error() << __PRETTY_FUNCTION__ << ": Misused. Must specify a length argument that is >= " << natLen << " for a vector of size " << hvsz << ". FIXME!";
            throw BadArgs(QString("Bad length arg to %1").arg(__func__));
        }
        HashVec branch;
        branch.reserve(length);
        using uint256 = bitcoin::uint256;
        using UHashVec = std::vector<uint256>;
        UHashVec hashes;
        hashes.reserve(hvsz+1u);

        // Copy all hashVec to our working vector, to start. This vector mutates as we iterate below.
        for (const auto & h : hashVec) {
            if (static_cast<size_t>(h.size()) == uint256::size()) {
                auto & back = hashes.emplace_back(uint256::Uninitialized);
                std::memcpy(back.data(), h.data(), std::min<size_t>(h.size(), back.size()));
            } else {
                // this should never happen -- indicates bad hash which is not of the right size.
                Warning() << "Merkle::branchAndRoot encountered a hash that is not of size " << uint256::size()
                          << " (size: " << h.size() << ", hash: " << QString::fromUtf8(h.toHex()) << ")";
                hashes.emplace_back();
            }
        }

        constexpr auto recomputeHashes = [](UHashVec & hashes) {
            UHashVec hv;
            const unsigned sz = unsigned(hashes.size());
            hv.reserve( (sz / 2u) + 1u );
            for (unsigned i = 0; i < sz; i+=2u) {
                const auto &a = hashes[i], &b = hashes[i+1u];
                hv.emplace_back(bitcoin::Hash(a.begin(), a.end(), b.begin(), b.end()));
            }
            hashes.swap(hv);
        };

        for (unsigned i = 0; i < length; ++i) {
            if (hashes.size() & 0x1u) // is odd, add the end twice
                hashes.emplace_back(hashes.back());

            const auto &h = hashes[index ^ 1u];
            branch.emplace_back(reinterpret_cast<const char *>(h.data()), QByteArray::size_type(h.size()));
            index >>= 1u;
            recomputeHashes(hashes); // makes hashes be 1/2 the size each time
        }
        if (UNLIKELY(hashes.empty())) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. Output vector is empty! FIXME!";
            throw InternalError(QString("%1: Output hash vector is empty").arg(__func__));
        }
        const auto &f = hashes.front();
        ret.first = std::move(branch);
        ret.second = QByteArray(reinterpret_cast<const char *>(f.data()), QByteArray::size_type(f.size()));
        return ret;
    }

    HashVec level(const HashVec &hashes, unsigned depthHigher)
    {
        HashVec ret;
        if (depthHigher > MaxDepth) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. depthHigher is too large " << depthHigher << " > " << MaxDepth << ". FIXME!";
            throw BadArgs("Argument depthHigher is too large");
        }
        if (hashes.empty()) {
            Error() << __PRETTY_FUNCTION__ << ": INTERNAL ERROR. empty hashes vector! FIXME!";
            throw BadArgs("Argument hashes cannot be empty");
        }
        const unsigned hsz = unsigned(hashes.size());
        const unsigned size = 1u << depthHigher;
        ret.reserve(hsz/size + 1u);
        for (unsigned i = 0; i < hsz; i += size) {
            const auto endIndex = std::min(i+size, hsz); // ensure we don't go past end of array
            ret.emplace_back(
                root(HashVec(hashes.begin()+i, hashes.begin()+endIndex), depthHigher) );
        }
        return ret;
    }

    BranchAndRootPair branchAndRootFromLevel(const HashVec & level, const HashVec & leafHashes, unsigned index, unsigned depthHigher)
    {
        BranchAndRootPair ret;
        if (level.empty() || leafHashes.empty() || depthHigher > MaxDepth) {
            Error() << __PRETTY_FUNCTION__ << ": Invalid args";
            throw BadArgs(QString("Invalid arguments to %1").arg(__func__));
        }
        const unsigned leafIndex = (index >> depthHigher) << depthHigher; // funny way to make 0's on the right.
        auto leafPair = branchAndRoot(leafHashes, index - leafIndex, depthHigher);
        auto & [leafBranch, leafRoot] = leafPair;
        index >>= depthHigher;
        const auto levelPair = branchAndRoot(level, index);
        const auto & [levelBranch, root] = levelPair;
        if (index >= level.size() || leafRoot != level[index]) {
            Error() << __PRETTY_FUNCTION__ << ": leaf hashes inconsistent with level. FIXME!";
            throw InternalError(QString("%1: leaf hashes inconsistent with level").arg(__func__));
        }
        auto & outVec (leafBranch); // we concatenate to the end of this vector
        outVec.reserve(outVec.size() + levelBranch.size()); // make room
        // concatenate leaf hash vector and level hash vector together (back into our leafBranch vector to save on redundant copies)
        std::move(levelBranch.begin(), levelBranch.end(), std::back_inserter(outVec));
        ret = { std::move(outVec), root };
        return ret;
    }


    Cache::Cache(const GetHashesFunc & f)
        : getHashesFunc(f)
    {
        if (!getHashesFunc)
            throw BadArgs("Merkle::Cache requires a valid getHashes function");
    }

    HashVec Cache::getHashes(unsigned int from, unsigned int count) const
    {
        QString err;
        auto ret = getHashesFunc(from, count, &err);
        if (ret.size() != count) {
            throw InternalError(QString("In getHashes, expected %1 hashes, instead got %2%3")
                                .arg(count).arg(ret.size()).arg(err.isEmpty() ? "" : QString(": %1").arg(err)));
        } else if (!err.isEmpty())
            throw InternalError(err);
        return ret;
    }

    void Cache::initialize(unsigned l)
    {
        ExclusiveLockGuard g(lock);
        Log() << "Initializing header merkle cache ...";
        const auto hashes = getHashes(0, l);
        initialize_nolock(hashes);
    }
    void Cache::initialize(const HashVec &hashes)
    {
        ExclusiveLockGuard g(lock);
        Log() << "Initializing header merkle cache ...";
        initialize_nolock(hashes);
    }

    void Cache::initialize_nolock(const HashVec &hashes)
    {
        length = unsigned(hashes.size());
        if (!length)
            throw BadArgs("Merkle cache was initialized with an empty vector");
        depthHigher = Merkle::treeDepth(length) / 2;
        level = getLevel(hashes);
        initialized = true;
        DebugM("Merkle cache initialized to length ", length);
    }

    HashVec Cache::getLevel(const HashVec &hashes) const {
        return Merkle::level(hashes, depthHigher);
    }

    void Cache::extendTo(unsigned l) {
        if (l <= length)
            return;
        auto start = leafStart(length);
        // Note this may throw here if a reorg happened and not enough headers now exist. Caller will just send error
        // to the client, which is what we want.
        auto hashes = getHashes(start, l-start);

        const auto limit = (start >> depthHigher);
        if (limit > level.size())
            throw InternalError("limit > levelSize in extendTo");
        level.erase(level.begin() + limit, level.end());
        auto vec = getLevel(hashes);
        level.reserve(level.size() + vec.size());
        level.insert(level.end(), vec.begin(), vec.end());
        length = l;
        DebugM("Merkle cache extended to length ", length);
    }

    HashVec Cache::levelFor(unsigned l) const
    {
        HashVec ret;
        if (l == length) {
            ret = level;
            return ret;
        }
        unsigned limit = l >> depthHigher;
        if (limit >= level.size())
            // should we throw do this instead?
            //limit = unsigned(level.size());
            throw InternalError("limit >= levelSize");
        ret.reserve(limit);
        ret.insert(ret.end(), level.begin(), level.begin() + limit);
        const auto leafstart = leafStart(l);
        const auto count = std::min(segmentLength(), l - leafstart);
        const auto hashes = getHashes(leafstart, count);
        const auto vec = getLevel(hashes);
        ret.reserve(ret.size() + vec.size());
        ret.insert(ret.end(), vec.begin(), vec.end());
        return ret;
    }

    BranchAndRootPair Cache::branchAndRoot(unsigned length, unsigned index)
    {
        if (!length)
            throw BadArgs(QString("%1: length must not be 0").arg(__func__));
        if (index >= length)
            throw BadArgs(QString("%1: index must be less than length").arg(__func__));
        if (!initialized)
            throw InternalError(QString("%1: Merkle cache is not initialized").arg(__func__));
        BranchAndRootPair ret;
        ExclusiveLockGuard g(lock);
        extendTo(length);
        if (length > this->length) {
            // ruh-roh.. what to do here?
            throw InternalError(QString("%1: extendTo failed to extend length to %2").arg(__func__).arg(length));
        }
        auto ls = leafStart(index);
        auto count = std::min(segmentLength(), length - ls);
        auto leafHashes = getHashes(ls, count);
        if (length < segmentLength()) {
            ret = Merkle::branchAndRoot(leafHashes, index);
            return ret;
        }
        auto level = levelFor(length);
        ret = Merkle::branchAndRootFromLevel(level, leafHashes, index, depthHigher);
        return ret;
    }

    void Cache::truncate(unsigned length)
    {
        if (!initialized)
            return;
        if (!length)
            throw BadArgs(QString("%1: length cannot be 0").arg(__func__));
        ExclusiveLockGuard g(lock);
        if (this->length <= length)
            // we are already smaller than length, so it's fine.
            return;
        length = leafStart(length);
        this->length = length;
        auto limit = length >> depthHigher;
        if (limit > level.size()) {
            limit = unsigned(level.size());
            Warning() << "limit > levelSize in merkle cache truncate. FIXME!";
        }
        level.erase(level.begin()+limit, level.end());
        DebugM("Merkle cache truncated to length ", length);
    }

} // end namespace Merkle

#ifdef ENABLE_TESTS
#include "App.h"
namespace {
    Merkle::Hash calculateRootFromMerkleBranch(const Merkle::Hash &txnHash, size_t index, const Merkle::HashVec &branch)
    {
        Merkle::Hash workingHash = txnHash;
        for (size_t i = 0; i < branch.size(); ++i) {
            Merkle::Hash a, b;
            if (index & 0x1u) { // odd
                a = branch.at(i);
                b = workingHash;
            } else {
                a = workingHash;
                b = branch.at(i);
            }
            workingHash = BTC::HashTwo(a, b);
            index >>= 1u;
        }
        return workingHash;
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
        auto pair = Merkle::branchAndRoot(txs, 3);
        static const auto ba2quoted = [](const auto &b){return QString("'%1'").arg(QString::fromUtf8(b.toHex()));};
        Log() << "Txs: [ " << Util::Stringify(txs, ba2quoted) << " ]";
        Log() << "Branch: [ " << Util::Stringify(pair.first, ba2quoted) << " ]";
        Log() << "Root: '" << pair.second.toHex() << "'";
        Log() << "Level1: [ " << Util::Stringify(Merkle::level(txs, 1), ba2quoted) << " ]";
        if (Util::ParseHexFast("de2a609fd92defb4b696dda3f4a88d0bb486e791c8b6eb4283bd14f2c83e4f90") != pair.second)
            throw Exception("Merkle root does not match expected value!");
        if (calculateRootFromMerkleBranch(txs[3], 3, pair.first) != pair.second)
            throw Exception("Calculated merkle root does not match expected value!");
        Log() << "merkle root verified ok";

        // txns from BCH mainnet block 758277
        Merkle::HashVec txs2 = {
            "74faf9942d54266c6f67a4c03d40ac3cf70e0e34dfac55d97f41a18c1f83f4fc",
            "00149dbf3ed5d0232325df5cc3568a97e2f2ed46c41fc575df91daa2143b4b52",
            "004bef5dc34606685ba00541eaa121c46527b8f8cc3512231ac9146423b98754",
            "005bd0fc1eed9af99f14d7615ae99c23c12150a70dabfcc87ca23c69b0bdbc1a",
            "0095bb2063b089965a00e9eea19b32bb5227570778ab46c2560e4140c989b271",
            "00a08a261fbcd12a7dd4dd6a107ff76c211af6125bce54e6bc4df2ba6b0149a5",
            "00a18dbffad09b487c4108bb086ff5956681c353a8b9750e1062a9693c09a103",
            "00a28d367e992458fd42c35cb80aaffe6e981a0fc3eeb470f6ec8b38b4394689",
            "01262fc38b434ef0537cec7452652a516fb10825839de5b8ad80ae2529400b94",
            "01618bd39e39b500c0985424f41dbc8db562c5389f7d66305bf1c78d252269fe",
            "01bb2fec0f8a2fc030dd19025a1fb4060d9c4053d15e3b821cfca0f6a6904827",
            "01bec84366715e98116c33aa74146910c55d1849218cb1bf97c5d82f205ef55a",
            "02233f7373b84faaa807b2f310a2565229a4deae14c0936fd6cbe62d84c81c88",
            "0223d0dca29bd7f4314bd82b82cd8fb8464025b889783a9ffd9d91317b487fe4",
            "026b0206d7641f4e421b7fbff2ccbad56f6f98407d8c69737891b8e73fd8b003",
            "02b74d1e7341c1ff74aa0765649f7db69dcb1d33a8e6d2f0f840dee06da2495b",
            "02c42a7b1eb303e9bc2510ea6c311cd5e640eb02e7aad2873a3c1cac072c0f59",
            "0374c7112b72e161e16157d0225aac693639b7666458b1e109a74ba7c0080018",
            "0384a9a801979c39ed6959a1d1f18eb0df34a43ea970b8a1aa5505da600cfb02",
            "03983d7287d33b44d0d2611a4e76129cdf10aee2f7f95b59adaf992587943bca",
            "03a48da65cfafe3018fe42dd7cbb56778d3a53f9aae515dda88773c4fc6a9abc",
            "03c443ea5365191f5e2ffa98856f6d67327968b14731ce3b31d10fd3c1d32ea8",
            "045e3799e460221eac36c6f893cb4377f41db94bdf16f4dea5cfeb2deb89ef66",
            "0460106fe21477ac400af6ec0c7fd3bfa67caeea1fac8f5b1e4e92ceedbc747a",
            "0476d9de3aff31759db70aa8e5d5e330b8fef11753cfe3ea4d3536136a1b9a6b",
            "048e7f0153209e1add2b27c0d63fa9ca46715c722ebdf8beaf9f76b0ec5ffebb",
            "04b587100c902450c8e71daf312faef701338de42e22b86912537c1e00520289",
            "04eb4d4ef9f52beb052bf83506ec6020308cfe61b67f71accbd199b0a3d87e44",
            "052247d161e5dabdbb4b892fc4bf659bb53fb0faaf5b692eaed712326450c1e5",
            "0540a4cc65c97e45474400dcfd4966fac18a7b2fae30e6caa5df9ef07119186e",
            "05a1f0d167554407ce84c4bb5f4f4a752c0890ad33fe5517722a4130ee3719d8",
            "063615892f78e5b624436b0058f544dcadec28b0cb1034eaad9c1fc3e189d2ec",
            "06362912267cc5f5e4cba553abe4488a9a03c22c9b7cf660f02570ae95d3ffd5",
            "0651d3fba760746744b84fb039c7d8a791b0e5dd09aad10148f86aaba3e553dc",
            "0689d017b933a2302d2bff8f58eaf17657900dda3d732cd70bdda80e6465c695",
            "06a87fdda4e84b0c2590efe634a7df0f22b69f7e3c41e027a054fbd7b4076cdd",
            "0724467bc448d44b3c6a74be24521021e688b3269f7e4a8535cf772cf012ca10",
            "072e42f1fb2112b2dd12883596a858b6f6613e7bc904db5df9760677a2e2301c",
            "076e5fb52798ae4be0286f3fe7e7d2b6a729cd76255e6d2c397966131256fee2",
            "07a49fe8763792aaffbc9e5ae7197ed204ef976aa47aa15ef6f02aaa0142a5cd",
            "08095a7a1d0eac9732f278afdcb131052bb559bfe2c0bdcaf8dca555fd27be69",
            "08103eae5948eda74b054be434009153bd654262a70b195350133c40dacf0a49",
            "089afdeacda945b2bd1d88113dc5e3ff2b3655a7b89e07affab863d4b6635f69",
            "08a7317976534f4161216bc6e02016d546f8399945561e5298e39225e01a94c0",
            "08bfc5ffde62cbe5c1812b4c720f1437581a744caa23097453972b56c78fd3be",
            "08dc2412eef740eb333c4741523cae76dab75aeaa12fb233c9a1696114a00c67",
            "095ec41e850cd2a1ecdd6f55589f3d79a2582f91a49b75f39f24849e177080d2",
            "097adccb2aed43bff8bc20d6202c88aa66050525f993e4faf236199769b40b7c",
            "09e56999a017aa0301ccfdfac0f86ea45ccdbb7dee7816e568ecafc5bf5bafd7",
            "0a65d86985ac453f378e603df4c58808ec5e30f6bcd5111b2d2d189a9bbc9678",
            "0adcd548524dfa3c79a2431c7ae7e7d90f4e9057e7c0f83467ee34704495314a",
            "0b22843ee86e632922ca37d6a3b981a43cfe91200dbb160ba40da26f27890a99",
            "0c2be888b4a9035e32b391f5d26217d3544019b680a2770ed80b8722ace3ce1c",
            "0c32101d8fec10fec0b91dfd91f883204d13d6e81d910516f7e5824676ed0211",
            "0c40316e36ab6ea933c0d8c16f5ad9641410623fc490f56451cac70cd02717b0",
            "0c4b45cd25761a02e4100e41f98816685e52fa71a251bf3de343803162152506",
            "0c5e8e1e7a23dbefeb47b3320a7cf05b09a6b1985659e796e40f0953d3242df6",
            "0c821ff9a17b620aab1f10f693a368b1324ff45167ffdb4ccfbf4ef92c27d90c",
            "0cb5abfb71ea7aa85075416a9443a11a0aa78f1d89cbfa7f6ed58e60fb72e3db",
            "0cdee35137f3b4f0d0efae7f93684bbc499322dded98ef7bf76808e7b5f696f8",
            "0d3a1143af63003702906883b7f231c5f3357d4d741a6213beda1346c1ea30e2",
            "0d3f4f5985ae2cbefd6d5fbab71424bc75659f1ec374506293c5f95857ad951e",
            "0d566d4def380820bf638c0d40986d04e300c1e661c30945586481c67d23f8c5",
            "0d9f5cea62bdd6ab6c70f3d2f8c52b62dda7f76712da431c43ad7ec6ecead147",
            "0db45012e28672e51f3a8dc08f4b93b1cb34458ab14b0734ff130218594d1664",
            "0de82f907d9e7750f2c821a217166c454e93ad0494d30c195e6e20eeb6a8c596",
            "0dec764d414ccca94c5447e2ae153bf39e082650ff0cda96c4d3825cd9a894ef",
            "0dfbbda8b3d136fb38397e77e787610a0db910adf2f63a9643f8ce53c92ca676",
            "0e1edcdfe2621a614e078481f4a3ed8755d0bf670065e1b799f902c10076943c",
            "0e756cd86917e07a74783201e873c4fb19d9457ce5d0cf503ef9245025d4abc6",
            "0e7593372182071c904d26a80d830029514ec8132e3b802dedccad7d448ea514",
            "0e8270be21ea6d48258e781529030cf9ee20d3efb996f7731f28e44fa962e736",
            "0ebb0cd3c57254b2d9ba5adcf9ec5c222d7922d1d0d8f0485da259ba1dc6e33b",
            "0f1ff65653bb6871c47def9d18511cbd3c5f0c6b9e2381277af5478d50b427f6",
            "0f25f6b46fd9fde223efaf2a055a6237693e2e9947b2284df6546f30fae34f60",
            "0f7253abf24d147577ce366269981f08968f3ff2ea7c2a33a9903416632e65f8",
            "0fc87917e030680ab4e22031f6f70853b4b5bc1a458de84e37131a078fcdf8f7",
            "0fe9ce09838765a79d0d9d561e1f369f92b4cef9967f9fd06089ee6cb76ccd4d",
            "0fec7627a062dd65290b30ebc7179a2e0fa0addd72c2cf682c4f0523d5d2c0a6",
            "100822c341d747ab044068d3c99bf56f6c9afe0e95554a4b86d71dd6585c16a4",
            "101acd7156a2f37e0b5cc26d38d89d1e588b61434194a3005d78965a9fa492fb",
            "10613fba874eb2501d6adf4a823f4b3a429c980787482ed6157f3b8a9e48c9cd",
            "1091345289c735b59d0e4758a6d41ca3e7d048eb9ce3442b49ebda25408f6061",
            "10b560ff5ba74306ce0edd8b429ddcbcffe199d6b3756bb2662cb7672e6440e5",
            "10cda8fec03179e3342b86a0f0bed3f0e2a613e042085437f4759b831e581079",
            "10e03c975466b08cd2314e3fdc4ec6e5f8b7920bb5102c2dc97276135bd8fc70",
            "10f240d961e5d1af763cec7e515afcd5845943dfa6be1421b92dd55cad620dd2",
            "110ff1bc457bd314ca05cbc33ee201cc4e6fbfbae87c29d10998568b32af0df7",
            "118ca9b19dd6ab8917daeb4987a7408561fbd1d4bad18e523df6c8b1dbd33e9a",
            "11905773a45e8d31624cbae2ff888274a7edcde879a42ef5148ab43d84e92afc",
            "11f9c233828480160fa98b9cc48a7864e04f78cf5c620ad49db865152fce167e",
            "121ae4cddf672a67414794cfc0901555769c3ae26054d5b2c88aedc62ffca41a",
            "1267a65d13aaebf7974bf6a83a47eb190db8ffd95669f1529138c2caaad313dc",
            "129f5e3aee5a1fc0eb0bf6f4c56814b41fecad821856f08a7e164c0db24e979e",
            "1333b11cb928f26827285a956b15f71874c1d528e6da55b37d20caafd361e8c5",
            "1384c5ef7405634a7db7db8e3e7e69aac944bca0209fd60c6aa5442131d26157",
            "14b1cb8ca070d22ee078148da60542ba19892766a43d5eda23c15d9218ac98ba",
            "14bb7b807bb83396cf6d3e45a981e763e4d79ef0de92e34e204e122b259f167a",
            "14ce06b90fff706e0ab5b78a7a6cd0540ef2b3b7cdfd752fe34248e9c57c49a1",
            "1569888bd3a3238d3d46d080a270c1e6acc50cac76b535c1dae860383eea321b",
            "157f36dbcbfb0ba702580e314558ead9695b9a68a072356bb9fbc25f84496db5",
            "15c04776958f468c5107050427e20cf7be9e7b45653b8adb0e9fd47f578dbe1d",
            "15e7476c76b1a3abc8ad4c4a6fa3f1a94871ba4ad001a69528541300e6d2f8c5",
            "1631b520099f740515b0b36d1a52ac42815889024267c1f550fa0d089641b89b",
            "164c9efe06a152cae449b41594bf49ebdbc1ae376676b53324bcd22b4b102b53",
            "169023245ffe9b9f2b03f1ca4850d8bce0962c14605fc933f8400f47aac07294",
            "1698827fc988458d5b8054f556fbed151979b844c2505ac1b886e333aac203d7",
            "169891403021eff5de863357a174012e2364647644077916dafc940edde98ae4",
            "16c97fc6a7a19444f371e3d921f403aff2547af63c517b207ba8c3863a409000",
            "16d79762bd86dd1272493bc5d19c8639810efbc20583bff2b3c9b0b03f232c57",
            "16e64809a09812729a83269e26cb987a5fdd45b8d3df6065db15d9a50ab99aee",
            "173c8ce8e751a7e3aa584bc4d67db4e053e01cd1a7bb40bd9bc5cc467b3900d3",
            "17c8c6aefc10121558c08c03d720a20f64928d9b645dfc2ba14b80497d95c7fb",
            "17d31f5405d388c57363e317c77929811525072949a758481415d91c7b9e3f07",
            "17d99d2687557ad3b9ea018cc3adbfacf2314635ae0c28ce620f8e0a7d85b5bb",
            "1820b2c99a5d46b6557a39c5d0473a964aa049f6d69b6dfb44c2fbfbf4b290c3",
            "1916c97333bf682e24a22c57a87f9b500738157a373ae4b4ff4791f27148f9f6",
            "1920c971c7a52904a3d85c61911cb25c1967ddd09b7e2eb1cc92f4a4f14767f7",
            "198a85951cd43a184da693af5f52a001a0458eac94fd424766b5c83677c66e1b",
            "199cee65e9ba33b092921954fe731b6a0eb42d79bbffc89cf613b290acaaed88",
            "19d67c4f3cee77a9ed4a3594a20da3542cb512d3b03de4f8b75e39a6052cbf58",
            "19d9f7282298ad12c35ff500fcfe116214ed8448f22e04651828013866898a65",
            "1a0bc71b8bb61d90fa74e1df350b8b23d4988b98b8f6527b01cb6b5e2c629e5a",
            "1a3a1b6ffa37198efa3f26db554d951c2f2639cf05550b75d13550cde80f3e48",
            "1ac2612d9c53f68b44a99857740c18755e6ca767c21eaf271e0d63a650aa557e",
            "1b080622aabe05ccc81136db31e7bf7568ef2a9dcad98eb884428b4a1038b6b9",
            "1b0d3d5ced420c45cd163153bc7c99824498c90adeebb4c5bd89bb34ad9a38f3",
            "1babb844064f6ac16d1d30451834e30cecc88169c94e6de27b7178cfba98dfd9",
            "1bd3b1484a0318846afa7375f1265cefcd1b05d44698c0cdd019c4b751e83f55",
            "1bfd28a592575d0c3fbcf67385bd20921d18bf97739c23ebf674834380038e44",
            "1bff935ffd39a1160c5645cd450246de8ec61172475263cce9f7c8a95c647c82",
            "1c4ef71b118005bddb3f2f21e7b85d2ed027bf6674cd11cdee2f06ed45d37ac9",
            "1cbf06eed219a84aa8cb4df87d3c546e0cac5a0661298d31415b8e696f80f1a1",
            "1cc3db1b3a645a1b59f50e568e14f7c96aa812933b4d2ae55c39edbd763a4ad1",
            "1d25c30d3bb641cfa1892b7da7b23348a8d4efb39f602bf7a28c6c594bdb2a0b",
            "1d420595e353bbe0a795147f9acb44f6e1fdf2916f5eecf5ceda674d4481ef45",
            "1d423c9944e738eae33705e1349ad23b728ddac059f13416578509df42b4e70d",
            "1e4b1a97422160652b781fc565613f70474311a2db3ba443e4d4279a8951dd8f",
            "1e63d723e104997e3c35eb135aaeb8d2bfa4fc7421e115d7a1daf58b4413dc7c",
            "1e867caac5cc8f8c18f57f5fa56db0b4532e484f76b9a6ab9fdcc923c729931c",
            "1eb1707db916093dceaddec44d318cfa1c3ff8f3e53592d6afd3f87138597b97",
            "1eca41fdbcf63c70751ea0a464e5ae0da1f1b84b13ea13f7d67ff6b47e5a1381",
            "1ecaf8260e9cd2eeaf3062ea1dd3c07da6c96ad25fe74d9ff72854973b3b41da",
            "1edc866113fc2b3c01ffab626dd672251ad086793e83930a7fd5eb9180ef2faa",
            "1edee1133349c83e58b96dc0cfeaed9eb7752ad6bdd9717c6fc21e33a05ed0f9",
            "1ef6f83487a92673211593ce640f96d4188adc8ce2b53dad71713c6e7b5eedcc",
            "1fbc12ed2559a2351214ce989c6585a25ae69ce48986f576846c876810ec7ee0",
            "1fc0120420e1a6b27ceb85036bf03110a804a6633bcb3c9026fd2ce7e2cda702",
            "1fc8d28b63922a5bb18a7222098db0374deab12bee30782972f607f9cc6fd2d3",
            "200a24e6d1877d3fc34d841f66f5e256280c76c10f7c82d68d101d33ef1f1990",
            "208006490fcf7800c9ee45585f7c75b422ef3c1742e8d444cabe3f52fdc92072",
            "20892bea9c106e81edf6233e8a34ac9cba340fd93334a08e044edb92dd66b50a",
            "20e22f06af9e58f6bba80730c8cfd9f5731b8fad2da3f18310e5ebad0ad33b43",
            "21070b85cb25197b13fbee3a86aaeb728b6c4b259a509cf8fb014d1156508729",
            "2143fbddc76ba54ec3b378f4d11e94c761d73fe24cce38452795dc63d5ab4b51",
            "215ef64b3f89739dac35d9a501ad1c7f8fd3d00ac64c7557b3cad781fc6e2511",
            "21880aeba16152b068d4ceb7351959ab29f09797f3475ea77b252d972ca24443",
            "21ecb3e76fff2058e4aaeecad2a83722c2264f8bc51d3f38bf011b414aec351c",
            "22213c82ff9fe03d39dbde35eafb4a3fcea9f3834ebddc7d9608eed63c7a25dc",
            "224256f0ebd58bbdc2e7d84bce7dd5ef646e7e80c0d3777ee1fc61d330a16e96",
            "227f9f6037b13c3fe717209789eb67778740d0040b233cf3db43b7dfb24e2630",
            "228a7584cec2878810bcfe2917a014ba843508e4077b150d7c100ca1a55bd39e",
            "228bc88363c04d25aebfe2e4362bd08cda8196eb7d09bf946e1c0e0882367d86",
            "22b825a86268165eb6dad00f87ca095d7893673a5bcfb2fa05e935b521dc10f5",
            "22e5f1c5650742ba64b1af223b74b03d485fb6209a7a4757b1d0a37fb3a8208a",
            "22fef632d88bafc771d00be91bd642622cec0adaef23d4fbbd924bd08b9dd9b6",
            "23219b78fc6fbd95ded220f5c2cfd2c1ec78a6701a77e360ac76d787a7c07a01",
            "233771fc41b203109c781dfb2715510d07707ba2f0fce66119ba24d674dd2548",
            "233c3db92c70bf5342fff8b47fde945fcb5ac1954b88f3d59cc0842f682e9d20",
            "2349585c4fd117fa92f265124e01be477fe5ef8df557512cfd4d3604cf07578e",
            "2377ece685461e634ff6e0b6c75694d88e34ee03c245739097925fa9875be74f",
            "23a44d387e4793c6291ad498d5bdbaed0ffc1009e2ab58e27b8d137824dacc30",
            "240f0b63ecb4fb8b016788e7723d356b2fee4b992a13b31fdf71f52c9cf9a7f6",
            "241658c5f87cf242f74b750f1eb882f7b8984d566c6491101045298cb9a70e32",
            "24a2c01e28867b68835bc69f16e5273ef8acaa37c841ac843e1b868e6d2b3153",
            "24dd00befeeec6cecd9d7b61127006028cf9b7be13580ecae7eefa6cc5f6c05b",
            "253aa42067c11bf56c85b742c2ff55ccb830bbecb528cee5cde53fa48a509afa",
            "253bf67c8a3e3727b8a51a8d4bcd3617a865ba676e08a14f0c5cd69791d73413",
            "258f8c8f2bc0d1114d17f2e185a7ae1dd435d3b9549641c5226b7acabbf84dfb",
            "260b96d8cec72b7bae20b340b4d6062158e5caf6c038824db6f0de2182a73ac5",
            "269199258562d0475e285dadb734f9bff3b5b52130708d7e3929c63c5e695aa2",
            "26b181a05ec3634f95aaae1964fd70d0f8ade35b0abbfe14fd1c4671ed995a22",
            "271534303af3cf4113e569bd9ea70b245adabe8cdf04e52ddb601bc494ba048d",
            "271e6b1f66738d1dd3f0a1f1884d47f9602d0c8c9e16f51110a578828fac0ee0",
            "274ed50b29feded5808e4a23ac29105f30c6d45d127abeb58024f490d0dd33d5",
            "276accda7242f09784b2e928df403da49567ea88d81cc2b4ffe12862e5a3bdd5",
            "2773c41512985c892a8ad95b27ae1e9ad38b2869650409b9844e2494860fc496",
            "27b718250a19890d7b30a6afaed212f4a0395aa8772df3b1193508e51caf23ee",
            "27e9c5648b850d56b2428355c7b52cc765f5206827b38064d35553a7977ad678",
            "27edbdace88c5832cea48eed44a5ee5deb5114f54af4827b076441ce790a83ba",
            "27fdda993e79dae8a9b3a409612bdffa6fe3ff9d6dab490a4e90d153432b0237",
            "28e119a00c793aa53f7313e141762290131318c7664613d17a13eb545e5ca1fe",
            "2920355d7430b24f5e4f2b7f10563bc688e61b9b39e9bcc70e72a72d9501d907",
            "29b6a68b035f4a0c333ac69bf32c592c47e008ae924514d100b1957f31ef3afd",
            "29dd347b3be31faec9608dbe68628c749056397543debe478e5f790a4965124d",
            "2a26411d5c121e62406209831956b15a246754a06488909b993cc4ca0cd6dc31",
            "2a72531bd2c7aadd60911debc336fb861c541b140070cc42ca32f44f649d3bc5",
            "2a95051c68a24e6fecd8fb30d0b624d6dc188fbb83ff12f717fd32bc8e0fb473",
            "2ab32879bd4f048efccd6b51e78461e3692948cc708205b2b82efcca43dfa0ce",
            "2ac02590d4d658476f362d7061818c3b3589ab35259af319fe71a8fb6885ac11",
            "2b7da6d287344d7504b388fa42b13fb28612e840ab9ae55b8c93203a49faef86",
            "2b7f594d8a60b3b6f3f2f0c4066eec32e935cbb5b8809c1f83e192fd0e9c5316",
            "2b888bd0f214b41242775bc8bec57a3591629588a7f58f4ad2d6c2cf4cc8e993",
            "2b8aadc3e8a65c9bf4d3334ba2cedf12ac454e9c55b0e203a0c4b1d5077da9ef",
            "2b9127324430eb60753adb0eb0d7b222d5b19459914dbbdbbe00d160c220e79a",
            "2c6a7ab9a9ecd3ffb21039ab967bd488c83f086da37f6494ef5f81799be753b6",
            "2c705dcde411a22073ab21e1907c5978cf94f5038beea931d11120bc65382658",
            "2cce4d5ba3fe54e464b36ed06593705bd428ded36b2b637645591c4e025f1444",
            "2cfcdd4f2968781f5029b66be4dcaf1cd46688a04fd99fb587de1f38cd5dd5a8",
            "2d0a526eade4e60f4ffbfe4561bc1b79980aeb52c1028c59080ad144270e3772",
            "2d5214178c2ef5b4f00b7b784181b1d1e10f8038acd7cc63670b3b00d03fc6ca",
            "2d8a745b13ba02a8e73c6c7dcf004b5afb02e580b40b02982b9d3db4b0e2fee4",
            "2dab6b86e6a4c0cda88d54d1af42e6eb76abf54aee0341bd9da630ac398ca434",
            "2de0bf57900d25e69c6a83eb5b98c0e085b454f01bba2e095587c1dfea6d4af4",
            "2e610dd877abce3ee9a355cfccc05f603ee3619a56ae270c7c3dcdd0b028a9dc",
            "2e77183ba6a853eff9760f6bac6661ef6c82ac351fa130bf164330cb6ab14472",
            "2eaf9175c4631b22201797bf1f1fc61f087975a5cd19c0663844f10cdf20aab3",
            "2eb310f67b39009b4001bf271a21eb544bf1b788e0df8cde51a377211a21ab3a",
            "2f8cd1116a113d51fefe0f74e975e2e8510e9cbc3fbe525cb2ba1a3b50869dd1",
            "2f99f8860be207543784c84ba1428f2069fb81eba726cf277b2026b349d05c24",
            "2fa83c97b4ed5668cfa338ba80a0f61336822a747fa85bf8be8e5603afad8098",
            "2fd2dcae70f3938c8e368f3ec9044372388cc655e83e888d39cdefe2d7e67a7c",
            "30178b0c3fdad7d7b71e44fc0a1e604312c22ec1e01533c6c22547a6e5242f46",
            "302fed854c260fda7c1c6d8dd0859f90efdea582c3e088bee1f53f20943b1fc2",
            "3036e92ada165e0ffb63519c02f15b49434ec6d3da910a78c8c2b41db026f0ed",
            "3061ba901048beee5588070215ddcdac7a4966e420cacdb84a8c4473cb7d9225",
            "3121296ec9195662322d7aa6604869ed84a39366b20450c70cad4dd059dae36d",
            "31345c0cdd8c3c5109b5de7a859237f07b193e61df0cebd5ad4040e9af16a75b",
            "31ac0167945f806f2ccf5c43b486ac496dfa5eb8b381a9cf0410cb771a2773fa",
            "32472cb980717bcaada7e0fe2163303b57a28c102cd948c7371a19f6cc19c4ba",
            "325facc8092ecdbe5b0b3e1b0e876b43c8be6b0f609c2c291e3348f694e39d7b",
            "3267d320069ce126f4b4f936106221f4fd971356a814c260895d60d7bfcb2ee4",
            "326e51276e3c4f290b087de41cfc7f943c3f48df97f3471850acfd83449d06ca",
            "32975c5735ee1ce3aea1dc233097c12ae560ec886cf28ba62d0b74f989ae9b5a",
            "3328cb4469f8606edf5cd24e81c52dcf9b25c98ca1dcad80767ee7aed66cec40",
            "334f50cace64cbf84d31e00ed58ec1f27ac6aee65f70bd8055922505d4939993",
            "335e5d4e83202edd9d5719633dd8823f711bdcc31a45ce1bf32292f069b7cdb5",
            "337cddbdbe7da6e3f2e51b0ef2859a093ad8c566be57c8e1be0ca278ffd2403c",
            "33959151bc946dee2d09d5e85970e815030b05680a99f9234a87e99cb886b085",
            "33ea0737a7aafee41660bbf01ba2088823be8d4a58e1d97522d80396385108a8",
            "341fdbf9312d35e0cca93ba969e8f92b5b488708b1e7c052961d841c6c92071d",
            "34513539cc529cb3f2b1a119f7d985489f494b2869a70f06f50b0ae154a77734",
            "346c6cf8a7a5b968824f8c5d41939d141a886480197a3e1cf46fa780ff90e564",
            "34ca5d66511bd73de4b184707b48244e1adb4ebae8a49ce136d5127dae4ba499",
            "34d10fb21b06554aecf1a97d3edea4aedf5e1aec74807a2b08fc079276460131",
            "34d61e4be029a754cd361f788629a5fedfc86c07a0a70a606acaa85568a96769",
            "34e53fc71e52e0b51751964b44a295a2df1ae3b4912bf0d1ec758a9b82a6a52e",
            "350f078ed46c9a3a20b3a890aad4812f129010d5db24a755b83f7d56a71a096b",
            "3515fb4decb873229eb9fd83d5329880f48c81d3e73671730abdf8039d84a9fc",
            "35ce84cebf6fd3357f2f7e80bf67a5d97b0f79287f0d48c8c541ba9e14ea1c14",
            "35e4a5dd1a8f0413f3858a59f0a35c6d408909342df4365094a57d98cf5f8263",
            "35f600a97c21bad4c9540e9093d819131be36239896598b171f45f9da7353c50",
            "35fc39dda52dd1307b9ed284962e8e740ce65188845805f505a64c5474426209",
            "362eadb85db35f7d88ff662150568ebf29615dbf8c952b23a0d198ed303e941b",
            "365c03675bf7a7ed12fe082c0f547c7750581c7472fd2842b59d1dc354deb614",
            "3692dacfcb2114f8c59515630b8ee5bce6f06e1f36ae2416c09f1f53867b6968",
            "36b891de14b114a7982890dfed67cf40e91d354b3ff9419ce76a31a7f99f8071",
            "36c29901dcca8184d1f575631d5f9a27f6fae3fa54c46950bb52a751d365dfab",
            "376019f91e224ae635ab10fa6c23c56940b4261ac5aa307fda9ba96da57cfc41",
            "377fbab1486b9026f6c76de06130bda21bc7c7a33bfd848d978b41c0678fab16",
            "37f05cba4e4fcdcc9e68840e6688daeb8733b75bf9b0313ff0fd00e833282165",
            "381bed9ffbd4c39ecf6390b5ad94bb43b2d3e67665e1f287cae07e3a3507821a",
            "385db2f80d0adbcf66274623691992711b65563c1c93ca14d6cf03a503dad391",
            "3873372961fa721fb1f9952f92096847a475d86b57754af1738746d200b8ee6e",
            "38916726aa57a26629110edafa5fb68f632b69ccc1d229fb3a10a7e5d53020dd",
            "38930afd5f6ac6ed416184919e11edbffa5927eaf4e94673b5fcfe616f361c87",
            "3895d6cd148dd435649755745cf0be5355d80cc157c810b8524be9eab5061f70",
            "3895f43a7a6320568fd4849f3d6c60fcbbb7729f1d1f120db95e5efab43cc2a2",
            "38de4b1d4c4cb7d6254a6889995ce9e8100e83d8881ba5adc84af4a4d30cdee7",
            "393bb0ff00f9695a6bd70b4d77f074e04f4e21d7583ffb45e3d88ed46cfbc8f9",
            "396eeaf02c45f0d9e19c42f0f6d996c32284103bdd3474a14f0c700c03799829",
            "39c446f561461d21ad839f8a4dc69d05d1e1e83eaf7a64c439649a22027228a2",
            "3a3e01fb403d3dd0ab2f6432f72496afd668bcd66af32ab464549c43fcab1b91",
            "3ab74b3bf48e72306d000b7dbebdd9dbad39640c6dd843eed334092e83553d65",
            "3abf29af02670afae40ad2cf360440f7a824d51561542a064d3e8b523a698a85",
            "3b126c4dd1562cca4d87c2d4c365f0644943f896c328394baca9a73ff0bcc245",
            "3b3fe101a4d2f50e150d67f1a884bb0dde9e1cfcdff3c21848f66174ffce169b",
            "3b52fec02273c4a0b3a44029ad794c0cf258358b0f3ce623fa3de3932697f5cd",
            "3b7e654ff2466dfaea98c71d42b4d05c058f12b78bcdf01103b613fb115b2074",
            "3b8bddea26e8c3cb2e7117198f80a08757efe1dea8d92688df4b86a4b9d9134e",
            "3babd817eb5faacf4a98f58463529a90eb35394fc409d927cd3f953997fc2d28",
            "3bf63508b61992f0e341a5302bf19758bc53aef7af3790563bdc01286fce8d0e",
            "3c130f54ecdfa76d1d40fb954a383a76f395e428776400e0cc1e98acfc2cc193",
            "3c1beff78ef2a4a2527a78c8ed15a579462ea51ed83f5a80b31320d8ca5573a8",
            "3c3551fb86254fa64fdb2083205b0b26d9be162a92546213f4b97e51d5214bae",
            "3ca2d09a7e5d4ff4adc05fc00f5a74c1b1c48e634874324b9ebf10e7df450af3",
            "3cf99a095e2b76aefb23f2abf01344cd9a1c491fc34f4816a2fa7b4f6b6064ca",
            "3d3a14023fb513a51a8f62616151dfdc6828a8897b6b610f69bf9630cb296934",
            "3d675f0da413f4db0d058eca0f7f1e468e3e3e3b34f7608840ec986817470624",
            "3dc84fe58dd8d9b9d851744b32f40a30bb42b57fc6b878a8b821e3925ae20586",
            "3de69ea14b7598baf363a3f1dd1b4ccc8dd4b2e38783d5b8eebb05e0f214b317",
            "3ea3f8e15d39f43247e5cdc6657e4454ecaf1b5234b179d20920222d6cb68fb7",
            "3ea8c4283fbdd2c4f7a2c03beb2025e2ed251b16884c51dcd1707f72f9d04507",
            "3ead0c0c3e2324dbf8909b95ff85c496229f8904a395e95d8826017e02cef8cd",
            "3ee04c24e8f34bd2564a4f7275763c432a2e4b535f22971f9a5fa33d1227b89a",
            "3eff60978b5642aa6a95e40b5ea85d7ff86467395a5935856e35c4b5d7192965",
            "3f01c6dc485d677aca1d2bfa441fd0019dd7d1ba6bfeb36008b4bfe325a805a0",
            "3f267dd49d42a8db9d7cfb2a06073849644e2fe3508c90bcb791116ae30194fb",
            "3f66e9df1bdbfee708faf68ac05c70122925d252d5375b41676291b3ccbba15e",
            "3f6cd6df83ce0112885bcf81da801dfefc80684e1f55811499d97305bd51bdd7",
            "3f894e29e2759454625cc25e99780a44192e06943155f5cf64604e2ecd70da05",
            "3fa45d12ab95e66c676385b4e08c4b2d7e4a1199371dd6c9140ece05eee00a17",
            "4005d2d436dea812c39ecb7ff1a899fb7d9f4502494524d1a8ab9f5a2cf3f52a",
            "4089d512813cce09cb888d0231e43687426b94c70b10633ade1d3b093c1d6858",
            "40ad66df095f3f0e23cd1acd7d52333a2d9c6e973396922595f57ceb80bc2efd",
            "40b48dceb848521b23ed5a3047ece09ae9a056aa38345b0a48997a55314062db",
            "40c411de1461b9db731857c1acf3134f50fb6e5985486c89edaa526228f6d5ec",
            "40eb8a380b7cd88cd0ec911ce8ac34b0e2b66b624b33fe05cd70710325f570ec",
            "41203fe06bb65c1789327751f729486971bee03c98151ec2859f93a21ae298e0",
            "41ea56624f29a23e29b61690f2ec4e897e24830642e70874e1115fd4c3245f88",
            "4204e6ad2f9478b3eb178db68ce90ea1d6685a84a5d4fa156c68d23f016ab8c8",
            "421e0fecfe61b4647596e95f472bfef34df8abec91ca69fbd9346776b497cb15",
            "42cc216a589e90394a53bdeef09e6b327e47df5c36b0414ae216a940d6eb2b90",
            "42cf1c5243682a3daf4f88fc2da04a8b6cf8d6d06104ff87fd4b1b4bcc88657f",
            "42e540e9d9c7b4f9277046e410d8dabb3393466705967fe6f584df6c77261b2a",
            "42f42b7dfda1668477bc9cde45bf0f9fa50e99f10ee43dd6c6b8f67c83bfb052",
            "4348b0af212ae6338cff2880cfa500b5550df592dc4a08f7fea963ece93b7cb1",
            "435626a22234a73d2aa9d15ea9f4b327e46da91348071cdf1f6ae3a9d06ee5f7",
            "43ad6f8285ee82e5c4b290f188a030f00423241a8e3fd65ce4d01223d78deeb9",
            "43ad8f82402903462759b5d274fea1447a98f62595b5f261be9950aea50bf53d",
            "43bff026c672be8b9c44df8d6c14e5dd99f98988d3cc5d52c113ead5194bb9b6",
            "440197cc2a01acfa738f4e45a9f984adf43537caf61ae52e4b175e0712478ec1",
            "440377122c26f9520b7dd2fc7639e9c848e61ddd9839fac89ae44127ba0f2870",
            "443cec4daec6591d67573ba541e05600d8c58a1900ca813fa6081dcff61ac090",
            "44860f705a503cf5b67cec5dc7b0c3975933c00abfcd3e62a4a32de0c2cbd02e",
            "44e4b85a1f3078718d0be1b5299d4b5e4181bad172278a02d1cca786760ebaa6",
            "44e83dc1295aacdfffa80f7ce94f4b1d94972144f39348f05e6c4a13c6ac3864",
            "44ea103100eae19e5a9a093b56c2566cf2cbe1ace94e5f03a596cc074119ec4a",
            "44eb9f3035d4647ffbd0a0e0393b9156d652d93ceca362de981c4f1c154ee303",
            "4530961aaab0c3292bdc6a8ecf3cd0adb40a1b31f7bbdf6815da7528d8a12018",
            "45366838e2c3d8ae077bfd384f024b9ac2fdd9e4d9799254a33977979526ac12",
            "45de0b0ae644bf3076a89d9706ee34e79aaa89753b6373d8ae2015640fe56cf9",
            "45e134a9331470a4fb10b2d771fdcc0960aee49d2d27865f9c88db0c3518b64c",
            "45eaf7022d6f009e5c215b0af9b922f5a14156c7ddcbab54cfce8a643cccc0d5",
            "463dfd7715c9996ff9c32f108d0fd76296820230fb57bcb054b5b4df1b09fe9d",
            "464598db419ee6be248dbc211771f3c280d69a4bb28b8c5bb75e5dee96119b77",
            "4667e2b42bda7cfeeb8df6c253481519d30520d7e8168d3f13f99e3bfdcc5e6d",
            "468072e36a3283d28fabb2b1cc0503d1c4a516e69a3ea5e72621426e0e7e599e",
            "46f50097b8c3250eec88237b02bbd405cf6500175f3e46968ba8baff142a10fb",
            "47326a0aa2316c86009f9bc06cf21309d1b49f20445f2b59049edb4f27e2bdad",
            "474f4b2fc7d844adf3db0da39670a5bc87d65cb201ad8f1b629ea86296291f7b",
            "4776ee6cc9f35d8ce8da156f22fc5081af924bced1ff8840850e37dded5b9cd7",
            "4799627bfdb26c89e7897ea3e2118865989bcd9392ae4a2f736dfbe67827c932",
            "479a3514e53cfb969823ebf3863148c7aecbd228d3b6853adf26a84786d5d5b1",
            "47a1611eff973b0a4535a0e501c6592caaf9095294a2754dc1c32aeb82c859d9",
            "47bd5110945a8dffb6318d7c1e586dd50583f245fcea0b90044748125e6f8a3a",
            "47e32efe1cff2cf99aba6601c203a1f59f14298d669c0bfb6caa4f5864d2f42c",
            "47e6058308ef48152f3be251693e72e8138080df6e656854ccde6a4c96779cac",
            "480f66058c74027b756f809b248732f4fc91e1820e3aebfe4372e9238512da1a",
            "48646d96e9766e80140342649fbf842b033afdc0a27c23a37ca4c024e3291439",
            "4873b1faf987270876e53150960f76f89438f30b88af5177cffaccf057fa9407",
            "488209d793dffb14448db410568896e3123d94e292f7d834cbf7446e438a701a",
            "489ec939393fb312a7d35f80e0d3049449f9fa7bbb7e28c42f5495a6b049d7c5",
            "48bbae568cd1a6754aae020c401c25c96f9d9bc2ca0c511482b6d3587ecf060f",
            "48c78d8737446b9245560f2cd29ae7a04a33b0852fa52265166517c30076f6fb",
            "48dbbb434b27aef04a2d4ff4884b83db69d599c6c33d58eb329cf5db80bfbbc2",
            "49274cbc004c6aca76931c91cfc1201e6c1aba16e95baa3ed20f5104a75c4180",
            "49282e6e0844c8fb8e078c31b5d202b381667ef3114a92a5c85d91f7071f54c8",
            "4945db33b79d8db2d74effd04f04bbd58f2772a535f3230491625332b7405bb0",
            "49c6d398843cbd4252d43f2a4a54261cbd1dabd1da04b9b6ac24574ecd32a745",
            "49cefa3e1cfb375452188bfcd105509b30f96af39f1889980ccd4dccead19b0f",
            "49d0c609a769cbc88d40d103cda4b2ef1e9c854107e19fbd06bc31532e443260",
            "49d2d869b5c195f14a204c8bf15e73e0ab426cf79cf8721fba8ad3ce39007dad",
            "49dc93866ac3c340cf482c8e2748bcf730afc00d45807417b58062205b377db5",
            "49febe0347e55e615ed0222ac6a9d4ab263aa98d07879b91f539e6e2164b2a98",
            "4a1f0aaa51b4f01caa65f513ae9caf0a13f928c0070e38ccc9a354780a9ea971",
            "4a5438953bbac27557d1d0ff9d282465dd9c5cdc76667169c412e03d9e04205a",
            "4a9211c07446bd97015254faf71812fb67e0c5ed8f5da89d0638ac59dffa5287",
            "4aa2899d85d02e39c6c21f471f2bedef7bf007dd89b80b445145cf2b480d382d",
            "4ac30c5dcaca2df5d17dff25d87f86e13bfe565d31b1896fd7f79fb3bf085585",
            "4b06bd54ba2f097842d7849d9f63552d81546514f1ed134a6c8350cae30f9b08",
            "4b1afc344fadab6eaf73314142415a0ce8228269d6ed868aeb985749bbaa2920",
            "4b265b6d0046803bfd866882cf8257fcc3113ecd80f64367edfc6b91fa918d3b",
            "4b3437ee87d49094edce5498e91164871907de98cbb19e9ff310a05e09b7a507",
            "4b465d946d063a79e1e26cc7b33f89bad00d1a1f9eb57127ec6ce8e9c23da95d",
            "4b489b69ecc1ac8769d9039469bd49f339b411f3fe94d5113a17108f6d203be3",
            "4bc38c72340a9b89107dd5cef69263e2d2cef8afd7b2dfc90a03b806eaa99715",
            "4c79a2a7befa8d2a39611a71e2e10f44f60c6ef5185a1509a793222088eba44d",
            "4c97e3139e592816560cf6d1335db5e425e182185eda97b564d98ca6b369148c",
            "4cd00cb69e9588acfd9ccd1645c5ae0f1542ff17a5f19d43f1f9055e5cd26242",
            "4cd65fd776aa40367f9ee9bc2f265600edd84dafdd5e6371d0fd5697e04bba12",
            "4d7e2fc75b019450a1163b648aec5e39fcdb796114dded7186080f1846a5edae",
            "4d89d0db1eb46984e3626192ef095b8b1e87bcdb22debd0f56330d02b9b99b93",
            "4dbe19de2557021ec9cc9ac69d591af248f850b79b7999c1f2dd56f42222cd59",
            "4e0a4e45fc0f865f16589a34a92425737af7850a330b3366b3158494bb556e96",
            "4e329c552c2be7f3970453b91a6ee0f80da306e7960e40ef2547781b522be1c2",
            "4e3ebe9ead5943720dfdee670e56b06ef2c94e4bfd09759b87e3e4abdddf00fa",
            "4e5b8ddb567d96d9cedc646fd8a0dcef8a4219daf4ef91c9782e234f4994b64b",
            "4e5e9ed78ae52cff1879efbb8bdcf01df9008ebbd365a38706975884509b3514",
            "4e7409477bae463bb4fa9881a63033a257b57d74e0d0aadeefae1e4905a5082e",
            "4ea55a42496d03d9a5ee6404c43616cc3edf33745e17b8468309ed9a138fd8f8",
            "4ebc4a5bd7dda047f3e9925c8cf4f02c71f76f3031bdffcf6e3983dfac659c18",
            "4f04b7ef300912e01309a07bb82b928143f551a556a50d564b23bb188ce039ed",
            "4f2ed2f984b280dee43b537135b0735e20b8dd2737e12393c5ed1bc999306da6",
            "4f868aea03c914574d66f300f1c378ca531efc59931dabccdc2ab9f9bd64709f",
            "4fde3e2030e2f2d3304559ff508776ad324227748e94196417390269663ceea9",
            "501c2b8d85f5285d69cff3158c2b873db464422f94cd36a7c6019b95e943a5f2",
            "50390ad46b62313133c2eba091c1990778b94f96ba908483efe2f8102bf1e66f",
            "5053805cfc023dc255472465f35292d5e50776d0fded3457ff3d69541a97fd0f",
            "508b6ba8a101c009ccb4660797b30d6e2a333acc1dc6aed8e7c557d62b954c90",
            "50d5aa32331e9b191fabc8b147d86c04798a5b9fc20c7c0e2518fa8ba7197cff",
            "51815557b632957cd9bde216c32e6badffa07abb9b13ab830da85aaa70df1b04",
            "51d424036610bb832aea0930182e521a9e31f83193f456d1991d279800af033a",
            "51d77d9c72cd6c687ad5722b4fc98555de0c9be4ce281dda2179e342f28b6856",
            "51df139e2fd20cf1d877d73ced10e0c4ce042bcba417aa91ea9c22d8aab1f952",
            "52687a2f657126239eb4c63339a58c3a31eb3ec7ebfcc5796642e1de4fbdfc77",
            "5281da0ac6bcb77b4ceccb7cc3850f4527df5c991fb82ed66783afac3937fbc6",
            "52f67d01743a52021611bae2e8e91f155f73d23563737a60fc21d8d38164510b",
            "5318803eadba5be0ea56c1cfb8430c069af5cffbc0d0f0de4ffe5ad74dad6c2f",
            "5362494afa2a9b95d76d4f91a1005262a3c931e0763bb9bd1283bceec77b5395",
            "537866cff25b575f37296744a47abbe387ff9c9bb4e9c6ebd4b3d36ab5efa376",
            "539bea3ae3991e0968da7e9616d548ba00745010d161a8f8051b25fbcae5d42c",
            "53a6c607f6d2f560c166c6163f09605db98cf38e536457e7a6d311e45331e0c4",
            "53b0f93387847b23a8d8de7df910bced88a9a649ff5d125b7e2e5f2051fd5b55",
            "53d42224b757dcbd1061f237ef1e736f4a56c617124d4a0e01f0c986b0c86b95",
            "53f55431643ccec88cf8e57b847f376f24f76b41eda83831aeb4fbdeb7fd7d48",
            "542de84392808f9b1ee258bc3671a58505ef284878eca5f803011a45aab09ab9",
            "5454889432ad98871d78c629e995be6e717c7571e47da5dc9fdc9d42e60c4db3",
            "545684342685ccbb09f4dbc3c5e02af51e3384f25add59c7159fe46b89068434",
            "547700a2c7b505f78037abd4e5750d204cbe03df3c08efe07c89c034c7a5922a",
            "5523cd6bdd15b652f9e817f95492385cdae063fb4c7cff2bc2bd69e7a021cb74",
            "5578e698b11a90bd3be9167af763295e38d225e5036906ef1704cc8ec573af3c",
            "559c8fb434c53e704845ddd66b4747d0e2a3ce6dec5b56174f645e09a7caca73",
            "559e026c2144ac04d11cab90488dbeef9df04343a1aaec84bb8b347ffb3842f0",
            "55b8455d77d2e8aa1139822a7ca7a9fa32649f1ecb1ce3f22cb1e893a1ac12cf",
            "55ccd6b4c717d2c5076ae67d35fc9982faef491b0859a65dfdb04e1e4207d573",
            "55cde64c0beab52d174dddd6b89f21b47b761b0fcfb69135f64ef711f4750c99",
            "55cff1bb938c914b1dfb9238baffd1caedefd3a80a162c7f27d8582baa3c92c9",
            "561219b3305fcdee234b89b318ed66dda525bb9389093fb9206258ca2a6d6063",
            "563e55a90b38e650134984a0d02e6cb546b6b0678237f7e0d21dd55f9492c3f6",
            "569c378dc40dfc866cb75d3e992f12d975e0dd9247a53aa4e5d56ce4616c82b3",
            "56a09bb2f7528d562f46b03abc9fbd090f40367144c739bf42703204a16782ac",
            "56f51a879e87d9b1b0a7ec4e4f252b647aec619c825b26466af86eb453c9197f",
            "57181a6f657deb0d0bfc6f3d57e8b4d834eecd824501bfcda8cd9f206c0c212b",
            "571ee529adec3c82d5a44aa2e4015bc44a9fb7aba8819212249776c9b533195c",
            "579ea982bae640f6b87ea36fe622329f5314699f4af4f0edb90e1a21855b0984",
            "582c6a675b20e8ba62c144fff97ed81d5882837a4e5331cc8468ff6429af2660",
            "583f73df10034ae0144f74d91d52a63d52bf5d1eda7bad8a660c4195df6d3aa1",
            "58ffafd7f59fdab431c9424371d034bcd8f6e1b8c5241e4c75026e0a03782e7c",
            "590a9f7799e98a5545cd0c37e29134a78e2026da4ba711c28ee3d648e08ebc85",
            "593c03a406cec439414d9949542b0aa29bf50a5ead0e1fc9ac59f1eb773a62e6",
            "59ac11a76791146102ab64d04e7d22a5d96aa895b8af376f191dfa36542daf61",
            "59b293bbbb1ff481517b71319a2ceef56b8edbc7691dca3f7a647c0105eec01a",
            "59be09edbfc156df78836dfc3ac3ccb49a122c482fe9c05cec4b8c065f9d48bd",
            "59ddc86580990550cf0707985f56f52cce076848f4db232d2678a64de166705b",
            "59e33c726d8ff19c0b5d24a1fddccaec256a3bb0240c004037dbabcb8e82a759",
            "5a50c322d4f22700f7a831528aa138b33aaea3ffdaa0efd42b6c72c7ed08b73f",
            "5a52aae5255a0264cb5f00f5ebbe78ff4017c052cf0b1c47b46f69a99f298d1a",
            "5aa0b069c68c9817e9d7fb889f3243b9087b64bf62fe1b3d4f8b6f8fb75da1fd",
            "5af2c3526eefe5f1746c5086a488223c73b2f5af3bd98f4aa2324ec224ed304a",
            "5bf708bd78c37d0d6403036e0455a075e5249168039d9162b2f96e3fe6201788",
            "5bffa3e7174987a4d3c1c1c4d07512282edcb89239d7b12fe18764a9e1dc9485",
            "5c5b216c61323930b012b5035426ce535b6043f1efddd1b6baa81b570d5a127b",
            "5ce3a032c3f5a0b42b4e92a13ce88d5254ee378f5e44dfeb737ffd4c0bdc28a8",
            "5d0f2142e0339ae83c30084e98ddb3be64c6b913e8e4fe8e56beb9e7f6f46203",
            "5d19037c0ad928a84fb755d363406bb282a4fbb07309210e4d421d5f33f4f0bc",
            "5d4ac4630180757bd6884ef3bad279ca5497fcf5b1059d048901909ffeb6c4b5",
            "5d583c8a23878622756472b60c40761e534138170004a1b682b51fc8d44621b3",
            "5d81fa2c4f1dfad064bb929c9a4ce066a3eed3e4ab1c9481260f4f6e792ee584",
            "5d9312a6c373f3fdb28060117772f3640a4606a8483a4826083ce0ff5df24b53",
            "5dba9937d0217c0de3cf421307868d62d20f2e260ca1a8ac83959683e6fdd1ae",
            "5dbc824d2d18ddace104ecfcc38ed693cbcba581ce4c1c1ec8a4e66382ef9828",
            "5de9331a1beb6e977e8edea1df2fef4e8b770529191f0869473d08bd80704471",
            "5e40bbdbf97991c96f64971aba333b284ad92026fcb06648b3f3b55da54c976b",
            "5ec7fd9e049e30eb68815a414c2a09fb30480ed3d3c2d1733bf59fec3278205d",
            "5ed9a76fdb05be9fbf1e3773d5c6d03e98a9c1f7cd65a65f3a585fec68c0bc14",
            "5f731d6f9fcc09a4b94532eeed795f335214d66b0108b5b6b22a13b318dd92ac",
            "5fa66890f1163b966f952b83b29b06f0fd1c14c55ebf1ed9d8240e88b04e3665",
            "5fe6dd2db64613e795ef82a804e8f688b8415711ad1dd7a4d3738505e235963c",
            "603a8f3c117d0c79d6e29c8572450d284ef29fb51dbdf3e7821a3fefbe4dc02d",
            "60a7fb980e31ddfc0cfc3ce5c00e1ea9f2677fd4d36eee6d33bfb5a91a2abf72",
            "6137d315b365f22505dedf15c3e0737acc99aea3e16e5b368be4b5d15cf8f9e1",
            "619ac4ad2ee23fa42eb3a0eea91a5edc2c301f7c2847cb3817b10221c5ed6b07",
            "61bdefaa28579a36d5408ec8c52e892213f4da654efc768058d7cf8bfed1a345",
            "61daaa27050419cb354586b22dce9fc7eef160b72ec73a577e1e3b6eacbe289d",
            "61e08731af4d03b597d9f86d2c8eac73a688babaac4e00efe04ec6206f74dec4",
            "6236c514f30b230b3daaeb981397f9ddb0c8d01be6310eccee72ec20d22e7ca7",
            "6244ab21757a7995ad3d10d95097c4e2b3261c32726b08654c7d209fe56193ef",
            "62a755c79b40ecffc1d4e9a411a9b84418265c25eaaf097e09dc4cd610e304f9",
            "62b025ea52dfb2248cbe2ed56a90d7853cdd0c2cce140c2bbda76a9b2cfb88c7",
            "62e64138bee51fd91d7836c6af8ace229955604e355225983a83d6446feeb95a",
            "630ea1ad4febe04e1f44500ec7a1c91378ba5cd15051fc9428cfc59eaebaf271",
            "63138ba2860b93bdf3ce372e51eba4947f7560fcc400c0a419acd871e0b90dc2",
            "63d7e0f29f5f2492dc5441cbdde0b931aa00046ac2d8a95397eb53ef57a92347",
            "64444ef7320089df4985535d36db0329539e65defb0b0b6c6ca63002ade94058",
            "6486aaffff25cb00e18369eb73d6816e903e6454263d0dbd8d433477b202b366",
            "64871cfa817182fd1b52af26cee9ac5d82f3162c4ccbac7c52e16a7233289aa5",
            "64bcfb53414274e80a8bc27f4f9a71f9477447a08b1aa15b9391e99b35787acb",
            "64ced3c40b20aaf2ae041be57b63a986e2b8adb66ad722e0b874b916a0bc715f",
            "64dfe480c5dfb2c87ad64c82593784dfcc2d63cd1f88d1c6ecfd1b8501027297",
            "657718f537df9f9682e2a1ec33d320046d58b4e3e2a4fde88e146f7300a1c26e",
            "65b417e419e0b5c677f8909a4c0203f5b010e6ee6f4a7dbad94d771928c8b4d9",
            "65c1122a802647a1c75a19e026644f98b691ddd38f05cf63a97aec9109dd7610",
            "65efa4f14579265d9c20f0efcd2c5d3ddbedbf9b7ec15c5236080aaa0dbe375d",
            "66103c66e75785075526d127dbd76069b1396a72144229457292f9227c72be10",
            "661cc0775b10474b3844d8e2849db1567c3c3de0a07bad0cd7405e389db92eef",
            "66629b16dd408120fa5ab9f1d6a75f78eba5fdeda7e77d06cec5af45738dd6e9",
            "667661eed4776fd3634714a52d6737d4352e7e8442825d7bfe7eba6ef0eb3da6",
            "676a0fbbdd708342ae5775577d452f7884a06843aa75a9ee1f34a001fcbcb835",
            "67bb749e47bac0784ff1febfb42b64dcd8c49b0de9236acaff82ebc44ac3a795",
            "67fb044e0853b10dd20b53c36c1a77441c78f30dfbed7856a92b125228982c76",
            "67feb2f0cb53ba23e0669246179d93c46e7891bb8dd36d7368b829e2b26dc4c0",
            "6813848e2d97d1184be4dc8dbe9c93bda379c71136dfc7c27ebf6036fc99c167",
            "689830bfbbe59d9efff6284d284f17a0c73c686101b3f27af2f0e3cc7cd0151b",
            "68d53eff4bd206186ca96345963c78fac414fc1f4ffd9f2ff52df0d867d5e792",
            "693394e3ed12c1bee7ae1da5e067b82c6cc89b35f75f7893e80d1b67530da3ef",
            "6936414deeb54964c9e85eba5d94a4fc8154bafc45c4a32207c534a1c8fd0cdf",
            "69364da7d444c008bfbcc1fa3694a2c502a92bc6589dba108ec4364cb1b02021",
            "6955ec9eba107c961e89dbbb4de070756831f31df7899bd090502fe8cb8731bd",
            "6991ba42da6e04214984aa59eb0445605a898a4e95cff84720135c583ddb0bd2",
            "69b482ad36d16da444318fe75b8209f13b37f58261fd9cf561a9d179b3cf6f30",
            "69d3209b8a9d1902c4ea7273249487a58b2d374c4e3fb89f289e3560a205f1f3",
            "69e11055554c35eb5721d19b1ae04c572abaccd0ead945a60999927858f55cf2",
            "69e83eca0a35de1d3499d494d194cabdcdb8454e3638051404623f547e4fd48d",
            "69fe05683bebce1f44bf2a8b34868c2aa053a9573830f931260e692315302837",
            "6a0bb23422df7c16e94ee5ad02c60fefff9c8fdfb34219683807a05cc8fda333",
            "6a58f04e9a818e88ed29c59997ffbd57d58491d9e179105229e8b73fe2e445e1",
            "6a7afba2c7150e2eb349a386d240a97b91158af10a93808b2c9182404f8a1146",
            "6ab1181a4b1bfa9efdc20607b519d4e612c2a90f759f56a72a86b1fa237defc7",
            "6ab44403007aa2adf5eabce44c0e165f96e84d1be6bc93896622ce643889121a",
            "6ab8050274a8c3583400527fce8c7d36078a02aa705768efe1444b965448e293",
            "6adf57eebcc7a37d4e31510ed7fd6ba6b371b20178d8180f0944e7f5ef82b578",
            "6b0c1ba7b3c1ccdb7ef4ed7e20bd16f4fe4794abd8ec7b2e51cc124715f79930",
            "6b2a156c1e71a17b2f81ab7b056a39d168354feb3e3bb75547d01de0a8172899",
            "6bc51b5228f91f463023a69a091cbe58a04b1fb6a3b6165157a652e004e9091d",
            "6c0f593a793598070c45735c72fcd6d44e4fb8b657977f9f7f5d52b0f122163c",
            "6c1a32d9789008f7e67c6b1266ad5e5e463a67adf65fc15566b69f74e16d5e62",
            "6c50913828cf7bfc65e6974b91d6e3cbba919267416a1d9e2922d3951b26117c",
            "6c7509df07388ba2fa6c4437b1e64adc8ebfee12cf45dda003484bc0f48a0d25",
            "6c8d95edfc3a0046145ff5e3db67153e033513144b9b187fd1bf88eac7cd7bed",
            "6c95e6d2aecaccbb52e14fae736c39ff37541809dbc04c99330ae4d58fa333f8",
            "6c9b51fd08edd226b7610cfed0335cc5e639fa66c64cf65706eadb351c4cd7b4",
            "6cbbd4360bd814c321da0c275f888ff9b985e35fc73d2968c2543e35087ab2e2",
            "6cf9f2cd0277dd6983be9fdf640cc3bf627f1eba3ed59c767b07fbed79399c14",
            "6d0f1e794137b1f761c35017e4d9a7ffba5911c244e517e79a1ef6976f939f51",
            "6d2ca60e4c32ae1ab3591f834d6c5031f92cd02fdbc43de55135a6c7feea1a5a",
            "6d8b39ca3e0a4fb8d83f06d15ce0c4e168d677aa3c0228b893bef3687086212d",
            "6dd4fead8db35df7e40d08988b17fda15382cf1bc5c3dd7185823e9c1358b153",
            "6de3319d4ceb22fefd68cb5c20feeee29a8cbd16ad57521699bb897d75c7dbe3",
            "6e3db8d6a5b629a456ecf6b2bedde7d76c2575c283b87b9cc8ad6c22959249d6",
            "6e8749ac5419f006e933980d60361e059b3df0712552a5fb3db8ebd261295078",
            "6e9030f3b049f9bc996297df2a142154d034335025b995c7ac1b01346a18db90",
            "6e9e85281f4c0c309275faa8e92f98a1b7b4262c74a5468ca9c0782709c8d304",
            "6ed67870b1723a3850fc456e59a98d84ebc045f2f05b5032d84255427f154cbc",
            "6efdb7922859aefa4a9d2a22487d566354c1efbc7618be3d4164ae7b3f181c33",
            "6f5ce64ee3e7490ff28b936ec9ab4b479996644fbd0793d679e390fba097f8b9",
            "6faf91ba34fd5b6ac363404b2029e5af4225ff69200356bf91352d6fc74987b7",
            "6fc7b21b9278c70074da87786ea8c32a1f9db9ab01c1647d823994e7f70f2c84",
            "6fd98e602a95116b715d183e4fd27f338e8b018c528b61f140184b8bcacf22eb",
            "6ff8e0d110cbc9a927f288f10f4da879d9cb92dbe07a04aaf488b34b90012242",
            "6ffd9a912261e19941b46204207ab65f56c0db0808455574a789a1fe641ca194",
            "6fff8080b4bac9060a4f6f69cc4f7a192289b6b4e6ecdbfb42952d8aa061260c",
            "700c12e390dbd2b93022b36f6872d99b53d47fd2a36e98a4d739d51ddb78ad33",
            "7027b467ad39fd98ac773aa29e244e335a15c3ff49f57e814f056939f4a12430",
            "7037a4c1084cee2fdbf58cfc834c7f21a33fdf06679a7ca41bab2c6a45594322",
            "70875ce9083c34665d80f07301519249f4261cbb2ab42732bc3441ba71c5bd96",
            "70ce0e85ec771175e553f6c99cff5fcbb41e5bb17707274abc96e0f309121700",
            "70e6f9026a85c87be7265e1f064fe9f41b71c7f6da72366eef99529035405c47",
            "71243bd92c4bb545208af8934023834004aad8d029bd6b3abaf0e5a2b6958e9d",
            "712f44dba02212dbc1b1cbaa7df0200868b386ee9ec952f79a5bfe238491596f",
            "717dfb4829da3c84787586d5745f33d5a3e4ae121f4783a006fe32b44afd2082",
            "71aa0fa1a4a808ec3298e32516a16139dfb25c578e69834f4224ed8ded0e6efb",
            "71cbd82dc9601d89de93fc693fcd9e9bb1ddfcc5e60ca7c685c2e158d10e4e80",
            "725b700d236550b5eb9f6419b08669c235177a7a5ba658046a9e24780430c6a6",
            "7272ca6c2191f68a40094b10baaad7631efa58d68575a17a1be9cd449a96c2d4",
            "727ca36f192eadf73d002516c7c0ac8d6b772482cbc73e915e375fb00702c453",
            "7293f85eb3965b4470bed077cf4dd93b48efc5ad40efc908d2c49fe58d9523d7",
            "732844d209c730165c45029d497e516a262dcd504efd8da170b8eee8b023c92b",
            "73501406abe7bd24cfa8fb09754a0a92712dae66694e02ff9033b0ff24757077",
            "738bab9352051f9dcf2e0987882c7c8e5189678b5d8eed20bdd767512606d2f1",
            "739f5a832426ff8b61bc8d85cbefb5154823ab4aea2f48036897475ebc87c9e5",
            "7463f568ba962bf83e2dac519adc5753dde477fb984dc2fcecd4c3ac2ece91dc",
            "746704cd7e3f077ac3ac1d510bf66cabb5df781a8ec488fec79fde440e0a6ad1",
            "7470dee2a42ecdfcb4969bad239d12b3d3ceb56adf9c874d15de7e4601b9e376",
            "74954c69745ff42aca25b4acbd20c5092b8ae0270d0039c2ba58962d481e2883",
            "74ba036c8a55152e57cc27544fb137a6ec214aa3f4e87ce73c90d1608d944766",
            "74c978f347a04a37ad8a4a4a9f5f62cbfbaa33af83087bbf9e8586e59f53d750",
            "74dba80e721a48f3c482bafa48fc6cec24551a6d5516681430b085b25aed6bcf",
            "74e1d30df918b2fbc86e92a6876872e071f42a9b6042ebebd2b987e0a7c3100d",
            "75153935ceddb10d278752bb404f1aaeeed7578592d1cc5055891909e66baced",
            "751e0ad22b39004e9e5fff9a6e062e66252932d4337c0b6dedea9f37efcefbf7",
            "7526f57f4ec57d058137679494126bf8c3b5bd3cfff90d9a005ef4c53516ed65",
            "756f0aef31019346f755906c99e02e30ac21e2968147a4a90ea2734637f60ba7",
            "758e84eca187d14c25f3c19b3925c34d3635daaacf664ad661b374bfc3ec5103",
            "759c629eec3edf71bc46f8f208a2af4f4164bcc7d0bacd35bc925ccfaa5c3b4c",
            "75f9250f1443089e1872ce3360de7eac170844f813198943c2241082b3ecf919",
            "7633a1900d312085883d014dc31849bc2df8c2aae109e5f12122840688a4e52e",
            "768875e65c9cec35610f48d913fff3de6d3d19214b2191db1b413b286b4aac17",
            "76aaf675a14d6332bd02ea7d23af19582be085e1bf92501ad0cd65366d39b966",
            "76fb09a7814c7f48bc3f0eb916364ce1af2db68f38ae92d925d377469520deb3",
            "77481128976fc605c0de1203ec2faea389e7f6a64927981349e1dae9c7533f07",
            "775b765f7bcd3c3a483a2dbd3fe21a5c7647bc67f662cad843c02bd244629e09",
            "775f038682cf010b1260d02e78c03e6c392ed451883608bf585c54cf0becfcb3",
            "7792c22eb11de3d643b0939c9a7e14114b177045b11a9ff662e3514fab182fda",
            "77d05fefe62c756e1e87893669569966afba30ac709f386601e9faf3672be8f7",
            "77d4fe7bbf086b9f3935b9ca121343a3e56a5470c506bf1e90508771a6fba8b6",
            "77df2de50cfb939e21a64e797420abc41cd388537ec08090ab2b2ee9171fa936",
            "7813c79c4541c51bcc90799095ba4bb449d69041f2cca598b9d957fc4cb30fab",
            "782c81f69004c92854a3620cb674076f3824cde2c5a48bde441e9af00b01d371",
            "78dc4af78b3f4aee641fc59fe7049320d72c4f5b600e817974e7d887e4d62c38",
            "78f281854abbc2cbbfe7db7e398159f8281942b437575a565706e9a85ff3aac2",
            "790291c97e7423a72aa49c99f7476fa5712ea1a52010c195cd1dbddd68510e46",
            "798a90a0194eeccbfe6fe39736fb90cb2d8fba79e019d8b5b18110bd42a948db",
            "7994f0d07dbeb274ffde6ae493cca07bfae0307bf2d1e23c5e5593fab8cb89a1",
            "7a283336f0c5425e32ebe6376633c556d74441c4fd15c0189591a63fef4a0c8a",
            "7a2bb6fd16729ad2ee72b819752b985886b0441efcf110b3dcaa42e91ec6c4fa",
            "7a35fb0aef6f2b2d072b8079967e2b92186c85615bffd517d0c581f8f330efb1",
            "7a367af224b692dc7a6784afbf56560b8d40977d7b3e774aa445c08efd402972",
            "7a3a057e80b5f1ce7aeccc9063d39cf408c7f3aea8ca0996f3e1b2150cb0977c",
            "7a4c5a4050a30e1d74a31aefd27bad29f8845eacb95fbf373d3ae4c1fdbdc260",
            "7a9da5a239fa7fda4834adbe3d7b2ad3e7a1ecb2bf830b5714a0e1f826d7737e",
            "7ab9c74c7bc525571b27122d547bede3c25ebc3aabc453407b59fa3f6e66cc56",
            "7ac624e1355e74373cac9af5c9372710ec265475ad058852eeac677cc792ce25",
            "7b11c019d62013fe3b0267e886dc21d2f3a6e92d263d774d86c88f7cc6b74824",
            "7b4742d473f32cf47ce442d3e6d5b44057a0d81a9df4903769c583b4b13e6598",
            "7bc6c041a80c654dbf01dfc7071c07f4ef948e4402d7f3ca16bbc67dbed087e5",
            "7bd8ba609c055463e86b18c4f929eacaeadfb9bff209502cd7594b3be82e2683",
            "7be32c61ddf19d87dd6b02746737991f6fd74c21fd5f797b38b0029e13ba69af",
            "7c5514fb93790161f8b286aa4ceeaa859220c9ff2112177f933af7d9e95bf7c9",
            "7c7e51e220ef7f6baf84c8191cb4650d4e2b44248493c24153ef041d08e00ccf",
            "7d30f812bced65f1bdea4b192ba59fba7e24ba3b1195bc4e6fa88e1386f35a71",
            "7d3ebabc1b159928be79452f97cba02fb57a167bf19b50e605cb2218080d337b",
            "7d7484d302afa5caea60fc275ded0d8f8735e1bd4402cb712d119d51f8dbec44",
            "7d84cf9ba9e4cd135ce9dbbad503f89025000f55908ed00fa27429a0de79e9c0",
            "7da0943246c66f3019dba70a9c52a80cd481a82ecf04b5cf7a64649b930d5954",
            "7e14c5af196c890e7f3f337a503e0a27dfc44a94f26b682ce2ee4fe3e109d5a6",
            "7e6e7cf0ce1a3804286efe33a4069689df5647bfa74f8089ac43edf16070a028",
            "7f3d1095c6b2d38293383f5e831243019efb994c5e3261f8787a50745808898a",
            "7f863f3df8036bfa05a106544e849c1f8ecbf9c2f5cffe5b21546c012e316ea7",
            "7fd224ed470cc7f3a2c1bbe4edc418f6683819b203cc8cc4c9a4ded773df8ead",
            "8009be550ce9492d25923c66a79b6745ae984e5a32f2958b0d070e51ceaf61e1",
            "8026f1857c242ed65bc0e68cb575ef18ee7010f9d4ba8c2c3fcb6b665c034a84",
            "808a8484a8bf751cb847e29f5f902a8d345b41864db446724380bbbbebfbc6f8",
            "80a34b3e07b018f6c84ba8bbc64aace47480050a0ac7ccffa974f6742545f16e",
            "80b9449ccdc37506d0ff3686b66c679022138772083951ad0f3d22ac18f719c8",
            "821d4d1d523ab38c68cab7ab35c17c3afbccd73a53bfa54ae9f059aed8810f6e",
            "8237ea72e6973f3745d0a8ac6a3587700f21f983da5d2a941049792994c03c2d",
            "823ed6c5bfb56afbc92310efc94aeb1e31cce835a155800315cb75684562b543",
            "82e6fe58ceb5486fcdeaa6509432f5824d834e36cb732fe8dac8c4a132cbe58f",
            "82e796eb32eb414ac6096638cd031d9df4ec8029853a2b2826c9d2a0eba3a8b3",
            "831d398ba09933d1831440a1dad488d0cd98f89f287e84f1cf9d7d984fc17441",
            "83423914bcff67a6e8248cb905bbecd0a84081ff4a3b83ed3df9fe3dafd3e710",
            "83ee422007cbc5e26e093f175b3c50c271fce515b521b75677672e039391ab1c",
            "84124eace0f5d426343caeb7aa302fdab5f57f1ac19e3f70196b0fe57368f3a7",
            "848426619ab51d892cbcb9337d86db0fc69ade44eef41069efb0f05666157a69",
            "85188ed37376032246e8a6d2c04736fab352d81e5e12db88c9beb001a23c8d04",
            "854efbdc2f6374f90ba0ad67373536c106cc6812c196b90a38f44933835a7f27",
            "85611a70b18a721e3a953dd25201034af61a0da9b06c23d1634023db94e442b4",
            "85ffe82b6d9b99046ef9b7d88e252f4ef6179f497ff0752fac8adde7dc03f350",
            "863b46858708bd6abefb8e791d55f338214b65c9504efc8b80b1a42f072fb6d5",
            "869e3ae346301f556b541aac572f0c2c2acf056ba3095f20ffc6d364cc6865bd",
            "86abc68f01c84ea15e4af1830df64c56135a2898126ea5caeaaf76312dffa20d",
            "86ea7ea375de84a1d94c0e24ad360789c21c132b91dbbf5312e521bd640e7526",
            "875b2f384fd1bfb395fa16a83b746d77d7bba7d305064f505572fb1f83f7c8ad",
            "875d1dac8631d383e4507e5372da76bdc9f8b0242b29e3624daf7c0c50932726",
            "87c0245563b7e7369a1065a0374f36530e6a45d6e0beb62bc2925bd5a62caaa5",
            "8882373c9a7d2ba67424b6aa829a19a8dc59438dfe0ce51b9269ef41f82c8279",
            "88b60d3580468ddaadda9d98fad779a7c5a6ee9a5b6e2f3b5964c6ee3ed11f01",
            "88bce6da4bdfc078438383f93c6a134f835497e37623345c24fe83c4bcf3d6e5",
            "89079d8eadeff49a1b6d8eb8411b5d3a2d5c34a45c3d86a66ed857838e2c80b7",
            "898db00b7653c6e46362551ce20e1db0495fe61978e55e988250b22790afad6f",
            "89a8b5700332ffb03230d9dc62f5e476d512bc438502e1793473292791f26c0e",
            "89bc733d19745dc42918399b3c3927df09d4347a6fb0fafbaf9e0baea677024d",
            "89f8f8d22e0b201e901f29cc488c5073526d59ac36ba402a5d31832291d89f99",
            "8a557c3ab136a149aeb7af337602e4746e3f7b8e423890956460f8cc564de698",
            "8ad9d75e816405510eef5f088c3292343936c603aa96e7b0e0cb363c6f126ecb",
            "8b0abe62d416b1e96ac57fd7fe113879ab928ec7dd56d9c608cbeb94e3cd775c",
            "8b8f30b5b30c4efcb1732f63d35f12c70dee28eb7c357f845a42e42a00a98bc3",
            "8b9024bb152e676da91278d338a2b246acca83533745e468c53f2799fcc321ec",
            "8c6a132ae9f029a7aa72c10b8f0f39fe226ea9a00aae7d01cb46b198325bce9a",
            "8c770489256eeb1735b1c4fbe0a9bb56eb82058de847e950793e1e156ec0fffb",
            "8c8fd56c632e965bce128b4d3c6a7ed00f4bf2eaf200f0aa9fef6adfa46e65dd",
            "8ca8e2d0d2a9a58daa2be3920a2be2ca92616673c6df96da5f15801e4c3ee2a7",
            "8d636dd8982f7d3880414fbe81a7c8ca3a67b76b713dea53ce4e92422fe4095e",
            "8d8cf1400dda36b7f0e4b469071e1075fa2675ed69096562cc07f35a9ee8da03",
            "8deeaeb655fb15265927e63462d9221d22597d39fc4fb06fe6f3d3cba4c81966",
            "8e739db99dc095744e8796da908b73006bf4dde668524b2e7a4440ae9b331eb7",
            "8eab194dfed681582089abe8c4fe2a1b8dd224cf1e5a2a55ddcd6db473641feb",
            "8eb88c325504185316f70b9d8d2a0249f0d3b79483c863bd3d4e55e4013c21cc",
            "8ee9871f9e8ce0b68f0f2114947694aede74b53de9f4873524c40fca7e841b58",
            "8f5c51050fc06a03edc7720db53d1af20334be8c34eef8f407bba31c363d1eb5",
            "8f6935efa3beca6f580179ca815153f796697075b7d917e35daa08ce8718e9ab",
            "900baf29f5d5b0cca2e6ce09fd6cf0dba2aedb10d9eea8b9fe208b5a7ef6407d",
            "902cc3f63655773ef4da042b95cf833aa0822124cf999658fddc11585e8a8091",
            "90af023a6b6c894abde1f2f24b3e02a4796fd2b68c570e58da95a563aca382f7",
            "90e3303b37b6d58a59216550774621115881c27cf79168fe01a8c6605d5bfa4c",
            "913572b5db0d4b35d630d779a614900274685ca560269575021c93a9945cf269",
            "9160ead20db088a449b222fcc0eb8d6798eef3a9b967db567c2929078975afa1",
            "91aa0884bfc58fd6b3b582dcd6cd968ac10cf6e44edbd6f70b8d3a5b61c743a6",
            "91d4991913dac0254b9089b82fa0d3e5929d5f35ec68b466378ae21d71f14cfb",
            "92135dacd6ebc41d596ea1f74829ecdf17695d47eb92f55014ae6a28165d2f80",
            "92320a91220a9e85bbd0388c81f982416b2f6da066e4772660d79b6f4207bc1e",
            "9237b1811b5307b6e82771fcdbb889554121ee4fb4e258bcf3feb252933eb8c5",
            "9244e467ff653caefee87964dbe1adb02ffe24508b76a867cff94c7aa7f679c6",
            "92c847f096b918014b9e4afa408fe6081fa2cacb6a283e2d3d17228713842016",
            "92cbb475dc8ed9c8265e24c4c4e8e761ad72169895a4d8700a06ab462a54bd1f",
            "93286e41ab5ba4a26f1d4b89b7c51da8926777f59584b5d1f4a04ef82cee0979",
            "935796b352363bfd9711c44abf0f023ce2a6bc6ddf92c777cc79366fe7ee02d4",
            "939d62272a5206411efb691cc28e618b5ee828499ad78a2fa72f6591d91bd27b",
            "93b71aa544b331877b349c67323dcd2122483897a467d907600d56d64440c37d",
            "944815c557fb9f81369e2eb75c85efcd8c39fc3d8d530fb60a6fbb82eef3305c",
            "945e3679e632fe560f1eb9426cd789e930257d41869fbad249f1b1e476363001",
            "94d3efea15478bb39dbb96c682f0b3253f58389f16c24ebc9c626ea62defca7a",
            "94e2410a4d3462b02daa5ae2ba85959da2f2e662c467eca6d8487706ef808cb6",
            "95154c70fe62f24b8d8755f57253c90978e887634dbd07e04ffd0ea8c7cb11b6",
            "966478ccfd35f8a330d85fd6bf241d21ca60c263a749f6e0e033d386e9d72602",
            "969bb84c1a0b31098cc82467ffea6588cf030e2450fea0a01bb73475be0e515c",
            "96e351235a4dc724c2258ecde641b92023d78832cbc5779430f6858fdee49ad1",
            "96ffce33b1da21168c1197a24a2e1590785c49e548f8b531af5237061096806c",
            "975d265d12aa5af0c04fb4f74ffcb62c426add5e0161c437b451a4ffc07a27bb",
            "978b211960eb0795c57c82116f9783cd44c8df1267915be6a540ee0a6701ce08",
            "97d9895d999015645eecb351118914813537d012b4ecc78c2ccf399a6c810290",
            "97ddd12fe91cbff827cc8b78965b9bc7754b6d8f022e83dca25426e44395ba1b",
            "98013750b45c7f25f465806a0a9003495f13d223002dbd7d6fc4d5a0b909d115",
            "9803e989fabe219ab8aa5dbb7e33d41c47cb8d8749c22982c61c756620337e85",
            "9836c2bfc178c48740e2d3496e38a4c9d3c60a09d1e533d429d28c2dbcb20acf",
            "98914d8a8c2fe92cf1e81c3beb2a629eda90eab337978922657927a51be04cc2",
            "98c1dd8bb3ec0dec98f4fbae43d09163c0e8c6e6c21660d7f52106cae3ee4bef",
            "98ff83aeed938fe9fba43c25680230f7964084a8a725454943e6ad564929dcef",
            "99560399ec7ccbadda25e7a1159192a2a812ffbd853fa65881520e1d202cccb6",
            "9959e6f342e6b06c887a5de78c4996fc84afc9e3de490925fbabd95546e7bd39",
            "99b8bdfc4dc6c43059d1b7e6484c9f32d6aa6bb7ba9ad93ec73ec5ac5893e474",
            "99cd559307ea6da4983841a855e042016d9593b2d930e0aa2f1b3a8002d12cef",
            "9a114d6483cbbc20f88b91b80f6d97cca663ff6989f616a24b38f7b8e21f4ef9",
            "9a35796b397db02a563d99cd699e56f55f6ab69e7c3bbef1a6ed5d71e738ab13",
            "9a44a9cddeef01e2ad1361553608b78e489fed67ce67f8400a95453c1f41a526",
            "9a6da8ede33ccef777a95414cc61c8a438a2be9e902bac797ddd17581891ca8a",
            "9acbbec153ed9c66a1d0c40786da6f308533c498a82e191d8197192752280e22",
            "9bb0f0e653ef9cf76a4aabc09ee12f240cab9615d76820b5f766717a469f6c94",
            "9be3cf75dc9e16f8616b26d6fa38b6b755b49cbd663edb087aaa7442eb0db9dd",
            "9beebc318b1612ef2aaa55510eb26eba8a96264a62c834ab5f4178bf21e308a4",
            "9c34010de1f8e4ea5a24879e6d9359a4b1ad203807e8831a9645a379939d4c24",
            "9c8260fbb2707998faf5661350e3c41fc915b33cac6d07f028ae057c3481e27b",
            "9cbee059375d4561449e14376e0d015fcc76e63a45024b112f00c8c570a4f4d5",
            "9ce7e742f8db2803bced9f2a51ab37acfb47d398afe22345a7d94e5205cc4dbb",
            "9cf2eae2e302461144e310783c25853c95416e3d0d1b5a4d54e6da5c99d94a8f",
            "9d1c4a0abb5f1ef29fc7968526e7f05554aafd514acde20903b1f600c3bebb1f",
            "9d5dfe5b719ef650948819f68c1d67aadcdb80caaa634222a13166dc5b26744e",
            "9d804a96345edd555ccc3644575b985d52a4fb75989b02cbe70f47d84ffcdb2d",
            "9d81a951e574ca81721e8ee12afcbd17083afe5be8b20fca0a21a152c66a716d",
            "9daab3bedaff83ad24bebd58ac5d791e59b09ae7a916f012c6144a2b684834e4",
            "9db61fd1b5fad9e611cfd012486f758df2212505440d58efa6022df00a8431af",
            "9dce9c694ba10b63deceaf262adf76701206c3d3f4b77246628d021c9717cb5e",
            "9e03f7cc44688c07fe0178e4901d964f8de92b9a3f5c1e163f36b38808a3e176",
            "9e4a8f09fa1a4348fec3ee315f5b6dcf0c4fccde351f9e0458ceb5102419c2cb",
            "9ea37b36d633d87979267b6746c67f6fdcfb36044715adcbecddbacf372b2f9d",
            "9eecf1f99109f38b75e88c3cad1afb0909937dde40de647d19eece4003f67744",
            "9eedbcd1c03189ade63f6d9a382602b64201e7f43d4085918d87fb3d0427834c",
            "9f122a931c7244f3de4fa09b1f8bd293144ff29b60be3712fff2d65f6175fddd",
            "9f6591c7af91295f2a55da053c924d1db54b2bd4219537ed6a86917a196bb449",
            "a0381a59b709a187806cc9eb36b0ee83faf749f045207c9f7098e388706d4130",
            "a04ffa7bbaa47e56955fea2d31a8f1e7c5e37fa5ed7c7485eebdcf38d6ef222d",
            "a067582bd8c44bd737bffcd30bae66728ccd2523c21ef4f42da91750912bc214",
            "a0a7fcb6a79f72eae0946790e502807bc897ad12f0023be58a958ccdc18a2104",
            "a100ea955bd940b32556914256e879d08ef47ee648a71871b7c3cea180f113bf",
            "a1081a0d83ab9e1e054314ad2c6e0d8a3a3d552c1527baabe2adaef7b368902f",
            "a120aaae6bda3c484c387d540c89c270e82d1b635457546d3d2f0bf7ec21b325",
            "a12692308420170729af7afa800b6122a68edf40c4e2eed423db4a08a3ea1a05",
            "a12e637ce6f678861bfe71b7718b531a8bd54f4f5d7dabe735469c550ad216e8",
            "a18bb455f2b84fbe901bedd821989a1ec47ecd3ac21247a7bc599a7cb8a7ba5b",
            "a19c55d138aabdf62d52bd8bd9900266c1cc5af293b8285717c9c33b2a8231e6",
            "a1be3b52a1e60caece6daaa289db1e2fd338456cd28eac178a22f532d62e7486",
            "a2850182b48bd78d02fab400d835786a3de2b1e172dca13f96087011e27ea71a",
            "a2af391125761f151bb68e03ad4d98ad5affacc4d34f26ec3a203628889d4f3b",
            "a3215b676f5e128710c8ff769ac7279ae666da77ddeca4223b232f6bad0e2473",
            "a356a96fff1df9b625098ec9961ff666eca6b6ade3dd8b4559fcaa962b1510d3",
            "a37f41b296142a1ec388e12724786af53347848e0b251c318a7c3f343e98c2f1",
            "a3bbb27911a6193f6c246791c5f1f18e89986de6a74b6940c8677e2922fd1ef1",
            "a3fdeb177bbadf53ff675c3ac47dd2ee266867dcae3a4ca311afed3b56827543",
            "a456c3a1e26470e8b26ae0c9121e49e7693e559e07495a242a7903fb3a750db4",
            "a4896d539cf713af0f7e5fca2b4721b23d5815ce0b0ed14f1c58381bec99e5bd",
            "a4d44260a0c8d8f0a43c581139ab7d38b92d3823540ac82aad803ba548da2847",
            "a53f5be5bbfa918dc4829e2515b56862d25ed87f5dc44e58435a2c15608aa4b0",
            "a56acb4078904a1b7f8a9c16574277bec3200dab415ea7c2489067616b9c6e24",
            "a59146d76b5dbfd3faa9904009e88b27d7ad650e524adad179c1f24ed9145a5c",
            "a5e4c3b0906375bbcdd285dc54b7d8f85759223ef1fe4682329912339f8e7975",
            "a6264aa2553f1ab817eb28a03ec316c08213b7a9681d73c13ebf56afc271cbff",
            "a640aee20086bf6284af490bad721e0c0cd6e8571e0d6a2e211f0e7e05772eb7",
            "a64b2740c6bdc757fc282aad936c10bdd3242fead7ce18eed0d700ab6f451745",
            "a6c6c2ed7f8071b6fcc56813d6a0203b95d45a082c45b562c7a8e99ca7c8389f",
            "a6c751507f2d7685b1f3ca68c17a566cae6932916757244457a5f465c7c33e0b",
            "a6e539615861c5a5bde2d226c0099a5c4df2840c17efafa79105259001133c3b",
            "a7200593086892484346c8691975f4339f89cbdfa1e44d77f49003cb4ffe13f5",
            "a75937f968f46ffb2f5e9622baa1a6a07ddc574ad221e778c7116ad8b6f118a9",
            "a768ae1ba8a6452b1e25bf27dabbaa2a33e9b7ea58f00f3265c932e3ddf2aca7",
            "a79ab534dcad0a5b25910649290c575e84a33a54912e06fb3ae868b7128ef2a4",
            "a7c4010b721a165813242d7ed83c9c490d6fcd9ae92e0aacb18c5496c9466e20",
            "a82e7cb4128c9e7cd472e0c0682efcfe92a773282b89a0a85a35dcc729912dfe",
            "a8794395a88f5b98b244a4732ecc5a194702e99cc407cc338babdc08d4f5c3b1",
            "a8bcd7949401c1705698ddfd5904f62e8059a2b4b85d0b3be16c1a0ce3deb259",
            "a8f85e665c34e6a74ffcba8b4881f99813645247472319db33da58404a847980",
            "a910bf648efa0d8112597b0b64785a18b19f561a643c52a66f6a649489885a35",
            "a9b4851dce7b263789c1bfc2aeacf0448b97636ea1b5f0ff0f1c37c640d51cad",
            "aa24b347da7593f37fd0ae8eb53aec78a9f59602acd02514bcd604f78352a081",
            "ab0f20cbe57a02babf2ee7dc729f44cec182b548786980ddacc27af6cee9ea3a",
            "ab2b7625eb0d87fb5ca0ee7c1efe29b094f47ef65466cd81be74688c94fa2338",
            "ab849f51a37d2e2111c9e026504eb558ad3e96fb2b5cda3ebbd0d1d91da4a94b",
            "abf6fe0f80293d91b40ee159932e0b87930e444b14a51e05c97a1313ea76aa04",
            "ac2d623de1d663f95613925c912dafc28794ef85f3f51db38fcd74d0fa9002b4",
            "acf42a9f51d14782b8dfc14468a835a170cb6c422cfe7c480ff20be996279264",
            "acf5fd01743243f2e227dfe8eb48be662b90226cbe33a52a8fffba3e8be296d6",
            "ad1b012c8ef87840ca77e82fc06110016b25156f38e1511208bcfacdba4640b7",
            "ad5bd59d9db6e1f588df52ae7929d94545689e7b7ebe4cd2a8fbdd3496604776",
            "ae2b64841071c06e2964b1d7fa230fac316e093559b4068c82cc5a28e67d9ce2",
            "ae302664362d7ac2636c6c595c19d62837f5ba99d7da9e165f452387bbeadc59",
            "aedb398e8d0007d0df87e45371c03272ff75f344d12aecfaad8366b6a7583f33",
            "aeddc46cc155d1c5dd28c98d4ef5bd84276933f94069dce9cec7255e2d01c53f",
            "aee5acbe2684e4c70b433e0842708c1318af22a08fd94245775690594f5f3b81",
            "af308bf269d9dd32ebe68b1fae3b7ae4bff670ed7d5e5efe74dbc10df25ddfe6",
            "af654b641fea7588262ad66a74e9bca560d27148062d3b52e35f8800b3169179",
            "afba4ae6f563e80c0759840be8b56526b6902024e64df6189a8c86ddf62b8dfd",
            "afc1345ba1bb107f69d7fa44bb385c76648e77c0ac1bac6e9f815e74727c0b64",
            "afc38083d95e13d10974f7b9d271996635d643226ca05c1dd789d39f62eff960",
            "afc44b6609334b98635c0ceaf81c1275203166a5e4dc99726ae38a8bfe7852d2",
            "afcdc74986a311e35b3a204df65d532294460e818ea1674af81d582d62df9b87",
            "aff548099baed654c4fba707f93a9ccec89135f2a708116449bc08e7fbfe605c",
            "aff9b5697a4abf992475e9f95a7a9398563fa69501aed48de2c25eb70089df15",
            "b01d7b323cf7087bf66753528d96a7ffe4dd7f89030b43ca58c808c8a28e2e58",
            "b0254c7f49d7aadbe5a5d4706f80ed25c5f4ff5f40a64cf6a4cc8bceaa4a1975",
            "b03e61723ba5cc542618fefae15d0a272226bf99224fe11075d467595bcbcab0",
            "b0ed066689f2dd0b7d6da8700815dc0dfd13636a91518b9f8a7a1a3f904064e4",
            "b1096c329d837dd07254b2292ce902428a5b3f3f43409b7fce45838bae9d8050",
            "b114c0f4f41e2f76471a773961c958f4f79da0f2938aa7fd4e8db82087c94535",
            "b13c1793eade2560b58662b728cec227400b1dcd684346f7110a3ab1134f4378",
            "b1b1b0cea577e07aa4c0613dfdc0963e241e43d2bd05a28fae3166023ff82419",
            "b1ddcda24a2bf1b0e6980f5afbf06b0a775d6a3919c33978e756413c1ceab7ba",
            "b24337c7a5a7403ec2289c417c41737232ac95aad22990a0dc8708f72e0dd134",
            "b24de8d1b9a3f30ababab3d7a541f139ec8520990a49485d608f1f71c1ef4835",
            "b261673b36bc79a25b9956d7ce3788c6328cdf59eecf79a93de908ad0e3f594b",
            "b29f6af411a0c5657944603defe35de45189312fbb8b14f41e1de66d1e51bc49",
            "b2e4fb44af46936c42b7ec31ad60df0e06a243e7a6ae3caab1bdcd5cb6c1f1fa",
            "b30780e82d556ae1af7745448d5b4950b8445325b8fe1f38a0a0ecefa5511fa2",
            "b34e002cbfaf4c0ef06b228621b80f67ccd056aa3d9ae7b36145dfab5ee77918",
            "b40bae231243ea9b0f1a572e5998969183069af90543103ff2e8375b63b3b02c",
            "b4d32b437c2cb86b6827104c9756c1b249ca45b49f3356b00bb060c66850e4a7",
            "b52971e1d22a765894f9b02378cc8fd27f151570b6f575525428f9af147b3e9e",
            "b5eb5ae102bb447402c77c9e63f9ebf6647ea5e65b2587301f1a7884807ab0f8",
            "b5f25ad7004b5057b6223c4cdf94b184227218fefe17a2f149d65fd345d3a1ff",
            "b64fd5ea0d8ad2dddd572d774954b43e017452b11ab3b7fcb1e7644c07b097b0",
            "b6de5a132bb4c35d09eb2248adc741ae0ab7e6a9bc36f7d3cd65f310ca3b049d",
            "b717a83580147a601ec363e38c4db9a1f03560dac0d43f3f7df9cf9d5362ec0a",
            "b766f84562d09fab4b2567bf7584288b70ad94a1363babe5c4936d17d41b2d62",
            "b780ba56bbd0901cc86b6344975c53698834221bcbcac9c792bba490ce324e4d",
            "b7d7268421d812aef60c566c0fbcd5348252cce5f7e3ebb47d43e49d21c25337",
            "b826dba2b33b62148f074cd19e7ad37093940c77db86fc3aa60ba57f53230387",
            "b84d2c9b0a8f14267c25c05599c286139bf87a38bee80945773245d02293473a",
            "b84f527e045e777f21cb7691efcca182f9e8e5fd71715a02dd74703a1835a5f5",
            "b87c57ced51cb7f8a03fb5a4ccf0f44eb22a8143ef2859bf8f33188139f74de7",
            "b8ed74ee5c0e027e5274b85ca840ddecd3b11386e10996a835dd7811db4debdb",
            "b9400748fa637127f9cae7c44359dd71ad42e12c9b5a358d8a8b11e89427f1be",
            "b943d9ba61452815765dac420bb660f66e6e811ebeff803d75a35a4794910f01",
            "b9978890802599313b33c1a2c308358cc4f09451ad62449e7f3a1676706de011",
            "b9a1ac203b009f1214391f86f635d645848d66bccc386127834ad6b272bfc744",
            "b9c048f3e8d73280316b00b73532aacf55e26403cdfc77977d4d67b03fa3f7eb",
            "b9c12877a026b2575ee8b547e5cfe55eb9582d116b0b45b355c6d0278d0e5424",
            "ba01f541bf2b6174fdfd97a529544fc00cd3015b5512c99d908f5422b4bebb1a",
            "ba711a659f7f9bff0df0da18eaa0d93e848d17ab674816da4a2ba4100dad3528",
            "ba73bb3602013ce10f603723ac1d6c14c68e64ef95196bf62b484f15ba3d6023",
            "ba834aa4a60765e770203c4994298f9afb9f359ebfdc515e89cad529e7d613fb",
            "ba9fd425807759a9680faf8afa9ad591ef9a6a5d45de45f9502c42486d4e20cd",
            "baab0e0c8c55390b59b54ad6cda3b9c3e7d33bb21da5707f62edd8eba8b6cbad",
            "bb0befd6e03429cfe4f7b3fe3a5b5758bd003e5700e047d6766835833cb8f800",
            "bb4da88f6bb0a6a10b1fffc5655a3e00793fdd4c93d3f1c24342b666a1bf12e1",
            "bb54e7497acd3a576984ac0f4771e8a6765fea660dfeb32bc7340c312531a4e1",
            "bb82d222ca69605f2297a3bf19bf693b14d44117c803102f68a03724f24d4610",
            "bbaaa268f66f9db3a21cd608c225ed89450babf82e337d6c7e097f7a3a630ef6",
            "bbbb3b1ea12962011285cfa3e28237352bf2daf12e6d8abad04503f309e5275c",
            "bbc1e8d72a40ffcb724cac1169da254587bb4d51b96d5d7db6016f45a7ef823a",
            "bbc2c42e9ae9669600aec3ea25e45a20ae2ba29fced72ef07784daeaf01025b3",
            "bbc83bab6960b1c033379ad6e74a775f407ffd3bbaf18ab60bd943147184230d",
            "bc0b40bcd41cca107f693419c4721fe4cdaae26f22a5082dbb6ff487b378807e",
            "bc12e191009e2f5b7e0ef60d8d10cf211f65ece8e6cc86fbf0a755a394345f7a",
            "bc249ddd715841df85525ea63d4743b6a7ea2ae10272f6caa0dc18d0952e6927",
            "bc313c5fc1e5483a003b8ac43b8837e8184228fe2d7acf76f176e0b5c03f54a9",
            "bc5880bf36c03ccbc5830cb6ce8b1e9b02bd7d4ea8a3e3719bfc8fb6d6859549",
            "bc72db8b50eec7d060643e0e45e147f5fd72062148e35f1f64aecd6763e5acf9",
            "bd2d2716ba8624dc1904353a24cd58ecf1e0511c12c7cc39f241b87924930ea1",
            "bd542e14a0e98a72eac947715d556637383e57b3548078869a3f909817724b94",
            "bd77da5780ceb9b49471be85726395838b423511183e64ef161dfe5554b788be",
            "bd8dd60b8cf2440e8389a0e251da58b6e649d02ef87b86d49ae87edd427df95b",
            "be02a1f38383e7992c17f692a0775ef63b19d871db3411fb84bf85b568e321c9",
            "be3226ff1e7d849513f0b5f801f2b9a9ba98795e5aaea0cc81199102da9a1b86",
            "be3755a3955722cf5e9732847adc20c47c9d947df90f2b8b9544bf7f75793aef",
            "becc74d799c85e376bd7e6473265b0b84e886beecbe371706e8cb2d571987067",
            "bf0b8eb29f10142f3dc2117b4c512ab6421871cb2f033358d01fec0699ffa869",
            "bf7cc40140b5f367a47694d1398dcb3906a08b80fb89b4e69b9aba34c30b8572",
            "bf8a7c8183a26dbc5f6ba48fc9481d7ac1fd09119b2f01102150e85d8bfca4ab",
            "bfc830a2373a253d21353b69af36c958bd558a30bc4e2bc6d3b6b6aea032a643",
            "c0167c019428b204432b49636f713908bd72794a9ace1c89e615b591ec337af9",
            "c032e5bc4da81bedd5012d7bdc85459921171e8e5f4aeaea4ee2e103648fb78e",
            "c04c9812196b70e684e429549537159813b30ac841d27c1cd7237411d3b328c6",
            "c0539cda39b075eda8c5a244d293c12d3b24af3f1063eb41b9cb5769e3711b5b",
            "c05873c660f24ffdeaada12d4990c569395a9c096440701599519f2ce9d29447",
            "c07382f0fdc2998163d3f630329278c4fecdcb7d65ba309880a6353f08fcb4e7",
            "c08ce44ef6ca8ca80d2a1a2c2991c62343f01652591467e48bc912d96d0c43fa",
            "c0a887d2c1b181e42dd9937208bf168166ad76cb4f279020b63f304362e9cb33",
            "c0b9367c92229a804193a5bb261bbf2a62489887e9aa408daa399344961d2aae",
            "c0c575411b2c29d678fad6973110e9291090a708dee2ee7b56a2514d710eda61",
            "c0df12b40b1dda8af23686c70be7019192f2b446d1efd61b9bd6250e1c66e0af",
            "c10af90e107216aabc6f3a6463f027d1b599b29effb04a690c17341994abe1f5",
            "c11ac68b8a8831056cfb0eb4067a9ca7dcddf9b100c7797c0a7f8e44218292a4",
            "c1714f19e8bb294f65217eec79641eea069dd90e5f7e8395fedfec0db4c14821",
            "c1d7e3443c32de04de15442767dc81b74dd2bb1ed722be6254f0f81a6a08c0f0",
            "c26eadc09014bc65bc3eb8ef8d0d38b0696005c8c0e26d44066e9de63081f8bf",
            "c28516383921721ee5eb10fd898e0c8f90e5cb468600e0d21025324e701d56d7",
            "c2e62ef112159719f2f23da710a5063e80c3a9e7dfda03462f626226edf9e269",
            "c2ef9678e8f594da6413eba9b67f054ef45515cd9b188488993f5f8408f6f64f",
            "c302fcb4dae628abe204811e7dcc8ac2f2f64eea19bc61b716c9e1ded91dfea9",
            "c31fe7a9835b905a0aaec3f84f5f7657468a0f40eba7a3b01d0bc8a731aa0289",
            "c34851b593275ff285fc07eb1a5bc7253ec84d1105c50e2643606c106264985f",
            "c37ab6dd2c844f9b5d269bbae54e60cf3b72f893c8b777a8250018a54aeac11c",
            "c3926a2f7c523a857231038de51cca6fdebfdf3d524ac71766bf3dc047179a7d",
            "c3be8e2e0208790a36c84d226072f03a99ab00b2d8fe6c67771f6f555df3808a",
            "c3ed56e7b7576c4b0efed7dac54dd91d176a646d16a57b6347b7d682d038f906",
            "c40089310072160a4024d38b0cdbaeea291f2e0fb592b23cd3d046df8ff0c079",
            "c4103d919ec78806cd9303244bccee61f3f52206ba41b1986ac6edefcfca018e",
            "c4127e1a45d62ea559f181cb2ecd9baa3ffb6f1290799285ee654772b4bb8cbc",
            "c41ce5916f09806be0ae23e5cf286d96fb918616e0344b4af5d1975628b823d4",
            "c467e6e592e51967b6968ca72f6f913ad8faf791cc1c8f4116ade49a6066d046",
            "c4989df1ed84ab44f18ec89a5f36d4d188cbe995cf8068c197e327e3d6bb7b4f",
            "c4aa10a1af21df7e2093a22f452de4206ae8546a89d02f3e0e9b7b7f8bd7da41",
            "c4b228e1dcf7e5010a9cf8a009997b08771a624ac10ee328f19575ce1d3fc552",
            "c4d132b41f34a74ff4b55a44172f34f451bf69fdc7841f856991ad967af07726",
            "c4f07975ada4eaa8f68e3fe0f0a354528f1df57aeb7dfa4d0b3ca3e9c888a110",
            "c501c5bc9d8373396cdc60cbbe3c0b17a3cb5b1a6aeb5b059ff49244e4083b9c",
            "c5165e9862f463fced5314e5ef14cbcc221b43824034b473e4b9dcac2bae218c",
            "c52236da95535b9ed61ef885a917eb6a1983ca9e69fde7dd62a339e993860cdb",
            "c537282254ad25a160ccdda6da8f71c36fc43640b7b1f96f2df0c73e272182cc",
            "c582702441f0648f1d0c87bd0bda4f503991893de939ab2c5a92e10ec0d45c30",
            "c622419e68f783b3a07ad42d61d98fb0b0a240835893befe97662a7968e1b5e1",
            "c6599a02b46e04159ef64831e1b1ebde922cc6ff8ab1061ff6ec04c3cda72b97",
            "c6778f15e7fc777744353a251ab0c5e047deebdaee35180664942e817e163e74",
            "c6ae1e8dbe20e8ae64cd57480cef8ca56661b2a025e0fa0fff380ca2813adf8d",
            "c6d2f2d92ad1236f4bd74f12bc3ffb8b22e0192ecc06ffc3e557c93fdfe3ed9d",
            "c6eb715c37d521fab79d5f91597527648a6a96a73037d957805e9d91df8043da",
            "c743b6ae6a8523fa7e09b6e0524b6d2607c8294bde59e283b2baa55a671e194b",
            "c75733607859cd82d75adb4d76c69fd2630e736ddddfda9a7eb102bebd58f2e6",
            "c75f548713f4b6704393368027e11996843367b84b190cb838f5f7d6e5e39324",
            "c7a49276dae6e56647cf5141321ccf5da958989efc942d28ace6b41cfe95c97f",
            "c7c355b7d2fe4b242e8d49a72bc7d58f9358c6b125ea763df9ce5f615e75e336",
            "c7d57d536b650a0fd7bd29f02a78f4ab561a211e29a024a58aa121235e1c104f",
            "c8197af62eb0a0db6b7ef8d9798bafd4ad5a2002ab7162ef808efc79b91bba12",
            "c81b6a7f153f06f55fef1536517e11fb0935a54cf856fe7bd17d7627cf6b5f7a",
            "c8759084bf6feb4f801b494cf49c2e97adfe4976b6db50687e889775e5873913",
            "c87e389205e3096a33823d3cbac9e3aa8795191a86a437b0e0046e8829c08cd9",
            "c880fa21dc63e9b4d06a21d4588e78d9d69d5c95f97a822ace21b23b3803d6c9",
            "c8923d1d2084bc5d09dc22abffac5d1f178ceb5d583658eb9e583ffdb0d768b3",
            "c8e5da99dac079fedf6716ff264615addee467f6e74ac1c6a213b05242af56d6",
            "c8ec226a459d24551667d40c0161a7ce86348f4a7f6a9d2f8c7e58997c52ec67",
            "c90bbb566b97be301b58d4be11c2cecc276a36856c72cc62faba5accf555ee98",
            "ca0d716a80dc1975f60ad7abe64eed3fbf2b4faddd7f67f8f93fb17baa149d38",
            "ca30fd00542e83ba57e9bfc7f98122db170c0e418c78fb858bbfbdb52b6b45ed",
            "ca799cbfc5792c8b6e1d9cbb089e9e602b4eae56e7e8cbaebe3623052d27ed22",
            "cbb23cf2592b5a2ecc7f6e7a934582db2cf016fb588110c87907548eeccc7fa5",
            "ccad83c10d665a6769eef56c0b6b2cd1f1139299f15b7b830bf52480dee039aa",
            "ccca02e52045d542441c351a79f482791b181fc9930c0d912428736e16416e8b",
            "ccd7f200d25b848de6ffedc3d815881a4d2c9758f71b94c4ad6157222b045129",
            "ccdebde5df74c69d23513a75a4acada94cc8a748e173a86a377d9d22681dc5d5",
            "cce09963c49e760f67b1d87d8f7c8aaaf1c8e4f7e6b4f6ef11082cc07737009e",
            "cce82a4a903027eede15ff26a31c96ac86ed4ab71874376d2a0047d03603ef42",
            "cceb03c4eee74ba5b5defb1e6d794aa22913cf46b124aace5b8e5168af6feba5",
            "ccf0843297ad12ea197e67506e0e5eebaac9ec1fabbf0e180f8c4a6605444156",
            "cd2215cff7df2eab34c2e8def22711b6a9e7d84df33e7b69b9d6b60770523e50",
            "cd90fdb3b7120f771f6a9e718e9380aaae610c82f977006b8ef5d5229415c969",
            "cda5666a544176207cd0ff6760c6ba7fe2edbf2a8b8dd4b2ddcd0b17237708ec",
            "ce6eaa47250f885cd013932a18ef291d33c928141a970e9c0a15c834c3c5445f",
            "ce95ed7f457544e9c3afbff1ed57ae824e84466da73db663e5cf2d3a9d5b7d4e",
            "ced80503db0696c4c0ed0b451d0c6b78fe786d5a11c1641ac9a977c176dca75a",
            "cf48801e7fe36c3217eb072411566591e9a6493f017fcd523cf61b7cd2e955d4",
            "cf71d47edc30b05b414085ce86d1ba825e5012907c028481b7cc3513355022ea",
            "d007bc477841dc635505d820e86d0f82791adc079dc6523e9a147000eed34c42",
            "d01f4ba17c6028c0040891dc08aadf72a5b9465bd7046762421fdf6526141236",
            "d0592463e90c8d381df19c0d14c3c5faa73258a2a673c59a6fe0688e2ce12ebe",
            "d07a50bbf0b5b37af2bf8fe283a44c48aae06386f21f12952f1d9573785de768",
            "d0b532e3b7b2701a47fb2e49d177df94b62e23e4c8f10f5070fc755f54a1c74b",
            "d0d87347191274335037b2ed40797b54a203d786af1036d996d75651159757ba",
            "d1214e7c7764f872d7994f95287c2d7264a90b5b8afc17b46248bad6ef52c382",
            "d180c63c9d24baeda07124d4310a45ee589ab8aca9d871fb5181714fba089c44",
            "d1b29f9b4617463f411b3fe5595cd8f369e40f5c6e651d42bfc395a2893bf996",
            "d1d0500936cedebb4d0ec9dd299673371aeaa61874cf179828f07b02d1a168b8",
            "d1e9078c0fb4d19eb10e4217a1118d7f378ae1e725dc217f7f29665f6f1aee3d",
            "d230f32b64d37a0b07a92083c30aebb1ae7d402f4efc64226f9e8e1e568776cf",
            "d2c634ed5043b84180e5077fa4f9cd981e227f27f82fa4e853ddc1bfb9c3d36b",
            "d3de9268dc6422c39f319fc9bc7e7247e8d2bbb4884d60316ca9e97cfde7ee99",
            "d45401d348d89b2337555dd5a9c172036cd1e50d9720899578ce6ad682e1d5a3",
            "d457597cb584d70108d47d1199e9291c266eb5cf5e93ae0bc5b8a112c328a79b",
            "d45b92f3e581877d0761a2c25384efe4dd95adcaedb3b2a83445f79e9113f7ab",
            "d46ae57bce104fd6631708bc2c58943bd99852e7c0138729e182d78794ba3764",
            "d47bfa15d9a69705b975c41ba7eab1b51a7f0d284b0f8696f9e2ccaac443b486",
            "d49c89bf6f59a1eab368ac3a24f634bd28f05f5c295f0978eabc882042f302bd",
            "d4deeb16498e997a0e0e276be7ba25cd92aa7e3d0e5bdef556a089ddeab603d0",
            "d51843382729014e5a0d6f5abccb827991e9f747c84a890a9785c2345bc85314",
            "d51c2d89c5ebb9387f369aa9ec9a5e0a073a162294169ab6501f7a355276e809",
            "d5b58aea1d434efb199fe7d41c8e7954387eb0e7942c55367b9bfcc9fdc86e9e",
            "d607dc0a343eacf072f26664c6d1f9f89e2d124a9c03795fb28b1fd715e6acd5",
            "d6118a171743002093ef23ed35c8d16aab77f784a1bdc0a41f2b62103bbf3ca5",
            "d64eea84fa996fa180b5e7f3ef9fbcad503d93945b57ee2b57fce42d91bced89",
            "d6731c1f0896335370f5ae906419f55ec672a7372bde17238ee119da719c4a1d",
            "d6777a1fcbd832e3dda81027b1c4833a5fa7fb59cb6cf9d461b2a013adbbb6d0",
            "d693d1d547108c0ad40f4398b5dab74ecfc29b96fc98f8127baecf27014cac08",
            "d6b071ababa587eb54d57ba6b8f5deb70978667208ea0fcfd4f9134ad499f49e",
            "d6b95c4f5b0b392989adf8b6678e0ccc817fc60af92244b50cb819b394fe718d",
            "d743dbaa300f6ac7e21773863722a064f98c7f1bcba4e5e0f029a8684bedc4a1",
            "d75a9700b4d48f3a15885dd8125bcce27ba72c53d53a8d0f868dc139a23e454f",
            "d779427049f872872c47e72ae0d53d12040c00792653a5388074baa171e3e467",
            "d782db1898690d49a2f83e35bbeeefb5ae92f50c4006de59b1c1f7557813908f",
            "d7aad302148d45db6eb0f204fa095db914225cbdc07e21dfcb626495fa55f4ee",
            "d7ed6c2f30d59b86a344232573d7f8ea905d7af941a75f147a2829eae8105052",
            "d832359b006e42ec6056bdc1a45326c05eeffee7d2b35e8e2bc4146ba444fd92",
            "d8349894e550d23de262364f5c45ca32f4a37c4f103edf8267596c592e172b45",
            "d83e093a908274fa45157700293f1052a422f291650fd41260e6e59bee7491e3",
            "d87a307aa1c3b7d684fa40ea6b4c20c6ce2a2b9e3ae135d063914f2aa8f8a46d",
            "d87c8e0a6aafc43f4a7182dafec65756df4c8c48587bffcdefb1fd6db2260784",
            "d8a871585e1f38b4afeac9a58d113480124646fda999a958a05f3045f552a429",
            "d8af899b05ea52129740988f4d9b6f46d02a342b03bce280c7434647d88d6b76",
            "d8ce5ada69d6a551b749ae1cd8ce99b69c435f1a9ac93402bedcb900758e29d0",
            "d94ef07384ab6cebf8c8a0ec9dc5d77add7df581a86c775f1ca272c164ddc05a",
            "d99eca46d0074833ab4fbdcc9d84e7aa2397f3bdfd12b6b87636c5978d45ed17",
            "d9a73680d18173de66d559bee3c91952550417e723730c6dbed8531cfce950ec",
            "d9ea4d3c2c72e79f7a589222a8052f8cd1c304f77ba3aa451c7bdff10cd06257",
            "da119cecbc268338d4ae761842c1fb9aaac200ef89b11d97e023389f6db92eed",
            "da407a078119e28f262f9a8749e674f6a7ecb84708342e14f23418e165f8b2b3",
            "da49979e1f2e3c92e1bba24c42207bbe8e0f8dbd00852c4466cb3916679fce1e",
            "da8e5f427a1e9f845da2244bed345e77f56c3aebecdf1bcc1763f2bb452136a0",
            "da96147d84741327f857ab2413b9b58f00a368fa7914e28736b7ef3ef8de8630",
            "dabdeb46463a10376b295f4d97b21a10bd6c5ee68f8e905452b508c1d0bd2975",
            "daf7d3f943b3c732d05d2822aa96f6147bb6cd14a1b49606635e207eed2b353e",
            "db2096a11a0638dc53e42bd974a1045b20d5ed28ba4568c046441589f54b0404",
            "db4e66f6ffa3e61353f55d02cd3b9b3b4f55457cf78922650693429c42166b9d",
            "db98c667a9ba16dfd4b69db6bd1cb67b28d0ed989801cd0cdbaddee41c85e2ba",
            "dba8599b6e7bf5f55e7ef85e8263d22c5d8992134698ff2726b6b6c3be0ddfe0",
            "dbb37b9be437db2bf95f1b11ff7be9cda74939a05d058a9574f61538aa968e4c",
            "dbdc422a9d52e5c607ca207f913defe7f5ecf3637d5fafe100ec8e44d9c128f7",
            "dbe6a528be0def656f33eb22351c8be9c8694fceee217ba7a9aafe84574e20d9",
            "dc3cc2da5d2672873dd2626ad4ebd69ca7c47935baef88f6a6a5c46dd242561f",
            "dc50b39542863852aac2b62b75b51c2d02c042a3491d748bbee3fb2e0bf07b14",
            "dc5915232f151c02295482208d8cd78e1763fd2581e7abb188ae3fee5efdfe19",
            "dca93480c73b8d30833423929c17156d946347fcce4f82ba88a8abbd73f320c2",
            "dd5923510550e9a6b5e262a0b35473820ff517c9723dc3cda28879588d7fa068",
            "dd8f05eafd496dac62a578e21d03ba906335528455262d995da33356f1d50457",
            "ddf5269cd3e5c15d3a3f42db97000692860622fe4f2267e33d6f01cf531cddc8",
            "de159b42bd3387c3e1eedf5914c13d9b8aab8fa97a3e5f5b1443171b49bc70ff",
            "de20a516d1e5fe021768264e9a40eccf7c3556a6ecd096a24979c937d2da5db0",
            "de6f070e3290a6109a8a344c24feb2847c28f8f8ca466baa121b26b40432a44a",
            "de7204abcf0fc4f29207b3c185dd088cd6243c11e81f99819c43005ae8339081",
            "de888b54554d06e7c5bf480f4e87d504d2ab0f054a1191ebdb7195b835d5aadf",
            "df14526c7c1275ef81f0d02dde437c0dc37602fc83be1b809a473ccfaf1f3cda",
            "df2b0bf7aa1ede1e19d303c1127faef821e2b7246f18ecc20443131453389c3b",
            "df9676d35946490e04ebb2d0eede759e68dca9ac8436ccf71e8ee5a0688406a8",
            "dfc9d2f400acbb00d8f143cb65823f8e517707db6afd84d16e2a5a4c552b21ea",
            "dff317c02ca42e07d706ef1d578117c22ef82e8fbc95b36e6fd99f8a8e5f5b2f",
            "e0269c14e87c43c6d66105b4e75ae481a81ff72c05aabd04dbe0f0ff9b844b7a",
            "e0492bf7619cf43b8f5332ec66cad27b85997427a7886307bdcc46949a6f693c",
            "e073bc8c628be3c67110ad934328ae803bf704f7b29497d769df3be739075b72",
            "e0791f76f5661e833d3e9ce15a3b21ce29aa99bad16b95f647a5736967d11ae3",
            "e08134a0f97e9642972d1b61c3b6f6d6349aa32d3cd8dc77e78ef794b18267fa",
            "e0f6c9f29a1c146323a997b8e52c8bec573cdde32922fc726097f95d49dcb537",
            "e15d2d268bd2d1ac4624326d49bf7ba3e3bd643e3a22d4df285e69b29bb27cfc",
            "e18de098bafea3fc447988edfb90abe54580f3f779d9207927650a2423520b23",
            "e1dc906ecf5c4d7cb644bcd704e80cdae0a6b2a21272828821cdbcd1a28b4e2e",
            "e2831f5a321454f75e271bdb383b6ea0a97086a2afc9ef21d202b4e4a238602a",
            "e2943455a0c1e6970401b0368a5f8119fac5e8799d51f5dd2a092660bd07e2b2",
            "e297ef02993a35a04f37271d8c716ffd3495a818cfc55e400463d97e406f0317",
            "e29d97338e1e4ac51684fd07236dfc5869589998760a6b1806bce4e153507fa6",
            "e2a8b1c0e673f1f4d81ee1aab167a4e884ee0cf783c038417bff8db7b9e35e2d",
            "e2ae0949321976ee91fda9827d53884e6aa7f9b746270991769c86c9718c75b2",
            "e2c95a913a5b6545ec2a6aef3c27772104a1bf4ce71ab8477dfef3ffaa6ab031",
            "e2cc46f30160154e49dd01604b8f28eb6508a3feeb9b334aa86398d5d89cdff0",
            "e32a6bf7f122c2e490707281d95354b5b7333c1f135f67fdb210f694db91b2ac",
            "e3423f6420e1554eda032de92c74a74c9ab6eafc9258571468e36301c551352c",
            "e35c58a30f02c5a709c16ff0680f3635b97e97599486b43f08ab3fac26f7cb4d",
            "e39175c944954f0bfbe4ed0aefd419dee3566061fea135d92e79039d4768eaa5",
            "e398de0453ff516ad084ca3e3bce2cb5844d9e042f692458b63edea0168a9464",
            "e445c78224b55dad22ca4d05257df98677129db1ba8a34d5f00da68dbe680266",
            "e47d4a5c6ac64ba7d7471ec0b2cd5f231dc8076f2458f96f4272dd4c67445aed",
            "e483425a24878d5cb9e9a8a9a62c6eb87f214aa1335b6a774ad9c77f935babbc",
            "e4f0a7d035fcfc467bc36c055b58b69b11335dc06a006389cc5d0f4b32efabd2",
            "e502eb6fa5d9248b4a3e7af133353df30e6e483d28c6a6be3e1609586da36d0b",
            "e518b7b217c30a351bb1238c15cd7fc06bc839f5e478517481cb54d63502ed2d",
            "e56ca479af4a9bb1293bd77f3f34cfb1c79fc72f001676d1f360ae9719f1b9e5",
            "e5739affd9ad9776b1b80401e36ea323a47a3b6dd75b9e2af22dc0b43f6523c8",
            "e5e845a7e68d89b185d3d7283a27178ad5179e40c6d9301d4df918ebce48ffbc",
            "e6039284b1f2998cc9798a10431161d6fdfc62bbad2a5a987bd95c6b0203e279",
            "e6103505912d6dc3553942ac1c54aeaaa0a10a47acb221c6ea663b27bea45fe0",
            "e65200f90f37e84a161615487a296466e9c176e3969734b0787673c726ca4857",
            "e706041a756963245c20ba63234ed8084ff8966d06b57f4440ba434311d4b0aa",
            "e71021bbdefbdff1c3788958deaa487ea1349eefd097330917e9919eb764f13e",
            "e74fbc8e1ddbdc7dcf80d2d4e69b63a1457c058fb4fca70bde0b636768da691a",
            "e769b65169e916654c2b2894f1711f67a288bcfc79f8be8b6104a2d6566606b6",
            "e79970487346581fe3d066891898c373ae628ce628f3ab338f48beb05d2f089c",
            "e79a190a8872d20ceaa2e7b5df6265ebc0788838b57ac83817e33fba8e4dec65",
            "e7befdbbdb9f8f93ea0ab23b31eb1d606317a36a4b16bc3a90e85f73806f0d28",
            "e7e5385ba1205ce2907da99512d3069fdd81c2f6c92dbf76394f75828c53f218",
            "e80e1e6215e70c53e642bb5bddf7f8801d9d91f3ee96a5a578ebb74991be5c3c",
            "e8520625a7ff7d123fe23abf1b885986fdeceb1de32e33525c2fd9d5f16ebd3e",
            "e8a44a0c63f0fc635fcf8303b55869d2e5a6832aa8a037d78ba7cb62d2da76e2",
            "e8b770547b4b8c88b5007699212b2ee300d7424718fce666ad09a8c634db59ff",
            "e8c600968225d0fddaba7c2fd1acb4d4b4b4cc4f30b5967e35c9cbd526a46a26",
            "e941354560c323bfa134ca270246003359db5a74811baab33a5a2457e094db0d",
            "e9718538082b8f7bbce9bc45b4e2fee00cb2237e55289d42da5b19f184a999a3",
            "e994203abac732b2d8c68578a144c287bc5b5a710ef5626ecaf170d0fa1e87b3",
            "e99b332a2261f507b32ecd80544c3443ea724c3b5851578e21ef90062815d1d2",
            "e9bf26d17ecb57ad00149b5184698eabc1adecf737dce160bf12a9318394f08d",
            "ea16a0a35db7be3e8fe9e399f5cd0f34b64d41c0693f0ed0a6b1f90c0b2c0ce9",
            "ea846173170147c7478f9a6850e7bd443c4747b53862d76d6aed5bef05c77489",
            "eab165d87966f9bdec2305819212542c73a28881213c90f79d3e195219981c91",
            "eabee17d73f4e40b9a22ba1ab8a1eae0b9fbca7b25a3783f6fb8034cbc0b2e74",
            "eadd271c343999fca066325c39614ca30f44613d9f8ae490c0c40d5d3910b01a",
            "eb09ece12ab586f89c8030cf640902cc5d0e9a386ff99ef03caf7c6fee9fd99b",
            "eb1452cf8038f585ac072167dae2c4c4947bb3c51a855f46cd020626bcab9101",
            "ebb8a05c9c0161055b19629a99ea6f4a5dd5d9a4b8fd79d41de4157890450211",
            "ebe8bc127156d00cfaf86fa01d128b671b2227525264671b1b8510ec568f567e",
            "ec03b0af4b903f27cf8b4b8e7a94088594f8631e867827b4c1e3a02f44260a58",
            "ec0e1ffe5ae3ce41f7c24f904b6c9dedeb52ff505df41e6a6e2c30df2e1556b7",
            "ec14debdc1c6d648194697d6ba2a1d465cbbb2723ac193c174f75155889a4ba7",
            "ec60dcef67d5d19ab5aaa02e40e05f8706a766c54f2a44bff54f3afbd84050c2",
            "ec7cb0d1377cab8fafa098f69805230a0b0ebc8808ee98873ec2c14eeb0c8b6d",
            "ec9c50d04261b96c67f3d248e1e04e8d8d6b5a09364e7e985aaa2b59b0b1a232",
            "ecf041c5079eb1d931a69f7727270228654de950f4532528ef5404f5009b2a72",
            "ecf204cc765f7790bec8fa835595435da064a2c1ef5099eea4d93ba5bf8bbe65",
            "ed0c5d9fcb222d3b0f8498c4eb7b4a3a56f5708cc10062e0749b25ac7100efdb",
            "ed2ba56babe22d08f8e63ce7bbeb75a9a0c4bd10497a6f72f6c649978b3dfee6",
            "ed413950889a5447764eea4b3fb52170fd2881ced80535b43b453f2c5f71ea83",
            "ed98bf171d0f5eb3152ad9c92ac06e7fc42ac14c419a4dfa9e90b99f962e89ad",
            "edd4b4c07ab063289b9a9f8abb5a9f4b941583f91bc67dd7c7f7eb37336a986c",
            "eddc6835a965797502fb0966b8626cda71c5790b27003cbd42fc90a0e8ce2459",
            "edf13e7499da998945ceccb2795342bf62bf554664bee63b057aacd41d9cceef",
            "ee01604e7f4613f78e75437309cac16e3cf45e91b9b1f4cde7d4d484170ce19d",
            "eec651de5f16a46dd36ab6f2dc9f395d3e28083f3dee914f7839f802d3f94604",
            "ef15146c63f8eb520840688f3ea99f36144c93c3d820eb97f017c5799068095e",
            "ef154f98afc21253abf8a6ef87570c138aaad2220c479f992df5d4392de9df66",
            "ef34ffb6eae676a84475a2c7fbde51613564acfdfe605642418e339f97353baa",
            "ef4ecac957ff4399da86752ae5ecf363b881ef2b75a9831a427abb0abe268571",
            "ef5b3648f6d5f1abac01df5744145485c299061c9564bd05b3c14da94d89f6c1",
            "ef7b97a24b6869b4b6c4ff755254e1c75d07a6b008d4884ae611485b3366932f",
            "efdbaa03dffdcdddb25d02187a6e174ecbe3aaee09085fdfe58d9bbf3ec0dc5c",
            "f04e178485ff665e825923d78cc0a5baba49e34d568933aa6461239a77493ba9",
            "f137a447e07293b47edc8ffd34972b0113b891a959ea863d303429fb30e51906",
            "f13b5ab38574efb5512d65a7cb845a295dfcd83642fa4ec97145dc8e69698db0",
            "f1c5edd560715a4ac09dd404a7eef3c19e9459c9bc26aeae3a91f6b0b47d80e2",
            "f249cbeb3ac5d16327b595373937ea15b7f925e7a855223d49cc68af84d227df",
            "f26a499ee6ecd2be4427aa4896060f8d1335d5670e60b507ca3e2fd471e6dbcd",
            "f27b066218c5328f757fcc795d1813b2aba50ae19d530a6feac61a4475929a0c",
            "f27b6e32ec80f0cb17b3fff4182051b18f80679ca2daafde7d363d0b9f1a985e",
            "f287787e63566b96c77497f9b0b5eb0e63701aeb594a6f06df9552fac6026803",
            "f29712a477f1b3292a42928d88f347965122101304b625676328c838d6a7b121",
            "f2f9f5e02ca4f041991ae850cc7f6f53aba27d5bb20e62f57854c15737b32fea",
            "f32c3e4e1320466ec0eb51bcdfae6f78fdd09a58d66f210e3740a1e9612623c5",
            "f349ae30e765a8724fe523a35ab0893de34090e236f5bc1888807c902a553170",
            "f369e3318197ce4a0ae106f2c1aaf07460a36a7d9531871db2995d00a63f7a6d",
            "f3858c38f1216cefd84f7990405173f4c90117799cd47727198e38d6a2f86473",
            "f38c53fd6f761c3167517f52873fbd641c1ce295e29dba07ebda95b56297a85f",
            "f3ea973d46a0ca9b708e78f31411ecadf2a5867a8fbb8244cff53f456ac58712",
            "f3f65aeed63664f59675a3bcb32b1a9ac980924cfbe3cc3f7f77317db769bb02",
            "f422e2643670c7ce5f476c8a03fb6dbbc5ed9876b8d2c77ca96adbc4cf2d71a3",
            "f439735336f310742d87fc60af5a45ee76c96731c1721bf6ea4ae56b0b8c419e",
            "f4a116fb4fafd1d88f114171f2b54f26f31fe9ebc50f140bc6509022519117c6",
            "f4a27c1b3ec9948e3748c6a9b8f0fed80a070b3f3308a430de000f38ff4935ea",
            "f4d5a27e17b9887b47a0653c9811f86310650debb93d4e0726b6f75d7eed0afb",
            "f5248bbf6c4a4fc5d78feac0fb8d5d2d6a154549b0b2adc39143709cce3a6657",
            "f52b730617ae8904c4589ec4ff28aae681f4adb53e4396532c0686d2c2562818",
            "f537793707314417f4d634881a3dd10e0494e6e1a2ef2785757dae26eda94f7d",
            "f54ecc8b5511987b60594e8bbfa38dd5ca842b96d8d22db5f14ef31b8d2812b1",
            "f5529b86ae627b78b4e1c3ca8932280e8332cbce1363784748a6dbd94da8cd24",
            "f58996ccee35afd6e87e02aa3c3f3e2393c12445b924cb6cf4ed5cb6d0f2028f",
            "f6037e430298386c78e2f62f09279e8900187bc02ad8a6c569ce5307bfcbf5fd",
            "f6dc8d47663b9c9b92e575b68b646c8d362b2b65e92d95b243c36cbf844a7cdf",
            "f6dc93ea1c687f7f78562351bfdb8956a14801a66c99c825844ffa531fae050b",
            "f7359fff7613fa762652ca603ae9cbe42eec60f795d50f901fe2e6593bf081b9",
            "f79ee7a8dcd78574273111a1c754da2b99257bb751d2c16e96414f13723bee04",
            "f7ed02d063c8b54650c48e3750261bd4fc6052eb0e358abac42baec7c94ff352",
            "f89c57ad78a3289d31cb50e0f59bffdc997ee1c56a9b932ba8f6ac50891707a3",
            "f8a261beb607284aa7d73d5ccc66907d1c7a8fc4e234fd4fe9824b3128a2f379",
            "f8a850a906c498b8025c8b807ecc49ab40648b9db3799416f76f822cf8dddb73",
            "f8a96d098bcecf20b8c7354e232ea706e9323bf96802cd6ae0905deef54c7d74",
            "f8b4d0fad95d7d7c0319f115e0d57ed16c562e44da2b64524e8378d552a869c0",
            "f8b97ef6c248702715461a075063fae8549c3b27481f35168930cf83ab12d786",
            "f8f1b5afbf64c7100c95c465c266fc9515e1e1e30168ba4f5ae46a4b6bea0f0b",
            "fa0320b5f6549da5a9aecc11b5d3515e105e1545fb3f75a97fc1eeb6fb8ebef4",
            "fa6971a8729411164d24ffe6b668a4c667e895ebc5778710ad972e08c10e0c2b",
            "fb2329fbba1b724d01f7fd4e17218635a9c8ad86af807bb9af0435d2360ce2dd",
            "fbce6f60a17f92b8374e4f51020b02f60e9a040fcf275e743fae5fd8c93d08eb",
            "fc10ccfa85d618e28d805b051fc99a9426ac6eda091f50caff7b5711dba8f0f2",
            "fc26277f3da7144503456bf36788d8e807e25410c3e7515b9b7331b66e9dc181",
            "fc62b602c920d7eadd7e12e8f8a6c12aec59111bbd5096b8f28f0c7f5569b9ab",
            "fcc2432a9dd936cb7454834e1304912a265d1dc188fc4d8ee91faea482145f12",
            "fcfb44215cb54018cfeccf5cbfb43d7671678e6dc91ef5b7ecd381fe2425402a",
            "fcfd36e54137a3a0b00d469c584e285b8944126480b92e3697167572027d3166",
            "fd570efd2e40444f2ae336118acc3410a995c523ead53aa07a8af8bf6868e563",
            "fd617a0fd7c5b7c34ff3289ea6265725705b0a960282a2a37abbe91d163fb756",
            "fdd77629db7d621472d309bf3688fbf7b065f4317b978a6c0ce3e5b154272d73",
            "fdde5e2151a40354f04d154ca6205aabb0454e532ee769c24c70bef10f4a6cb5",
            "fe26547c9fb1f253e6ff4209dac5e0b81e5e1d9122a480fab2770a6f973706ad",
            "fe91783366c30a18d7f346c31195e9363029fcdc14b010e944b2f401171bdb5d",
            "ff6887cb574b898f94caac8470b02b29ae2101f6ddb0a68c82e1babdbed810b2",
            "ffa7da1a051d98be3ca9c003aa2ede7cff22a7365c9c833630406f09ff2ab7b7",
            "ffc14f86f70375c03ccbf3235d36f575447c8c0b7ee6d405f0dbe70f8e8f1d17"
        };

        // Parse hashes, reverse them since they are in big endian order above (JSON output from bitcoind),
        // but they need to be little endian order in memory
        for (auto & tx : txs2) {
            tx = Util::ParseHexFast(tx);
            std::reverse(tx.begin(), tx.end());
        }
        Log() << "Calculating merkle root for block 758277 (" << txs2.size() << " hashes) ...";
        const QByteArray expectedRoot = Util::reversedCopy(Util::ParseHexFast("7583c0c858d8f53c53a5ff30f1f8d034b6a2cf01daf77a04f382597c9aa76a2f"));
        for (size_t i = 0; i < txs2.size(); ++i) {
            pair = Merkle::branchAndRoot(txs2, i);
            if (expectedRoot != pair.second)
                throw Exception("Merkle root does not match expected value!");
            const auto calculatedRoot = calculateRootFromMerkleBranch(txs2[i], i, pair.first);
            if (calculatedRoot != expectedRoot)
                throw Exception("Calculated merkle root does not match expected value!");
        }
        Log() << "merkle root verified ok " << txs2.size() << " times";
    }
    void bench() {
        const size_t num = 64000;
        Log() << "Testing performance, filling " << num << " hashes and computing merkle...";
        // next, test perfromance
        Merkle::HashVec txs(num);
        for (size_t i = 0; i < txs.size(); ++i) {
            QByteArray & ba = txs[i];
            ba.resize(HashLen);
            QRandomGenerator::securelySeeded().fillRange(reinterpret_cast<uint32_t *>(ba.data()), HashLen/sizeof(uint32_t));
        }
        const Tic t0;
        auto pair2 = Merkle::branchAndRoot(txs, 0);
        Log() << "Merkle took: " << t0.msecStr(4) << " msec";
    }
    static const auto test_ = App::registerTest("merkle", &test);
    static const auto bench_ = App::registerBench("merkle", &bench);
} // namespace
#endif // ENABLE_TESTS
