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
#include "BTC.h"
#include "BTC_Address.h"
#include "Common.h"
#include "Util.h"

#include "bitcoin/base58.h"
#include "bitcoin/cashaddrenc.h"
#include "bitcoin/script.h"

#include <QHash>
#include <QHashFunctions>

#ifdef QT_DEBUG
#include <QRandomGenerator>
#include <thread>
#include <iostream>
#endif

namespace BTC
{
    inline uint qHash(BTC::Net n, uint seed = 0) noexcept { return ::qHash(uchar(n), seed); }

    namespace {
        // Hash of Net -> [Hash of VerByte -> Kind]
        const QHash<Net, QHash<quint8, Address::Kind> > netVerByteKindMap = {
            { MainNet, { {0, Address::P2PKH },  {5, Address::P2SH} } },
            { TestNet, { {111, Address::P2PKH },{196, Address::P2SH} } },
            { RegTestNet, { {111, Address::P2PKH },{196, Address::P2SH} } },
        };
        Byte verByteForNetAndKind(Net net, Address::Kind kind) {
            if (const auto map = netVerByteKindMap.value(net); LIKELY(!map.isEmpty())) {
                for (auto it = map.begin(); it != map.end(); ++it) {
                    if (it.value() == kind)
                        return it.key();
                }
            }
            return Address::InvalidVerByte;
        }
        Address::Kind kindForNetAndVerByte(Net net, Byte verByte) {
            if (const auto map = netVerByteKindMap.value(net); LIKELY(!map.isEmpty())) {
                for (auto it = map.begin(); it != map.end(); ++it) {
                    if (it.key() == verByte)
                        return it.value();
                }
            }
            return Address::Kind::Invalid;
        }
        /// NB: This won't ever auto-detect regtest since it has the same verBytes as testnet (111 & 196).  Since
        /// between the two choices, testnet is the much more likely network anybody using this software will be using,
        /// we always return testnet if the verByte matches regtest and/or testnet.
        Net netForVerByte(Byte verByte) {
            for (auto it = netVerByteKindMap.begin(); it != netVerByteKindMap.end(); ++it) {
                const Net net = it.key();
                if (net == RegTestNet)
                    // don't auto-detect regtest net -- skip it.
                    continue;
                if (it.value().contains(verByte))
                    return net;
            }
            return Net::Invalid;
        }
    } // end anon namespace

    /// -- Address --

    /*static*/
    Address Address::fromString(const QString &legacyOrCash)
    {
        static const auto DecodeCash = [] (Address & a, const std::string &ss) -> bool {
            a._net = Net::Invalid;
            auto content = bitcoin::DecodeCashAddrContent(ss, bitcoin::MainNetChainParams.CashAddrPrefix());
            if (!content.hash.empty())
                a._net = Net::MainNet;
            else {
                // try testnet
                content = bitcoin::DecodeCashAddrContent(ss, bitcoin::TestNetChainParams.CashAddrPrefix());
                if (!content.hash.empty()) a._net = TestNet;
                else {
                    // try regtest
                    content = bitcoin::DecodeCashAddrContent(ss, bitcoin::RegTestNetChainParams.CashAddrPrefix());
                    if (!content.hash.empty()) a._net = RegTestNet;
                }
            }
            if (!content.hash.empty() && a._net != Net::Invalid) {
                a._kind = static_cast<Address::Kind>(content.type) /* Our Kind enum intentionally matches content.type's enum for values, so this works*/;
                a.verByte = verByteForNetAndKind(a._net, a._kind);
                if (UNLIKELY(a.verByte == InvalidVerByte))
                    // Defensive programming.. we should never reach this branch.
                    throw Exception("Unknown content.type or other missing data on cash addr decode attempt");
                a.h160.clear();
                a.h160.insert(0, reinterpret_cast<const char *>(content.hash.data()), int(content.hash.size()));
                return a.isValid(); // this is here as a reduntant check -- this should always be true if we get here
            }
            return false;
        };
        Address a;
        std::vector<Byte> dec;
        if (const auto ss = legacyOrCash.toStdString(); bitcoin::DecodeBase58Check(ss, dec)) {
            // Legacy address
            if (dec.size() != 1 + H160Len) {
                // this should never happen
#ifdef QT_DEBUG
                DebugM(__func__, ": bad decoded length  ", dec.size(), " for address ", legacyOrCash);
#endif
            } else {
                a.verByte = dec[0];
                a.h160.resize(int(H160Len));
                std::memcpy(a.h160.data(), &dec[1], H160Len);
                a._net = netForVerByte(a.verByte); // note this will not correctly differntiate between TestNet and RegTestNet and always pick TestNet since they have the same verBytes.
                a.autosetKind(); // this will clear the address if something is wrong
            }
        } else {
            // Cash address
            bool ok = false;
            try {
                if (!(ok = DecodeCash(a, ss))) {
#ifdef QT_DEBUG
                    DebugM(__func__, ": got bad address ", legacyOrCash);
#endif
                }
            } catch (const std::exception &e) {
                Warning() << "Internal error decoding cash address " << legacyOrCash << ": " << e.what();
            }
            if (!ok) a = Address(); // clear it to save memory.
        }
        // if either of the above branches succeeded, a.isValid(), otherwise it will just be a default-constructed address.
        return a;
    }

    /* static */
    Address Address::fromPubKey(const Byte *pbegin, const Byte *pend, Kind k, Net net)
    {
        Address ret;
        if (const auto vb = verByteForNetAndKind(net, k); LIKELY(vb != InvalidVerByte && pend > pbegin)) {
            const auto hash160 = bitcoin::Hash160(pbegin, pend);
            ret.h160 = QByteArray(reinterpret_cast<const char *>(hash160.begin()), int(hash160.size()));
            ret.verByte = vb;
            ret._kind = k;
            ret._net = net;
        }
        return ret;
    }

    // Used internally in one branch when parsing Legacy.  If it fails it will clear the address to default constructed values.
    bool Address::autosetKind()
    {
        if (h160.length() == int(H160Len)) {
            _kind = kindForNetAndVerByte(_net, verByte);
            if (_kind != Kind::Invalid)
                return true;
        }
        // if we get here, there was a problem, so clear to default and return false.
        *this = Address();
        return false;
    }


    bitcoin::CScript Address::toCScript() const
    {
        using namespace bitcoin;
        CScript ret;
        if (h160.length() == int(H160Len)) {
            if (_kind == P2PKH) {
                ret << OP_DUP << OP_HASH160;
                ret.insert(ret.end(), uint8_t(h160.length())); // push length
                ret.insert(ret.end(), reinterpret_cast<const Byte *>(h160.begin()), reinterpret_cast<const Byte *>(h160.end())); // push h160
                ret << OP_EQUALVERIFY << OP_CHECKSIG;
            } else if (_kind == P2SH) {
                ret << OP_HASH160;
                ret.insert(ret.end(), uint8_t(h160.length())); // push length
                ret.insert(ret.end(), reinterpret_cast<const Byte *>(h160.begin()), reinterpret_cast<const Byte *>(h160.end())); // push h160
                ret << OP_EQUAL;
            }
        }
        return ret;
    }

    QByteArray Address::toHashX() const
    {
        const auto cscript = toCScript();
        if (cscript.empty())
            return QByteArray();
        return BTC::HashXFromCScript( cscript );
    }

    /// if isValid:  Returns the legacy address string, base58 encoded if legacy==true,
    ///              otherwise returns the cash address with prefix
    /// if !isValid: Returns the empty string.
    QString Address::toString(bool legacy) const {
        QString ret;
        if (isValid()) {
            if (legacy) {
                std::vector<Byte> vch;
                vch.reserve(1 + size_t(h160.size()));
                vch.push_back(verByte);
                vch.insert(vch.end(), h160.begin(), h160.end());
                ret = QString::fromStdString(bitcoin::EncodeBase58Check(vch));
            } else {
                const std::string *prefix = nullptr;
                switch (_net) {
                case MainNet: prefix = &bitcoin::MainNetChainParams.cashaddrPrefix; break;
                case TestNet: prefix = &bitcoin::TestNetChainParams.cashaddrPrefix; break;
                case RegTestNet: prefix = &bitcoin::RegTestNetChainParams.cashaddrPrefix; break;
                default: break;
                }
                if (prefix) {
                    const std::vector<Byte> content(h160.begin(), h160.end());
                    const auto type = _kind == P2PKH ? bitcoin::PUBKEY_TYPE : bitcoin::SCRIPT_TYPE;
                    ret = QString::fromStdString( bitcoin::EncodeCashAddr(*prefix, { type, content }) );
                }
            }
        }
        return ret;
    }

    QString Address::toShortString() const
    {
        QString s = toString(false);
        if (int colon = s.indexOf(':'); colon > -1)
            s = s.mid(colon+1);
        else
            s.clear();
        return s;
    }

    /*static*/
    bool Address::isValid(const QString &legacyOrCashAddress, Net net)
    {
        Address a(legacyOrCashAddress);
        return a.isValid() && a._net == net;
    }

#ifdef QT_DEBUG
    /*static*/
    bool Address::test()
    {
        std::condition_variable cond;
        std::mutex mut;
        std::atomic_bool start{false};

        const auto Bench = [&cond, &mut, &start](size_t id){
            while (!start) {
                std::unique_lock g(mut);
                if (!start)
                    cond.wait(g);
            }
            constexpr auto MyNet = Net::MainNet;
            constexpr auto MyKind = Kind::P2PKH;
            auto & os = std::cout;
            constexpr size_t count = 1000000;
            os << id << ": Generating " << count << " random pubkeys...\n";
            std::vector<QByteArray> pubkeys(count);
            const auto t0pk = Util::getTimeNS();
            for (size_t i = 0; i < count; ++i) {
                QByteArray & pk = pubkeys[i];
                pk.resize(int(sizeof(quint32)*4));
                QRandomGenerator::global()->fillRange(reinterpret_cast<quint32 *>(pk.data()), pk.size()/int(sizeof(quint32)));
            }
            const auto elapsedpk = Util::getTimeNS() - t0pk;
            os << id << ": Took: " << QString::number(elapsedpk/1e6, 'f', 6).toUtf8().constData() << " msec\n";

            os << "Generating " << count << " legacy address strings ...\n";
            std::vector<QString> legStrings(count);
            const auto t0ls = Util::getTimeNS();
            for (size_t i = 0; i < count; ++i) {
                QByteArray & pk = pubkeys[i];
                QString & leg = legStrings[i];

                const auto a = Address::fromPubKey(pk, MyKind, MyNet);
                leg = a.toLegacyString();
            }
            const auto elapsedls = Util::getTimeNS() - t0ls;
            os << id << ": Took: " << QString::number(elapsedls/1e6, 'f', 6).toUtf8().constData() << " msec\n";
            os << id << ": Last string: " << legStrings.back().toUtf8().constData() << "\n";

            os << id << ": Generating " << count << " cash address strings ...\n";
            std::vector<QString> caStrings(count);
            const auto t0ca = Util::getTimeNS();
            for (size_t i = 0; i < count; ++i) {
                QByteArray & pk = pubkeys[i];
                QString & ca = caStrings[i];

                const auto a = Address::fromPubKey(pk, MyKind, MyNet);
                ca = a.toString();
            }
            const auto elapsedca = Util::getTimeNS() - t0ca;
            os << id << ": Took: " << QString::number(elapsedca/1e6, 'f', 6).toUtf8().constData() << " msec\n";
            os << id << ": Last string: " << caStrings.back().toUtf8().constData() << "\n";

            os << id << ": Parsing " << count << " legacy strings ...\n";
            std::vector<Address> addrsleg(count);
            const auto t0pleg = Util::getTimeNS();
            for (size_t i = 0; i < count; ++i) {
                QString & ls = legStrings[i];
                Address & addr = addrsleg[i];
                addr = Address(ls);
            }
            const auto elapsedpleg = Util::getTimeNS() - t0pleg;
            os << id << ": Took: " << QString::number(elapsedpleg/1e6, 'f', 6).toUtf8().constData() << " msec\n";

            os << id << ": Parsing " << count << " cashaddr strings ...\n";
            std::vector<Address> addrsca(count);
            const auto t0pca = Util::getTimeNS();
            for (size_t i = 0; i < count; ++i) {
                QString & cs = caStrings[i];
                Address & addr = addrsca[i];
                addr = Address(cs);
            }
            const auto elapsedpca = Util::getTimeNS() - t0pca;
            os << id << ": Took: " << QString::number(elapsedpca/1e6, 'f', 6).toUtf8().constData() << " msec\n";

            os << id << ": Ensuring all equal each other ...\n";
            for (size_t i = 0; i < count; ++i) {
                if (addrsleg[i] != addrsca[i] || Address::fromPubKey(pubkeys[i], MyKind, MyNet) != addrsca[i])
                    throw Exception(QString("Address index %1 mistmatch").arg(long(i)));
            }
            os << id << ": All ok!\n\n\n------------------------------------\n";
        };

        const size_t  N = 7;//std::thread::hardware_concurrency() / 2 + 1;
        std::vector<std::thread> threads;
        threads.reserve(N);
        for (size_t i = 0; i < N; ++i) {
            threads.emplace_back(Bench, i);
        }
        std::cout << N << " threads created.. starting them all now!\n";
        mut.lock();
        start = true;
        cond.notify_all();
        mut.unlock();
        for (auto & thr : threads) {
            thr.join();
        }

        constexpr auto badAddress = "1C3SoftYBC2bbDbbDzCadZxDrfbnobEXLBLQZbbD";
        constexpr auto anAddress = "qpu3lsv4uufvzsklf38pfl2wckesyuecxgledta0jl";
        constexpr auto anAddress_leg = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        constexpr auto anAddress2 = "bitcoincash:prnc2exht3zxlrqqcat690tc85cvfuypngh7szx6mk";
        constexpr auto anAddress2_leg = "3NoBpEBHZq6YqwUBdPAMW41w5BTJSC7yuQ";
        constexpr auto reg1 = "mxdxDXaKkdX4vFcMFVZKCcZwTLyykvYXir"; // this is regtest but lacks info on what network it is in verbyte so it will be parsed as testnet because legacy
        constexpr auto reg2 = "bchreg:qzmakj5v6pk8qqf50fv6tc8jc6ew3ldz0vz2n35u44"; // this is regtest and since it's cashaddr will be correctly detected as invalid
        Address a = anAddress, b, bad(badAddress);
        b = a;
        Address c(a);
        std::cout << "a < b? " << int(a < b) << std::endl;
        std::cout << "a <= b? " << int(a <= b) << std::endl;
        std::cout << "a == b? " << int(a == b) << std::endl;
        std::cout << "bad is Valid? " << bad.isValid() << std::endl;
        c = b;

        Address p2sh(anAddress2);
        Address p2sh_leg(anAddress2_leg);

        Address testnet("qq9rw090p2eu9drv6ptztwx4ghpftwfa0gyqvlvx2q");

        std::cout << "p2sh == p2sh_leg? " << int(p2sh == p2sh_leg) << std::endl;
        std::cout << "a == p2sh? " << int(a == p2sh) << std::endl;
        std::cout << "a > p2sh? " << int(a > p2sh) << std::endl;
        std::cout << "a < p2sh? " << int(a < p2sh) << std::endl;
        std::cout << "a >= p2sh? " << int(a >= p2sh) << std::endl;
        std::cout << "a <= p2sh? " << int(a <= p2sh) << std::endl;

        Address last;
        for (const auto & a : { bad, Address{anAddress}, Address{anAddress_leg}, Address{anAddress2}, Address{anAddress2_leg}, testnet, Address{reg1}, Address{reg2}}) {
            std::cout << "------------------------------------" << std::endl;
            std::cout << "Cash address: " << a.toString().toUtf8().constData() << ", legacy: " << a.toLegacyString().toUtf8().constData() << ", short cashaddr: " << a.toShortString().toUtf8().constData() << std::endl;
            std::cout << "Decoded -> VerByte: " << int(a.verByte) <<  "  Hash160 (hex): " << a.h160.toHex().constData() << std::endl;
            std::cout << "IsValid: " << a.isValid() << " Kind: " << a.kind() << " Net: " << NetName(a.net()).toUtf8().constData() << std::endl;
            const auto cscript = a.toCScript();
            std::cout << "Script Hex of: " << a.toString().toUtf8().constData() << " = " << QByteArray(reinterpret_cast<const char *>(&*cscript.begin()), int(cscript.size())).toHex().constData() << std::endl;
            std::cout << "HashX of " << a.toString().toUtf8().constData() << " = " << a.toHashX().toHex().constData() << std::endl;
            c = a;
            std::cout << "HashX again " << c.toString().toUtf8().constData() << " = " << c.toHashX().toHex().constData() << std::endl;
            std::cout << "c==a : " << int(c==a) << "  a==Address()? : " << int(a==Address()) << "  a>Address()?: " << int(a > Address()) << "  a<Address()?: " << int(a < Address()) << std::endl;
            std::cout << "last==a : " << int(last==a) << "  last>a?: " << int(last > a) << "  last<a?: " << int(last < a) << "  last==a?: " << int(last == a) << std::endl;
            last = a;
        }
        return true;
    }
#endif
} // end namespace BTC
