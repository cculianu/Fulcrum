#include "BTC.h"
#include "bitcoin/base58.h"
#include "bitcoin/hash.h"
#include "Util.h"
#include "bitcoin/crypto/endian.h"
#include "Common.h"
#include <QString>
#include <string.h>
#include <iostream>
#include <QMap>
#include <utility>

#ifdef __clang__
#pragma clang diagnostic push
// we get warnings using bitcoin templates but they compile and work anyway.
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

namespace bitcoin
{
    inline void Endian_Check_In_namespace_bitcoin()
    {
        constexpr uint32_t magicWord = 0x01020304;
        const uint8_t wordBytes[4] = {0x01, 0x02, 0x03, 0x04}; // represent above as big endian
        const uint32_t bytesAsNum = *reinterpret_cast<const uint32_t *>(wordBytes);

        if (magicWord != be32toh(bytesAsNum))
        {
            throw Exception(QString("Program compiled with incorrect WORDS_BIGENDIAN setting.\n\n")
                            + "How to fix this:\n"
                            + " 1. Adjust WORDS_BIGENDIAN in the qmake .pro file to match your architecture.\n"
                            + " 2. Re-run qmake.\n"
                            + " 3. Do a full clean recompile.\n\n");
        }
    }
}

namespace BTC
{
    void CheckBitcoinEndiannessCompiledCorrectly() { bitcoin::Endian_Check_In_namespace_bitcoin(); }

    // Map of Net -> [Map of VerByte -> Kind]
    static QMap<Net, QMap<quint8, Address::Kind> > netVerByteKindMap = {
        { MainNet, { {0, Address::P2PKH },  {5, Address::P2SH} } },
        { TestNet, { {111, Address::P2PKH },{196, Address::P2SH} } },
    };

    /// -- Address --

    Address::Address(const QString &legacyAddress)
    {
        *this = Address::fromString(legacyAddress);
    }

    /*static*/
    Address Address::fromString(const QString &legacyAddress)
    {
        Address a;
        ByteArray dec;
        try {
            if (!bitcoin::DecodeBase58Check(legacyAddress.toUtf8().constData(), dec)) {
                Debug() << __FUNCTION__ << ": got bad address " << legacyAddress;
                return a;
            }
        } catch (const std::runtime_error &e) {
            Error() << "Internal error decoding address " << legacyAddress << ": " << e.what();
            return a;
        }
        a.verByte = dec[0];
        a.h160.resize(int(dec.size()-1));
        memcpy(a.h160.data(), &dec[1], dec.size()-1);
        a.net = BTC::Invalid;
        // figure out the net based on the verbyte, if the verbyte is in our map
        for (auto it = netVerByteKindMap.begin(); it != netVerByteKindMap.end(); ++it) {
            if (it.value().contains(a.verByte))
                a.net = it.key();
        }
        return a;
    }


    bool Address::isValid() const
    {
        return kind() != Invalid;
    }

    Address::Kind Address::kind() const
    {
        // NB: all the isValid() functions eventually end up here.
        if (h160.length() == 20) {
            auto it = netVerByteKindMap.find(net);
            if (it != netVerByteKindMap.end()) {
                auto it2 = it.value().find(verByte);
                if (it2 != it.value().end()) {
                    return it2.value();
                }
            }
        }
        return Invalid;
    }

    ByteArray Address::toScript() const
    {
        ByteArray script;
        using bitcoin::OP_DUP, bitcoin::OP_HASH160, bitcoin::OP_EQUALVERIFY, bitcoin::OP_CHECKSIG, bitcoin::OP_EQUAL;
        if (kind() == P2PKH) { // kind() checks for validity
            script << OP_DUP << OP_HASH160 << Byte(h160.length()) << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
        } else if (kind() == P2SH) {
            script << OP_HASH160 << Byte(h160.length()) << h160 << OP_EQUAL;
        }
        return script;
    }

    bitcoin::CScript Address::toCScript() const
    {
        auto ba = toScript();
        return bitcoin::CScript(ba.begin(), ba.end());
    }

    ByteArray Address::toScriptHash() const
    {
        ByteArray script(toScript()), ret;
        if (!script.isEmpty()) {
            auto hash = bitcoin::HashOnce(script.begin(), script.end());
            ret.insert(ret.end(), hash.begin(), hash.end());
        }
        return ret;
    }

    /// returns the ElectrumX 'scripthash_hex'
    QByteArray Address::toHashX() const
    {
        if (!cachedHashX.isEmpty())
            return cachedHashX;
        QByteArray ret;
        auto script = toScript();
        if (!script.isEmpty()) {
            // Note as a performance tweak here we don't call toScriptHash() as that would do extra copying.
            // Instead, we just reproduce some of its work here.
            bitcoin::uint256 hash = bitcoin::HashOnce(script.begin(), script.end());
            auto str = hash.GetHex(); /// this is reversed hex
            ret = str.c_str();
            cachedHashX = ret;
        }
        return ret;
    }

    /// if isValid, returns the legacy address string, base58 encoded
    QString Address::toString() const {
        QString ret;
        if (isValid()) {
            ByteArray vch = ByteArray({verByte}) + h160;
            auto str = bitcoin::EncodeBase58Check(vch);
            ret = QString::fromUtf8(str.c_str());
        }
        return ret;
    }

    /*static*/
    bool Address::isValid(const QString &legacyAddress, Net net)
    {
        Address a(legacyAddress);
        return a.isValid() && a.net == net;
    }


    /*static*/
    bool Address::test()
    {
        //const char *badAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQQ";
        const char *anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        Address a = anAddress, b; //bad(badAddress);
        b = a;
        Address c(a);
        std::cout << "a < b? " << int(a < b) << std::endl;
        std::cout << "a <= b? " << int(a <= b) << std::endl;
        std::cout << "a == b? " << int(a == b) << std::endl;
        c = b;
        // NOTE: the below tests are unsafe because they access charData() which may not have a nul byte at the end.
        // If this crashes, then modify the code below to read into QStrings or something like that.
        // On my platform it just happened to work and I was testing things quickly so I didn't bother to
        // do the below the correct way.
        std::cout << "Decoded -> VerByte: " << int(a.verByte) <<  "  Hash160 (hex): " << a.h160.toHex().constData() << std::endl;
        ByteArray v = { 'a', ' ', 'b', 'c', 0 };
        ByteArray v2 = "this is a test";
        auto vcat = ByteArray({'a','b','c',' '}) + v2;
        std::vector<Byte> v3(v2); // support construction from ByteArray to vector
        ByteArray v4(v3); // support construction from vector to ByteArray
        std::cout << "Init list test: " << v.charData() << " .length() = " << v.length() << std::endl;
        ByteArray inl("12345");
        std::cout << "Inline string: " << inl.charData() << " .length() = " << inl.length() << std::endl;
        std::cout << "Init string test: " << v2.charData() << " .length() = " << v2.length() << std::endl;
        std::cout << "Chained c'tor string test: " << v4.charData() << std::endl;
        std::cout << "Concat test: " << (vcat + ByteArray({0})).charData() << std::endl;
        std::cout << "Concat test 2: " << ((vcat+"..more stuff")+ByteArray({'z','z','z',0})).charData() << std::endl;
        std::cout << "v < v2 : " << int(v < v2) << std::endl;
        std::cout << "IsValid: " << a.isValid() << " kind: " << a.kind() << std::endl;
        std::cout << "Script Hex of: " << a.toString().toUtf8().constData() << " = " << a.toScript().toQHex().constData() << std::endl;
        std::cout << "Script Hash (Hex) of: " << a.toString().toUtf8().constData() << " = " << a.toScriptHash().toQHex().constData() << std::endl;
        std::cout << "HashX of " << a.toString().toUtf8().constData() << " = " << a.toHashX().constData() << std::endl;
        c = a;
        std::cout << "HashX again " << c.toString().toUtf8().constData() << " = " << c.toHashX().constData() << std::endl;
        std::cout << "c==a : " << int(c==a) << std::endl;
        std::cout << "c==b : " << int(c==b) << " (cached?,cached?): (" << int(!c.cachedHashX.isEmpty()) << "," << int(!b.cachedHashX.isEmpty()) << ")" << std::endl;
        //std::cout << "Testnet: " << a.toString().toUtf8().constData() << std::endl;
        return a.isValid() && a.toString() == anAddress && a == b;
    }

    // -- ByteArray --
    ByteArray::ByteArray() : std::vector<Byte>() {}
    ByteArray::ByteArray(const std::vector<Byte> &b) : std::vector<Byte>(b) {}
    ByteArray::ByteArray(std::vector<Byte> &&o) : std::vector<Byte>(std::move(o)) {}
    ByteArray::ByteArray(const std::initializer_list<Byte> &il) : std::vector<Byte>(il) {}
    ByteArray::ByteArray(const QByteArray &a) { (*this) = a; } // leverage operator=
    ByteArray::ByteArray(const QString &s) { (*this) = s; } // leverage operator=
    static Byte emptyBytes[sizeof(long)] = {0}; ///< C++ init would have been zero anyway. We do it like this to illustrate the point to the casual observer.
    Byte *ByteArray::data()
    {
        if (!empty()) return &(*this)[0];
        return emptyBytes;
    }
    const Byte* ByteArray::constData() const
    {
        if (!empty()) return &(*this)[0];
        return emptyBytes;
    }
    ByteArray ByteArray::operator+(const std::vector<Byte> &b) const
    {
        ByteArray ret(*this);
        ret += b;
        return ret;
    }
    ByteArray ByteArray::operator+(const QByteArray & o) const
    {
        ByteArray ret(*this);
        ret += o;
        return ret;
    }
    ByteArray ByteArray::operator+(const QString &s) const
    {
        ByteArray ret(*this);
        ret += s;
        return ret;
    }
    ByteArray ByteArray::operator+(const std::initializer_list<Byte> &il) const
    {
        ByteArray ret(*this);
        ret += il;
        return ret;
    }
    ByteArray & ByteArray::operator+=(const std::vector<Byte> & b)
    {
        if (!b.empty())
            insert(end(), b.begin(), b.end());
        return *this;
    }
    ByteArray & ByteArray::operator+=(const QByteArray &b)
    {
        if (!b.isEmpty())
            insert(end(), b.begin(), b.end());
        return *this;
    }
    ByteArray & ByteArray::operator+=(const QString &s)
    {
        return (*this) += s.toUtf8();
    }
    ByteArray & ByteArray::operator+=(const std::initializer_list<Byte> &il)
    {
        return (*this) += ByteArray(il);
    }

    ByteArray & ByteArray::operator=(const std::vector<Byte> &a)
    {
        clear();
        return (*this) += a;
    }
    ByteArray & ByteArray::operator=(const QByteArray &a)
    {
        clear();
        return (*this) += a;
    }
    ByteArray & ByteArray::operator=(const QString &a)
    {
        clear();
        return (*this) += a;
    }
    ByteArray & ByteArray::operator=(const std::initializer_list<Byte> &il)
    {
        clear();
        return *this += il;
    }
    ByteArray::operator QByteArray() const
    {
        QByteArray ret;
        if (!empty())
            ret.append(reinterpret_cast<const char *>(constData()), length());
        return ret;
    }
    ///< append a Byte to this array
    ByteArray & ByteArray::operator<<(Byte b)
    {
        insert(end(), b);
        return *this;
    }

    ByteArray ByteArray::toHex() const
    {
        return ByteArray(toQHex());
    }
    QByteArray ByteArray::toQHex() const
    {
        QByteArray qba = *this;
        return qba.toHex();
    }

    /// UTXO
    QString UTXO::toString() const {
        QString ret;
        if (isValid()) {
            ret = QString("%1:%2").arg(_txid).arg(_n);
        }
        return ret;
    }

    bitcoin::COutPoint UTXO::toCOutPoint() const
    {
        return bitcoin::COutPoint(toString());
    }

    /// will only accept if the hash is valid hex, otherwise will leave this class in "Invalid" state
    UTXO & UTXO::setCheck(const QString &prevoutHash, quint32 n)
    {
        bitcoin::uint256 h;
        QString trimd(prevoutHash.trimmed());
        h.SetHex(trimd.toUtf8());
        if (h.GetHex() == trimd.toStdString()) {
            _txid = trimd;
            _n = n;
        } else
            clear();
        return *this;
    }
    UTXO & UTXO::setCheck(const QString &prevoutN)
    {
        auto l = prevoutN.split(":");
        bool ok;
        unsigned N = 0;
        if (l.length() == 2 && ((N = l.back().toUInt(&ok)) || ok)) {
            setCheck(l.front(), N);
        } else
            clear();
        return *this;
    }

    /* static */
    void UTXO::test()
    {
        UTXO u("0a4bd:13"), u2;
        u2 = u;
        qInfo("u isValid? %d str=%s", int(u.isValid()), Q2C(u.toString()));
        u = "f6b0fc46aa9abb446b3817f9f5898f45233b274692d110203e2fe38c2f9e9ee3:56";
        qInfo("u isValid? %d str=%s", int(u.isValid()), Q2C(u.toString()));
        auto outpt = u.toCOutPoint();
        qInfo("U hex:%s N:%u", outpt.GetTxId().ToString().c_str(), outpt.GetN());
        u2 = u;
        qInfo("u == u2 ? %d", int(u == u2));
        u2.setCheck(u.txid(), u.n()+4);
        qInfo("u2: %s ... u == u2 ? %d  u < u2 ? %d  u <= u2 ? %d", Q2C(u2.toString()), int(u == u2), int(u < u2), int(u <= u2));
        qInfo("u: %s ... u == u2 ? %d  u2 < u ? %d", Q2C(u.toString()), int(u == u2), int(u2 < u));
    }

    quint64 MakeUnsignedTransaction(bitcoin::CMutableTransaction & tx,
                                    const QList<UTXO> & inputs, const QList<QPair<Address, quint64> > & outputs,
                                    quint32 nLockTime)
    {
        quint64 ret = 0;
        static const auto clearTx = [](bitcoin::CMutableTransaction & tx, int resrv_in = 0, int resrv_out = 0) {
            tx.vin.clear();
            tx.vout.clear();
            tx.nVersion = bitcoin::CTransaction::CURRENT_VERSION;
            tx.nLockTime = 0;
            if (resrv_in >= 0) tx.vin.reserve(size_t(resrv_in));
            if (resrv_out >= 0) tx.vout.reserve(size_t(resrv_out));
        };
        clearTx(tx, inputs.size(), outputs.size());
        tx.nLockTime = nLockTime;
        try {
            int n = 0;
            for (const auto & utxo : inputs) {
                tx.vin.emplace_back(bitcoin::CTxIn(utxo.toCOutPoint()));
                if (!utxo.isValid())
                    throw Exception(QString("Bad utxo specified in tx for input: %1").arg(n));
                ++n;
            }
            if (!n) throw Exception("No inputs specified for tx");
            n = 0;
            for (const auto & adrAmt : outputs) {
                auto & addr = adrAmt.first;
                const auto amt = int64_t(adrAmt.second)*bitcoin::SATOSHI;
                constexpr auto DUST_THRESHOLD = 546*bitcoin::SATOSHI;
                if (!addr.isValid())
                    throw Exception(QString("Bad address specified in tx for output %1").arg(n));
                if (amt < DUST_THRESHOLD)
                    throw Exception(QString("Bad amount specified in tx for output %1: %2 < %3").arg(n).arg(amt.ToString().c_str()).arg(DUST_THRESHOLD.ToString().c_str()));
                ret += adrAmt.second;
                tx.vout.emplace_back(bitcoin::CTxOut(amt, addr.toCScript()));
                ++n;
            }
            if (!n) throw Exception("No outputs specified for tx");
        } catch (const std::exception & e) {
            Warning() << e.what();
            clearTx(tx);
            ret = 0;
        }
        return ret;
    }


} // end namespace BTC

#ifdef __clang__
#pragma clang diagnostic pop
#endif
