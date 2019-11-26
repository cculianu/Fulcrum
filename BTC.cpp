#include <QMap>
#include <QString>

#include <algorithm>
#include <iostream>
#include <string.h>
#include <sstream>
#include <utility>

#include "bitcoin/base58.h"
#include "bitcoin/cashaddrenc.h"
#include "bitcoin/crypto/endian.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/hash.h"
#include "bitcoin/interpreter.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/script_error.h"
#include "bitcoin/streams.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin/version.h"

#include "BTC.h"
#include "Common.h"
#include "Util.h"

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
    extern bool TestBase58(bool silent, bool throws);
}

namespace BTC
{
    namespace InitData {
        // setup the global secp verify context at app startup.
        extern bitcoin::ECCVerifyHandle myVerifyHandle;
        bitcoin::ECCVerifyHandle myVerifyHandle; // this singleton object allocates a secp handle. see bitcoin/pubkey.h
    }

    void CheckBitcoinEndiannessAndOtherSanityChecks() {
        bitcoin::Endian_Check_In_namespace_bitcoin();
        if ( ! bitcoin::CSHA256::SelfTest() )
            throw InternalError("sha256 self-test failed. Cannot proceed.");
        Tests::Base58(true, true);
        Debug() << "Using sha256 algorithm: " << bitcoin::SHA256AutoDetect();
    }

    // Map of Net -> [Map of VerByte -> Kind]
    static QMap<Net, QMap<quint8, Address::Kind> > netVerByteKindMap = {
        { MainNet, { {0, Address::P2PKH },  {5, Address::P2SH} } },
        { TestNet, { {111, Address::P2PKH },{196, Address::P2SH} } },
    };

    /// -- Address --

    Address::Address(const QString &legacyOrCash)
    {
        *this = Address::fromString(legacyOrCash);
    }

    /*static*/
    Address Address::fromString(const QString &legacyOrCash)
    {
        static const auto DecodeCash = [] (Address & a, const QString &s) -> bool {
            const auto & ss = s.toStdString();
            auto content = bitcoin::DecodeCashAddrContent(ss, bitcoin::MainNetChainParams.CashAddrPrefix());
            bool isTestnet = false;
            if (content.hash.empty()) {
                // try testnet
                content = bitcoin::DecodeCashAddrContent(ss, bitcoin::TestNetChainParams.CashAddrPrefix());
                isTestnet = !content.hash.empty();
            }
            if (!content.hash.empty()) {
                const auto whichNet = isTestnet ? TestNet : MainNet;
                auto & map = netVerByteKindMap[whichNet];
                if (content.type == bitcoin::PUBKEY_TYPE && !map.isEmpty()) {
                    a.verByte = map.firstKey();
                } else if (content.type == bitcoin::SCRIPT_TYPE && !map.isEmpty()) {
                    a.verByte = map.lastKey();
                } else
                    // Defensive programming.. we should never reach this branch.
                    throw Exception("unknown type or other missing data on cash addr decode attempt");
                a.h160.clear();
                a.h160.insert(0, reinterpret_cast<const char *>(content.hash.data()), int(content.hash.size()));
                a.net = whichNet;
                return true;
            }
            return false;
        };
        Address a;
        ByteArray dec;
        try {
            if (!bitcoin::DecodeBase58Check(legacyOrCash.toUtf8().constData(), dec)) {
                if (!DecodeCash(a, legacyOrCash))
                    Debug() << __FUNCTION__ << ": got bad address " << legacyOrCash;
                return a; // a is either valid or invalid here, depending on return value of DecodeCash in line above.
            }
        } catch (const std::runtime_error &e) {
            Error() << "Internal error decoding address " << legacyOrCash << ": " << e.what();
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

    /* static */
    Address Address::fromPubKey(const Byte *pbegin, const Byte *pend, Net net)
    {
        Address ret;
        const auto hash160 = bitcoin::Hash160(pbegin, pend);
        ret.h160 = QByteArray(reinterpret_cast<const char *>(hash160.begin()), int(hash160.size()));
        ret.verByte = 0;
        ret.net = net;
        if (auto map = netVerByteKindMap.value(net); !map.isEmpty())
            ret.verByte = map.begin().key(); // P2PKH verbyte
        return ret;
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

    QByteArray Address::toScriptHashQ() const
    {
        ByteArray script(toScript());
        QByteArray ret;
        if (!script.isEmpty()) {
            auto hash = bitcoin::HashOnce(script.begin(), script.end());
            ret.insert(0, reinterpret_cast<char *>(hash.begin()), int(hash.end()-hash.begin()));
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
    bool Address::isValid(const QString &legacyOrCashAddress, Net net)
    {
        Address a(legacyOrCashAddress);
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
        std::cout << "Script Hash (Qt, Hex) of: " << a.toString().toUtf8().constData() << " = " << a.toScriptHashQ().toHex().constData() << std::endl;
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
    /* static */
    ByteArray ByteArray::fromHex(const QString &s)
    {
        return ByteArray(bitcoin::ParseHex(s.toUtf8().constData()));
    }
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

    int64_t MakeUnsignedTransaction(bitcoin::CMutableTransaction & tx,
                                    const QList<UTXO> & inputs, const QList<QPair<Address, int64_t> > & outputs,
                                    quint32 nLockTime, int nVersion, quint32 nSequence)
    {
        int64_t ret = 0;
        static const auto clearTx = [nVersion](bitcoin::CMutableTransaction & tx, int resrv_in = 0, int resrv_out = 0) {
            tx.vin.clear();
            tx.vout.clear();
            tx.nVersion = nVersion > 0 ? nVersion : bitcoin::CTransaction::CURRENT_VERSION;
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
                tx.vin.back().nSequence = nSequence;
                if (!utxo.isValid())
                    throw Exception(QString("Bad utxo specified in tx for input: %1").arg(n));
                ++n;
            }
            if (!n) throw Exception("No inputs specified for tx");
            n = 0;
            for (const auto & adrAmt : outputs) {
                auto & addr = adrAmt.first;
                const auto amt = adrAmt.second*bitcoin::SATOSHI;
                constexpr auto DUST_THRESHOLD = int64_t(546)*bitcoin::SATOSHI;
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
        Q_ASSERT(ret >= 0);
        return ret;
    }

    bool VerifyTxSignature(const bitcoin::CMutableTransaction &tx,
                           const ByteArray & sigData, const ByteArray & pubKeyData,
                           uint nInput, int64_t inputValSatoshis,
                           QString *errIn, bitcoin::CScript *scriptSig_out)
    {
        QString dummy, &errStr = (errIn ? *errIn : dummy);
        bitcoin::CScript scriptSig;
        scriptSig << sigData << pubKeyData;
        bitcoin::ScriptError err;
        const auto & scriptPubKey = Address::fromPubKey(pubKeyData).toCScript();
        bool ret = bitcoin::VerifyScript
        (
            scriptSig,
            scriptPubKey,
            bitcoin::SCRIPT_ENABLE_SIGHASH_FORKID
                | bitcoin::SCRIPT_VERIFY_STRICTENC
                | bitcoin::SCRIPT_VERIFY_LOW_S
                | bitcoin::SCRIPT_VERIFY_DERSIG,
            bitcoin::MutableTransactionSignatureChecker(&tx, nInput, inputValSatoshis*bitcoin::SATOSHI),
            &err
        );
        errStr = bitcoin::ScriptErrorString(err);
        if (ret && scriptSig_out)
            // caller wants the valid script, so swap the buffers to provide it
            scriptSig_out->swap(scriptSig);
        return ret;
    }

    namespace Tests {
        void SigCheck()
        {
            using namespace bitcoin;

            static const auto BuildCreditingTransaction =
                    [] (const CScript &scriptPubKey, const Amount nValue) -> CMutableTransaction {
                CMutableTransaction txCredit;
                txCredit.nVersion = 1;
                txCredit.nLockTime = 0;
                txCredit.vin.resize(1);
                txCredit.vout.resize(1);
                txCredit.vin[0].prevout = COutPoint();
                txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
                txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
                txCredit.vout[0].scriptPubKey = scriptPubKey;
                txCredit.vout[0].nValue = nValue;

                return txCredit;
            };

            static const auto BuildSpendingTransaction =
                    [](const CScript &scriptSig, const CMutableTransaction &txCredit) -> CMutableTransaction {
                CMutableTransaction txSpend;
                txSpend.nVersion = 1;
                txSpend.nLockTime = 0;
                txSpend.vin.resize(1);
                txSpend.vout.resize(1);
                txSpend.vin[0].prevout = COutPoint(txCredit.GetId(), 0);
                txSpend.vin[0].scriptSig = scriptSig;
                txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
                txSpend.vout[0].scriptPubKey = CScript();
                txSpend.vout[0].nValue = txCredit.vout[0].nValue;

                return txSpend;
            };
            static const auto VerifyTx =
                    [](const QString & pubKeyHex, const QString &sigHex, int64_t nValue=0, uint32_t flags=0,
                       uint32_t nLockTime=0, uint32_t sequence=CTxIn::SEQUENCE_FINAL, const QString & prevOutOverride = "",
                    const QString & outAddr = "", int64_t spendVal = -1)
            {
                const auto pubKeyData = ByteArray::fromHex(pubKeyHex);
                const auto sigData = ByteArray::fromHex(sigHex);
                Address addr = Address::fromPubKey(pubKeyData);
                CScript scriptSig;
                scriptSig << sigData << pubKeyData;
                auto scriptSigHex = QByteArray(reinterpret_cast<char *>(scriptSig.data()), int(scriptSig.size())).toHex();
                Log() << "Address is: " << addr.toString() << " pubKey: " << pubKeyData.toHex() << " scriptPubKey: " << addr.toScriptHash().toHexStr() << " hash160: " << addr.hash160().toHex() << " scriptSig: " << scriptSigHex;

                ScriptError err;
                auto scriptPubKey = addr.toCScript();
                CMutableTransaction txCredit =
                    BuildCreditingTransaction(scriptPubKey, nValue*SATOSHI);
                CMutableTransaction tx = BuildSpendingTransaction(scriptSig, txCredit);
                CMutableTransaction tx2 = tx;
                tx.nLockTime = nLockTime;
                tx.vin[0].nSequence = sequence;
                if (!prevOutOverride.isEmpty())
                    tx.vin[0].prevout.SetQString(prevOutOverride);
                if (!outAddr.isEmpty())
                    tx.vout[0].scriptPubKey = Address(outAddr).toCScript();
                if (spendVal > 0)
                    tx.vout[0].nValue = spendVal*SATOSHI;
                bool ret = VerifyScript
                        (
                            scriptSig,
                            scriptPubKey,
                            flags,
                            MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue),
                            &err
                        );
                Log() << "Verify: " << int(ret) << " err: " << ScriptErrorString(err);
            };
            VerifyTx("038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508",
                     "304402201e0ec3c6c263f34049c93e0bc646d7287ca2cc6571d658e4e7269daebc96ef35022009841f101e6dcaba8993d0259e5732a871e253be807556bf5618bf0bc3e84af001");
            VerifyTx("0277b926d8fd088be302ed207d7d35ca6e7b78005c415bdf9873b45337939704cd",
                     "30440220757c81c9aea06f19ce8bcf3ca088e28f0659273e8deb6dabc8e7fdeb7d235f6c0220688fa0ba75debf36b1a45a2d10ee18c9f546eb1aa6a8e08d1a96d9c08b95a21c41",
                     1111, SCRIPT_ENABLE_SIGHASH_FORKID|SCRIPT_VERIFY_STRICTENC|SCRIPT_VERIFY_LOW_S, 577472, 4294967294,
                     "4058a690de126e5b696dba53c9e63d0344adf5487ba1e0124322ba2735c74bd1:0",
                     "1Ca1inCimwRhhcpFX84TPRrPQSryTgKW6N", 919);
            CMutableTransaction tx3;
            MakeUnsignedTransaction(
                tx3,
                { UTXO("4058a690de126e5b696dba53c9e63d0344adf5487ba1e0124322ba2735c74bd1:0") },
                { { Address("1Ca1inCimwRhhcpFX84TPRrPQSryTgKW6N"), 919} },
                577472
            );
            QString errStr;
            auto b = VerifyTxSignature(tx3,
                                       ByteArray::fromHex("30440220757c81c9aea06f19ce8bcf3ca088e28f0659273e8deb6dabc8e7fdeb7d235f6c0220688fa0ba75debf36b1a45a2d10ee18c9f546eb1aa6a8e08d1a96d9c08b95a21c41"),
                                       ByteArray::fromHex("0277b926d8fd088be302ed207d7d35ca6e7b78005c415bdf9873b45337939704cd"),
                                       0, 1111, &errStr);
            Log() << "VerifyTxSignature: " << int(b) << " errStr: " << errStr;
        }

        bool Base58(bool silent, bool throws) { return bitcoin::TestBase58(silent, throws); }

        void CashAddr() {
            using namespace bitcoin;
            auto content = DecodeCashAddrContent("bitcoincash:qphaxewltpcd5pcwr074tmrn7ged4h9ayuxp49h7nh","bitcoincash");
            Log() << "Decoded type: " << content.type << ", bytes (hex): " << (content.hash.empty() ? "" :  HexStr(content.hash));
            content = DecodeCashAddrContent("qphaxewltpcd5pcwr074tmrn7ged4h9ayuxp49h7nh","bitcoincash");
            Log() << "Decoded type: " << content.type << ", bytes (hex): " << (content.hash.empty() ? "" :  HexStr(content.hash));
            content = DecodeCashAddrContent("qphaxewltpcd5pcwr074tmrn7ged4h9ayuxp49h7nh","bchtest");
            Log() << "Decoded type: " << content.type << ", bytes (hex): " << (content.hash.empty() ? "" :  HexStr(content.hash));
            Address a("qphaxewltpcd5pcwr074tmrn7ged4h9ayuxp49h7nh");
            Log() << "Address as legacy: " << a.toString();
        }

        void TestBlock()
        {
            /* Bitcoin Block # 100000 with 4 txns in it. Test deserialization of blocks. Works! We commented this
             * out to reduct binary size.. */
            /*
            QByteArray blockHex (
                "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000"
                "006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f33722"
                "1b4d4c86041b0f2b571004010000000100000000000000000000000000000000000000"
                "00000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a"
                "010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7"
                "457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf"
                "84ac000000000100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc007"
                "79ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c2092"
                "75ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055c"
                "f7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a"
                "4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25"
                "f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c3"
                "92ba6013c5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914"
                "d43f2a7ac177da2c2f6b52de3d7c88ac000000000100000001c33ebff2a709f13d9f9a"
                "7569ab16a32786af7d7e2de09265e41c61d078294ecf010000008a4730440220032d30"
                "df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942ae90a3231e0ba333e02203deee806"
                "0fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81e26b4fe014104ae31c31b"
                "f91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0ba403ff96c9dee"
                "b680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420f0000"
                "0000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d2110000"
                "00001976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac00000000010000"
                "00010b6072b386d4a773235237f64c1126ac3b240c84b917a3909ba1c43ded5f51f400"
                "0000008c493046022100bb1ad26df930a51cce110cf44f7a48c3c561fd977500b1ae5d"
                "6b6fd13d0b3f4a022100c5b42951acedff14abba2736fd574bdb465f3e6f8da12e2c53"
                "03954aca7f78f3014104a7135bfe824c97ecc01ec7d7e336185c81e2aa2c41ab175407"
                "c09484ce9694b44953fcb751206564a9c24dd094d42fdbfdd5aad3e063ce6af4cfaaea"
                "4ea14fbbffffffff0140420f00000000001976a91439aa3d569e06a1d7926dc4be1193"
                "c99bf2eb9ee088ac00000000");
            auto bl = DeserializeBlockHex(blockHex);
            Log() << "Decoded block: " << bl.ToString() << " nTxns: " << bl.vtx.size();
            QByteArray ba;
            bitcoin::GenericVectorWriter<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, ba, 0);
            bl.Serialize(vr);
            Log() << "Reserialized is equal: " << (ba.toHex() == blockHex ? "YES" : "NO");
            */
        }

        bool Addr() { return BTC::Address::test(); }

        void HexParsers(const QString &filename)
        {
            const auto varlist = Util::Json::parseFile(filename, false).toList(); // throws on error
            QList<QByteArray> hexList;
            size_t bytes = 0;
            for (const auto & v : varlist) {
                auto ba = v.toByteArray();
                ba = ba.trimmed().simplified();
                if (ba.isEmpty())
                    throw Exception(QString("read an empty bytearray for item %1 -- make sure json has hex strings").arg(hexList.size()));
                if (QByteArray::fromHex(ba).toHex() != ba)
                    throw Exception(QString("read bad hex data at %1: %2").arg(hexList.count()).arg(v.toString()));
                bytes += size_t(ba.size());
                hexList.push_back(ba);
            }
            Log() << "Read " << bytes << " hex-digits in " << hexList.count() << " bytearrays...";
            using BVec = std::vector<QByteArray>;
            BVec vec1, vec2;
            using UVec = std::vector<std::vector<uint8_t>>;
            UVec vec3;
            vec1.reserve(size_t(hexList.size()));
            vec2.reserve(size_t(hexList.size()));
            vec3.reserve(size_t(hexList.size()));
            const auto qtMethod = [&vec1, &hexList, &bytes]() -> qint64 {
                size_t bytes2 = 0;
                Log() << "Parsing hex using Qt's QByteArray::fromHex() ...";
                const auto t0 = Util::getTimeNS();
                for (const auto & hex : hexList) {
                    vec1.emplace_back(QByteArray::fromHex(hex));
                }
                const auto tf = Util::getTimeNS();
                for (const auto & b : vec1)
                    bytes2 += size_t(b.size());
                if (bytes2 * 2 != bytes)
                    throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
                const auto micros = qint64((tf-t0)/1000LL);
                Log() << "Qt method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
                return micros;
            };
            const auto customMethod = [&vec2, &hexList, &bytes]() -> qint64 {
                size_t bytes2 = 0;
                Log() << "Parsing hex using custom parseHex() ...";
                const auto t0 = Util::getTimeNS();
                for (const auto & hex : hexList) {
                    vec2.emplace_back(Util::ParseHexFast(hex));
                }
                const auto tf = Util::getTimeNS();
                for (const auto & b : vec2)
                    bytes2 += size_t(b.size());
                if (bytes2 * 2 != bytes)
                    throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
                const auto micros = qint64((tf-t0)/1000LL);
                Log() << "Custom method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
                return micros;
            };
            const auto abcMethod = [&vec3, &hexList, &bytes]() -> qint64 {
                size_t bytes2 = 0;
                Log() << "Parsing hex using bitcoin::ParseHex() from bitcoin-abc ...";
                const auto t0 = Util::getTimeNS();
                for (const auto & hex : hexList) {
                    vec3.emplace_back(bitcoin::ParseHex(hex.constData()));
                }
                const auto tf = Util::getTimeNS();
                for (const auto & b : vec3)
                    bytes2 += size_t(b.size());
                if (bytes2 * 2 != bytes)
                    throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
                const auto micros = qint64((tf-t0)/1000LL);
                Log() << "abc method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
                return micros;
            };
            qtMethod();
            customMethod();
            abcMethod();
            if (vec1 == vec2)
                Log() << "The first two resulting vectors match perfectly";
            else
                throw Exception("The first two vectors don't match!");
            if (vec3.size() != vec2.size())
                throw Exception("The abc method vector is of the wrong size");
            for (size_t i = 0; i < vec3.size(); ++i) {
                if (std::memcmp(vec3[i].data(), vec2[i].data(), vec3[i].size()) != 0)
                    throw Exception(QString("The abc method hex string %1 does not match").arg(i));
            }
            Log() << "The abc method data matches the other two data sets ok";

            Log() << "Checking ToHexFast vs. Qt ...";
            for (const auto & ba : vec1) {
                if (Util::ToHexFast(ba) != ba.toHex())
                    throw Exception("ToHexFast and Qt toHex produced different hex strings!");
            }
            BVec res; res.reserve(vec1.size());
            auto t0 = Util::getTimeNS();
            for (const auto & ba : vec1) {
                res.emplace_back(Util::ToHexFast(ba));
            }
            auto elapsed = (Util::getTimeNS() - t0)/1000LL;
            Log() << "Util::ToHexFast took: " << elapsed << " usec";
            res.clear(); res.reserve(vec1.size());
            t0 = Util::getTimeNS();
            for (const auto & ba : vec1) {
                res.emplace_back(ba.toHex());
            }
            elapsed = (Util::getTimeNS() - t0)/1000LL;
            Log() << "Qt toHex took: " << elapsed << " usec";
        }

    } // end namespace Tests

    // BLOCK deser
    bitcoin::CBlock DeserializeBlockHexStr(const QString &hex) { return DeserializeBlockHex(hex.toUtf8()); }
    bitcoin::CBlock DeserializeBlockHex(const QByteArray &hex)
    {
        return DeserializeBlock(QByteArray::fromHex(hex));
    }
    bitcoin::CBlock DeserializeBlock(const QByteArray &bytes)
    {
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, 0);
        bitcoin::CBlock bl;
        bl.Unserialize(vr);
        return bl;
    }
    bitcoin::CBlock DeserializeBlock(const std::vector<uint8_t> &bytes, size_t pos)
    {
        bitcoin::VectorReader vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, pos);
        bitcoin::CBlock bl;
        bl.Unserialize(vr);
        return bl;
    }

    // HEADER deser
    bitcoin::CBlockHeader DeserializeHeaderHexStr(const QString &hex) { return DeserializeHeaderHex(hex.toUtf8()); }
    bitcoin::CBlockHeader DeserializeHeaderHex(const QByteArray &hex)
    {
        return DeserializeHeader(QByteArray::fromHex(hex));
    }
    bitcoin::CBlockHeader DeserializeHeader(const QByteArray &bytes)
    {
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, 0);
        bitcoin::CBlockHeader bh;
        bh.Unserialize(vr);
        return bh;
    }
    bitcoin::CBlockHeader DeserializeHeader(const std::vector<uint8_t> &bytes, size_t pos)
    {
        bitcoin::VectorReader vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, pos);
        bitcoin::CBlockHeader bh;
        bh.Unserialize(vr);
        return bh;
    }

    // TX deser
    bitcoin::CTransaction DeserializeTxHexStr(const QString &hex) { return DeserializeTxHex(hex.toUtf8()); }
    bitcoin::CTransaction DeserializeTxHex(const QByteArray &hex)
    {
        return DeserializeTx(QByteArray::fromHex(hex));
    }
    bitcoin::CTransaction DeserializeTx(const QByteArray &bytes)
    {
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, 0);
        return bitcoin::CTransaction(bitcoin::deserialize, vr);
    }
    bitcoin::CTransaction DeserializeTx(const std::vector<uint8_t> &bytes, size_t pos)
    {
        bitcoin::VectorReader vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, pos);
        return bitcoin::CTransaction(bitcoin::deserialize, vr);
    }

    /// Helper -- returns the size of a block header. Should always be 80.
    size_t GetBlockHeaderSize()
    {
        static std::atomic<size_t> sz = 0;
        if (!sz) {
            bitcoin::CSizeComputer comp(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION);
            bitcoin::CBlockHeader h;
            h.Serialize(comp);
            sz = comp.size();
        }
        return sz;
    }

    QByteArray Hash(const QByteArray &b, bool once)
    {
        bitcoin::CHash256 h(once);
        QByteArray ret(int(h.OUTPUT_SIZE), Qt::Initialization::Uninitialized);
        h.Write(reinterpret_cast<const uint8_t *>(b.constData()), size_t(b.length()));
        h.Finalize(reinterpret_cast<uint8_t *>(ret.data()));
        return ret;
    }

    QByteArray HashRev(const QByteArray &b, bool once)
    {
        QByteArray ret = Hash(b, once);
        std::reverse(std::begin(ret), std::end(ret));
        return ret;
    }

    QByteArray Hash160(const QByteArray &b) {
        bitcoin::CHash160 h;
        QByteArray ret(int(h.OUTPUT_SIZE), Qt::Initialization::Uninitialized);
        h.Write(reinterpret_cast<const uint8_t *>(b.constData()), size_t(b.length()));
        h.Finalize(reinterpret_cast<uint8_t *>(ret.data()));
        return ret;
    }

} // end namespace BTC

#ifdef __clang__
#pragma clang diagnostic pop
#endif
