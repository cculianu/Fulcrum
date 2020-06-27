//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
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
#include "BTC_unused.h"
#include "Common.h"
#include "Util.h"

#include "bitcoin/base58.h"
#include "bitcoin/cashaddrenc.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/interpreter.h"
#include "bitcoin/script.h"
#include "bitcoin/script_error.h"
#include "bitcoin/utilstrencodings.h"

#include <QHash>

#include <iostream>


#ifdef __clang__
#pragma clang diagnostic push
// we get warnings using bitcoin templates but they compile and work anyway.
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

namespace BTC {
    namespace InitData {
        // setup the global secp verify context at app startup.
        extern bitcoin::ECCVerifyHandle myVerifyHandle;
        bitcoin::ECCVerifyHandle myVerifyHandle; // this singleton object allocates a secp handle. see bitcoin/pubkey.h
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

    } // end namespace Tests
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif
