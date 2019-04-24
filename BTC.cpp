#include "BTC.h"
#include "bitcoin/base58.h"
#include "Util.h"
#include <QString>
#include <string.h>
#include <iostream>
#include <QMap>
#include <QSet>
#include <QPair>
namespace BTC
{
    // Map of Net -> [Map of VerByte -> Kind]
    static QMap<Net, QMap<quint8, Address::Kind> > netVerByteKindMap = {
        { MainNet, { {0, Address::P2PKH },  {5, Address::P2SH} } },
        { TestNet, { {111, Address::P2PKH },{196, Address::P2SH} } },
    };


    Address::Address(const QString &legacyAddress)
    {
        *this = Address::fromString(legacyAddress);
    }

    /*static*/
    Address Address::fromString(const QString &legacyAddress)
    {
        Address a;
        std::vector<unsigned char> dec;
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

    /// returns the ElectrumX 'scripthash_hex'
    QByteArray Address::toHashX() const {
        QByteArray ret;
        if (!isValid())
            return ret;
        // TODO: Refactor the below ...
        std::vector<quint8> script, scriptEnd;
        if (kind() == P2PKH) {
            script = {
                OP_DUP, OP_HASH160, quint8(h160.length())
            };
            auto oldsize = script.size();
            script.resize(oldsize + size_t(h160.length()));
            memcpy(&script[oldsize], h160.constData(), size_t(h160.length()));
            scriptEnd = { OP_EQUALVERIFY, OP_CHECKSIG };
            script.insert(script.end(), scriptEnd.begin(), scriptEnd.end());
            bitcoin::uint256 hash = bitcoin::HashOnce(script.begin(), script.end());
            auto str = hash.GetHex();
            ret = str.c_str();
        } else if (kind() == P2SH) {
            script = {
                OP_HASH160, quint8(h160.length())
            };
            auto oldsize = script.size();
            script.resize(oldsize + size_t(h160.length()));
            memcpy(&script[oldsize], h160.constData(), size_t(h160.length()));
            scriptEnd = { OP_EQUAL };
            script.insert(script.end(), scriptEnd.begin(), scriptEnd.end());
            bitcoin::uint256 hash = bitcoin::HashOnce(script.begin(), script.end());
            auto str = hash.GetHex();
            ret = str.c_str();
        }
        return ret;
    }

    /// if isValid, returns the legacy address string, base58 encoded
    QString Address::toString() const {
        QString ret;
        if (isValid()) {
            std::vector<unsigned char> vch;
            vch.resize(size_t(h160.size()+1));
            vch[0] = verByte;
            memcpy(&vch[1], h160.constData(), size_t(h160.size()));
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
        c = b;
        std::cout << "Decoded -> VerByte: " << int(a.verByte) <<  "  Hash160 (hex): " << a.h160.toHex().constData() << std::endl;
        std::vector<char> v = { 'a', ' ', 'b', 'c', 0 };
        std::cout << "Vect: " << (&v[0]) << std::endl;
        std::cout << "IsValid: " << a.isValid() << " kind: " << a.kind() << std::endl;
        std::cout << "HashX of " << a.toString().toUtf8().constData() << " = " << a.toHashX().constData() << std::endl;
        //std::cout << "Testnet: " << a.toString().toUtf8().constData() << std::endl;
        return a.isValid() && a.toString() == anAddress && a == b;
    }
}
