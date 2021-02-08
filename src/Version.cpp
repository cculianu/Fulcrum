#include "Version.h"

#include <QStringList>

// Again, on some Linux setups, sys/sysmacros.h defines these symbols :/
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif


Version::Version(BitcoinDCompact valIn) noexcept
{
    const unsigned val = static_cast<unsigned>(valIn);
    // e.g. 0.20.6 comes in like this from bitcoind (as an unsigned int): 200600
    major = val / 1'000'000u;
    minor = (val / 10'000u) % 100u;
    revision = (val / 100u) % 100u;
}

unsigned Version::toCompact() const noexcept { return 1'000'000u * major + 10'000u * minor + 100u * revision; }

/*
Version::Version(BCHDCompact valIn) noexcept
{
    const unsigned val = static_cast<unsigned>(valIn);
    // from bchd sources: version = 2 ^ AppMajor*3 ^ AppMinor*5 ^ AppPatch
    // I don't understand that code. So we kind of hack it and this mostly works.
    const unsigned v = val ^ 2; // undo the first 2 ^
    const unsigned patch   = (v & 0x0f) >> 0;
    const unsigned minor   = (((v & 0xf0) >> 4) ^ patch) * 16;
    *this = Version(0, minor, patch);
}
*/

QString Version::toString(bool revZeroOk) const
{
    return QStringLiteral("%1.%2%3").arg(major).arg(minor).arg( revision || revZeroOk ? QStringLiteral(".%1").arg(revision) : QString() );
}

Version::Version(const QString &s_)
{
    QString s(s_.trimmed());
    if (auto pos = s.indexOf('/'); pos >= 0) {
        // trim everything up to and including the first '/' seen -- such that "MyClient/1.0" -> "1.0"
        s = s.mid(pos+1);
    }
    if (s.startsWith('v', Qt::CaseInsensitive))
        s = s.mid(1); // remove leading 'v' char
    const auto sl = s.split('.').mid(0, 3); // take the first 3 elements of whatever list was generated
    bool ok = false;
    if (sl.length() >= 1) {
        major = sl.at(0).trimmed().toUInt(&ok);
        if (!ok)
            major = 0;
        else if (sl.length() >= 2) {
            minor = sl.at(1).trimmed().toUInt(&ok);
            if (!ok)
                minor = 0;
            else if (sl.length() >= 3) {
                const QRegExp nonNumericRE("[^0-9]");
                QString s2 = sl.at(2).trimmed();
                if (int pos = s2.indexOf(nonNumericRE); pos > -1)
                    // only take the numeric part of the string eg 3.3."4CS" -> 3.3."4"
                    s2 = s2.left(pos);
                revision = s2.toUInt(&ok);
                if (!ok)
                    revision = 0;
            }
        }
    }
}

#ifdef ENABLE_TESTS
#include "App.h"
#include <algorithm>
#include <vector>

namespace {
    void testVersion()
    {
        unsigned nChk = 0;
        const auto Chk = [&](const char * const strexp, bool exp) {
            if (exp) {
                ++nChk;
                Debug() << "Passed: " << strexp;
            }  else
                throw Exception(QString("Check failed: %1").arg(strexp));
        };
        auto CHK_EQ = [&](auto && a, auto && b) {
            if (a == b) {
                ++nChk;
                Debug() << "Passed: " << a << " == " << b;
            } else
                throw Exception(QString("Check failed: %1 != %2").arg(a).arg(b));
        };
#       define CHK(exp) Chk( #exp, bool(exp))

        using StrTup = std::tuple<QString, QString, QString, unsigned>;
        std::vector<StrTup> strChecks = {
            { "0", "0.0", "0.0.0", 0u },
            { "2", "2.0", "2.0.0", 2000000u },
            { "3", "3.0", "3.0.0", 3000000u },
            { "4", "4.0", "4.0.0", 4000000u },
            { "5", "5.0", "5.0.0", 5000000u },
            { "763", "763.0", "763.0.0", 763000000u },
            { "1.0", "1.0", "1.0.0", 1000000u },
            { "2.0", "2.0", "2.0.0", 2000000u },
            { "19", "19.0", "19.0.0", 19000000u },
            { "0.0.7", "0.0.7", "0.0.7", 700u },
            { "3.22.83", "3.22.83", "3.22.83", 3228300u },
            { "3.22.83.1", "3.22.83", "3.22.83", 3228300u },
            { "0cs", "0.0", "0.0.0", 0u },
            { "1.0junk", "1.0", "1.0.0", 1000000u },
            { "trask/6.2.1junk", "6.2.1", "6.2.1", 6020100u  },
            { "19/junk", "0.0", "0.0.0", 0u },
            { "19.0sadakjla123abc", "19.0", "19.0.0", 19000000u },
            { "    electrum/0.0.7.1cs has space   ", "0.0.7", "0.0.7", 700u },
            { "1.2.3/fulctum/3.22.8.13Trash", "0.0", "0.0.0", 0u },
            { "1.2.3fulctum/3.22.8.13Trash", "3.22.8", "3.22.8", 3220800u },
            { "/a1.2bc444/7.69.22.5ignoreme", "0.0", "0.0.0", 0u },
            { "a1.2bc444/7.69.22.5ignoreme   ", "7.69.22", "7.69.22", 7692200u },
            { "/a/1.2/b/c/444/7.69.22.5ignoreme/heh", "0.0", "0.0.0", 0u },
        };
        std::vector<Version> vers;

        for (const auto & [inp, vstr1, vstr2, num] : strChecks) {
            const Version ver(inp);
            CHK_EQ(ver.toString(), vstr1);
            CHK_EQ(ver.toString(true), vstr2);
            CHK_EQ(ver.toString(true), Version(Version::BitcoinDCompact(num)).toString(true));
            // test implicit conversion
            CHK(Version(Version::BitcoinDCompact(num)) == Version::BitcoinDCompact(num));
            const Version v2 = Version::BitcoinDCompact(ver.toCompact());
            CHK(v2 == ver);
            // test operators
            CHK(ver < Version::BitcoinDCompact(num + 101));
            CHK(Version(Version::BitcoinDCompact(num + 203) )> ver);
            CHK(ver == Version(Version::BitcoinDCompact(num)));
            CHK(ver == Version::BitcoinDCompact(Version(Version::BitcoinDCompact(num)).toCompact())); // round trip to compact and back
            CHK(ver >= Version::BitcoinDCompact(num));
            if (num > 100) CHK(ver > Version::BitcoinDCompact(num - 100));
            CHK(ver <= Version::BitcoinDCompact(num + 2000000));
            // check .isValid
            CHK(ver.isValid() == bool(num));
            // check .toCompact
            CHK(ver.toCompact() == num);
            vers.push_back(ver);
        }
        CHK(Version("1.2.0.1") == Version("1.2"));
        CHK(Version("17.2.0.1") >= Version("1.2"));
        CHK(Version("0.0.0.1") == Version("0"));
        CHK(Version("0.1.0.1") > Version("0.0.1"));
        CHK(Version("10.1.0.1") != Version("3.10.1"));
        Version v;
        CHK((v = Version("electrum/3.3.8-beta")) == QString("electron-cash/3.3.8.1CS") && v.isValid());

        v = Version("overflow/23.201.76ggg");
        CHK_EQ(v.toString(), "23.201.76");
        // however, the compact repr can't represent the above
        CHK(Version("23.201.76") != Version::BitcoinDCompact(v.toCompact()));
        // test the toCompact overflow
        CHK(Version("23.201.76.1").toCompact() == 25017600u);
        // once more for sanity
        CHK(Version("23.201.76.1") == Version(23, 201, 76));

        // more operator checks
        std::sort(vers.begin(), vers.end());
        Version prev;
        for (const auto &ver : vers) {
            CHK(prev <= ver);
            if (prev != ver) CHK(ver > prev);
            prev = ver;
        }

        Log() << nChk << " checks passed ok";
#       undef CHK
    }

    const auto t1 = App::registerTest("version", testVersion);
} // namespace
#endif
