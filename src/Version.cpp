#include "Version.h"

#include <QStringList>

// Again, on some Linux setups, sys/sysmacros.h defines these symbols :/
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif


Version::Version(unsigned val, CompactType type)
{
    switch(type) {
    case BitcoinD: {
        // e.g. 0.20.6 comes in like this from bitcoind (as an unsigned int): 200600
        const unsigned major    = val / 1'000'000,
                       minor0   = val % 1'000'000,
                       minor    = minor0 / 10'000,
                       revision = (minor0 % 10'000) / 100;
        *this = Version(major, minor, revision);
        break;
    }
    /* // this is currently not used because the API will change soon (to the BitcoinD method above)
    case BCHD: {
        // from bchd sources: version = 2 ^ AppMajor*3 ^ AppMinor*5 ^ AppPatch
        // I don't understand that code. So we kind of hack it and this mostly works.
        const unsigned v = val ^ 2; // undo the first 2 ^
        const unsigned patch   = (v & 0x0f) >> 0;
        const unsigned minor   = (((v & 0xf0) >> 4) ^ patch) * 16;
        *this = Version(0, minor, patch);
        break;
    }
    */
    }
}

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

