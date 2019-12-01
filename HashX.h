#ifndef HASHX_H
#define HASHX_H

#include "bitcoin/script.h"

#include <QByteArray>

/// "HashX" (ElectrumX/ElectronX style hash) which is a sha256 hash, done once, and "pre-reversed"
/// (that is, ready to be converted to hex for transmission directly as-is).
/// We inherit from QByteArray so as to benefit from its implicit sharing and other untility functions.
struct HashX : public QByteArray {
    // inherit c'tors
    using QByteArray::QByteArray;
    /// construct from a CScript by taking the 32-byte *reversed* sha256 once of the CScript data.
    HashX(const bitcoin::CScript &);

    static HashX fromCScript(const bitcoin::CScript &);
    /// Faster fromHex() which should be used only when you are sure the incoming data is definitely hex.
    /// (calls Util::ParseHexFast())
    static HashX fromHexFast(const QByteArray &definitelyHexData);

    // shadows QByteArray::toHex().  We have a faster implementation we use (calls Util::ToHexFast())
    QByteArray toHex() const;

    HashX & operator=(const bitcoin::CScript &);

    /// we had to explicitly redefine this because 'using' it created some compile errors about ambiguous
    /// overloads (likely there are some private methods we inadvertently brought in?)
    bool operator==(const HashX &o) const;


    // inherit operators
    using QByteArray::operator<;
    using QByteArray::operator=;
    using QByteArray::operator>;
    using QByteArray::operator<=;
    using QByteArray::operator>=;
    using QByteArray::operator[];
    using QByteArray::operator!=;

    // remote + and += as they make no sense for us.
    QByteArray & operator+=(const QByteArray &) = delete;
    QByteArray & operator+(const QByteArray &) = delete;
};

#endif // HASHX_H
