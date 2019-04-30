#ifndef BTC_H
#define BTC_H

#include <QByteArray>
#include <QString>
#include <vector>
#include "BTC_OpCodes.h"

namespace BTC
{
    enum Net {
        Invalid = 0,
        MainNet = 0x80,
        TestNet = 0xef
    };

    /// Helper class to glue QByteArray (which is very fast and efficient due to copy-on-write)
    /// to bitcoin's std::vector usage.
    /// This class also allows expressions like: ByteArray a = { opcode1, opcode2 } + somebytearray + { moreopcodes };
    /// Or: byteArray << OP_CODE1 << OP_CODE2 << someVal << etc...
    /// NB: Do not use this to operate on C strings as they may not always be nul terminated. For that,
    /// use QByteArray or QString.
    typedef unsigned char Byte;
    struct ByteArray : public std::vector<Byte>
    {
        ByteArray();
        ByteArray(const std::vector<Byte> &);
        ByteArray(std::vector<Byte> &&);
        // TO DO: see about removing some of this boilerplate using either C++ subtleties or templates.
        ByteArray(const QByteArray &);
        ByteArray(const QString &);
        ByteArray(const char *s) { *this = s; } ///< Note: the nul byte is NOT copied into the buffer.
        ByteArray(const std::initializer_list<Byte> &);

        ByteArray toHex() const; ///< returns Hex encoded (non-reversed)
        QByteArray toQHex() const; ///< returns Hex encoded (non-reversed)
        QString toHexStr() const { return QString(toQHex()); } ///< returns Hex encoded (non-reversed)

        /// Convenienct to obtain a pointer to [0]. If not empty, points to the same
        /// place as .begin().  If empty, will return a pointer to a static buffer
        /// with a 0 in it. Thus, a valid pointer is always returned.
        /// As such, don't rely on this to always == .begin() (it won't if empty)
        Byte *data(); ///< unsafe.
        const Byte* constData() const; ///< same notes as .data()

        /// convenience interop -- note that there may not be a nul byte at the end!
        char *charData() { return reinterpret_cast<char *>(data()); }
        /// convenience interop -- note that there may not be a nul byte at the end!
        const char *constCharData() const { return reinterpret_cast<const char *>(constData()); }

        // compat with Qt's int lengths
        int length() const { return int(size()); }
        // compat with QByteArray
        bool isEmpty() const { return empty(); }

        // TO DO: see about removing some of this boilerplate using either C++ subtleties or templates.
        ByteArray operator+(const std::vector<Byte> & o) const;
        ByteArray operator+(const QByteArray & o) const;
        ByteArray operator+(const QString &) const;
        ByteArray operator+(const char *s) const { return *this + QByteArray(s); }
        ByteArray operator+(const std::initializer_list<Byte> &) const;
        ByteArray & operator+=(const std::vector<Byte> & b);
        ByteArray & operator+=(const QByteArray &);
        ByteArray & operator+=(const QString &);
        ByteArray & operator+=(const std::initializer_list<Byte> &);
        ByteArray & operator+=(const char *s) { return *this += QByteArray(s); } ///< C-string terminating nul byte is NOT copied into the buffer!
        ByteArray & operator=(const std::vector<Byte> &o);
        ByteArray & operator=(const QByteArray &);
        ByteArray & operator=(const QString &);
        ByteArray & operator=(const std::initializer_list<Byte> &);
        ByteArray & operator=(const char *s) { return *this = QByteArray(s); }
        template <typename T>
        ByteArray & operator<<(const T &t) { return (*this) += t; }
        ByteArray & operator<<(OpCode c) { return (*this) << Byte(c); } ///< append an op-code to this array
        ByteArray & operator<<(Byte c); ///< append any byte to this array
        operator QByteArray() const; ///< convenienct cast to QByteArray. Involves a full copy.
    };


    struct Address
    {
        enum Kind {
            Invalid = 0, P2PKH = 1, P2SH = 2
        };

        Address() {}
        Address(const QString &legacyAddress);
        Address(const char *legacy) { *this = legacy; }
        Address(const QByteArray &legacy) { *this = legacy; }

        QByteArray hash160() const { return h160; }

        Kind kind() const;

        bool isTestNet() const { return net == TestNet; }

        bool isValid() const;


        /// Returns the ElectrumX 'scripthash', bitcoin hex encoded.
        /// (Which is reversed because of bitcoin's way of encoding hex).
        /// The results of this function get cached.
        QByteArray toHashX() const;

        /// Returns the bitcoin script bytes as would be used in a spending transaction.
        /// (not reversed)
        /// The results of this function do not get cached.
        /// Note the return is a ByteArray and not a QByteArray.
        ByteArray toScript() const;
        /// Returns the bitcoin script bytes as would be used in a spending transaction,
        /// hashed once with sha256. (not reversed)
        /// The results of this function do not get cached
        /// Note the return is a ByteArray and not a QByteArray.
        ByteArray toScriptHash() const;

        /// If isValid, returns the legacy address string, base58 encoded
        /// Returns null string on error.
        QString toString() const;

        /// test any string to see if it's a valid address for the specified network
        static bool isValid(const QString &legacyAddress, Net = MainNet);

        Address & operator=(const QString &legacy) { return (*this = Address::fromString(legacy)); }
        Address & operator=(const char *legacy) { return (*this = QString(legacy)); }
        Address & operator=(const QByteArray &legacy) { return (*this = QString(legacy)); }

        bool operator==(const Address & o) { return verByte == o.verByte && h160 == o.h160 && net == o.net; }
        /// less operator: for map support and also so that it sorts like the text address would.
        bool operator<(const Address & o) { return verByte < o.verByte && h160 < o.h160 && net < o.net; }

    private:
        Net net = BTC::Invalid;
        quint8 verByte = 99;
        QByteArray h160;
        mutable QByteArray cachedHashX;
        static Address fromString(const QString &legacy);
    public:
        static bool test();
    };

} // end namespace

#endif // BTC_H
