#ifndef BTC_H
#define BTC_H

#include "Util.h"

#include "bitcoin/block.h"
#include "bitcoin/script.h"
#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"
#include "bitcoin/version.h"

#include <QByteArray>
#include <QString>
#include <vector>
#include <QMetaType>
#include <QPair>
#include <QHash>

#include <cassert>
#include <cstring>
#include <type_traits>
#include <utility> // for pair, etc
#include <vector>

namespace BTC
{

    /// Checks that the bitcoin lib has the correct endian settings for this platform. Will throw InternalError on
    /// failure. Also does other sanity checks, as well.
    extern void CheckBitcoinEndiannessAndOtherSanityChecks();

    enum Net {
        Invalid = 0,
        MainNet = 0x80,
        TestNet = 0xef
    };

    using Byte = uint8_t;

    /// Helper class to glue QByteArray (which is very fast and efficient due to copy-on-write)
    /// to bitcoin's std::vector usage.
    /// This class also allows expressions like: ByteArray a = { opcode1, opcode2 } + somebytearray + { moreopcodes };
    /// Or: byteArray << OP_CODE1 << OP_CODE2 << someVal << etc...
    /// NB: Do not use this to operate on C strings as they may not always be nul terminated. For that,
    /// use QByteArray or QString.
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
        static ByteArray fromHex(const QString &); ///< construct from Hex encoded (non-reversed)

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
        ByteArray & operator<<(bitcoin::opcodetype c) { return (*this) << Byte(c); } ///< append an op-code to this array
        ByteArray & operator<<(Byte c); ///< append any byte to this array
        operator QByteArray() const; ///< convenienct cast to QByteArray. Involves a full copy.
    };


    struct Address
    {
        enum Kind {
            Invalid = 0, P2PKH = 1, P2SH = 2
        };

        Address() {}
        /// for the below 3 c'tors, the 'net' is auto-detected based on address.
        Address(const QString &legacyOrCashAddress);
        Address(const char *legacyOrCashAddress) { *this = legacyOrCashAddress; }
        Address(const QByteArray &legacyOrCashAddress) { *this = legacyOrCashAddress; }

    private:
        static Address fromPubKey(const Byte *pbegin, const Byte *pend, Net = MainNet);
        template <typename iter>
        static Address fromPubKey(const iter & begin, const iter & end, Net net = MainNet) { return fromPubKey(reinterpret_cast<const Byte *>(&(*begin)), reinterpret_cast<const Byte *>(&(*end)), net); }
    public:
        static Address fromPubKey(const QByteArray &pubKey, Net net = MainNet) { return fromPubKey(pubKey.begin(), pubKey.end(), net); }
        static Address fromPubKey(const std::vector<Byte> &pubKey, Net net = MainNet) { return fromPubKey(pubKey.begin(), pubKey.end(), net); }

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
        /// Same as toScript(), but returns the data as a CScript object (bitcoin data structure
        /// for use with CTransaction et al in the txOut )
        bitcoin::CScript toCScript() const;
        /// Returns the bitcoin script bytes as would be used in a spending transaction,
        /// hashed once with sha256. (not reversed)
        /// The results of this function do not get cached
        /// Note the return is a ByteArray and not a QByteArray.
        ByteArray toScriptHash() const;
        /// Same as above but returns QByteArray
        QByteArray toScriptHashQ() const;

        /// If isValid, returns the legacy address string, base58 encoded
        /// Returns null string on error.
        QString toString() const;

        /// test any string to see if it's a valid address for the specified network
        static bool isValid(const QString &legacyOrCashAddress, Net = MainNet);

        Address & operator=(const QString &legacyOrCash) { return (*this = Address::fromString(legacyOrCash)); }
        Address & operator=(const char *legacyOrCash) { return (*this = QString(legacyOrCash)); }
        Address & operator=(const QByteArray &legacyOrCash) { return (*this = QString(legacyOrCash)); }

        bool operator==(const Address & o) const { return net == o.net && verByte == o.verByte && h160 == o.h160; }
        bool operator!=(const Address & o) const { return !(*this == o); }
        /// less operator: for map support and also so that it sorts like the text address would.
        bool operator<(const Address & o) const {
            if (isValid() && o.isValid()) {
                if (int cmp = std::memcmp(h160.constData(), o.h160.constData(), size_t(h160.length())); cmp < 0)
                    return true;
                else if (0==cmp)
                    return net < o.net ? true : (net==o.net ? verByte < o.verByte : false);
            }
            return false;
        }
        bool operator<=(const Address & o) const { return *this < o || *this == o; }

    private:
        Net net = BTC::Invalid;
        quint8 verByte = 99;
        QByteArray h160;
        mutable QByteArray cachedHashX;
        static Address fromString(const QString &legacyOrCash);
    public:
        static bool test();
    };

    /// for Qt QSet support of type Address
    inline uint qHash(const Address &key) {
        if (key.isValid())
            return key.hash160().left(8).toUInt(nullptr, 16); // just take the first 4 bytes and convert them to uint
        return 0;
    }

    struct UTXO {
        static constexpr int validTxidLength = (256/8)*2; ///< any txid not of this length (64) is immediately invalid.
        static constexpr quint32 invalidN = 0xffffffff;
    protected:
        /// hex encoded uint256 hash of its tx. (64 characters). Do not set these directly, instead use operator= etc below.
        QString _txid;
        quint32 _n = invalidN;
    public:
        inline const QString & txid() const { return _txid; }
        inline quint32 n() const { return _n; }

        /// construct an invalid utxo
        UTXO() {}
        /// construct a UTXO from a bitcoin::COutPoint
        UTXO(const bitcoin::COutPoint &cop) { *this = cop; }
        /// if hash is not 256 bit encoded hex, will be inValid()
        UTXO(const QString & prevoutHash, quint32 prevoutN) { setCheck(prevoutHash, prevoutN); }
        /// if "hash:N" is not "256 bit encoded hex:UInt", will be inValid()
        UTXO(const QString & prevoutHash_Colon_N) { setCheck(prevoutHash_Colon_N); }

        inline bool isValid() const { return _txid.length() == validTxidLength && _n != invalidN; }
        inline UTXO & clear() { _txid = QString(); _n = invalidN; return *this; }

        /// assign from a bitcoin::COutPoint. Not terribly efficient but fast enough for now.
        inline UTXO & operator=(const bitcoin::COutPoint & c) { return *this = c.ToQString(); }
        /// parses prevouthash:N, if ok, sets class to valid state and saves values, otherwise class becomes invalid.
        inline UTXO & operator=(const QString &prevOutN) { return setCheck(prevOutN); }

        inline bool operator<(const UTXO &b) const {
            if (isValid() && b.isValid()) {
                if (int cmp = _txid.compare(b._txid); cmp < 0)
                    return true;
                else if (0==cmp)
                    return _n < b._n;
                //else ...
            }
            return false;
        }
        inline bool operator<=(const UTXO &b) const { return *this < b || *this == b; }
        inline bool operator==(const UTXO &o) const { return _n == o._n && _txid == o._txid; }
        inline bool operator!=(const UTXO &o) const { return !(*this == o); }

        /// will only accept if the hash is valid hex, otherwise will leave this class in "Invalid" state
        UTXO & setCheck(const QString &prevoutHash, quint32 n);
        UTXO & setCheck(const QString &prevoutHash_Colon_N);

        bitcoin::COutPoint toCOutPoint() const;
        /// convert to prevouthash:N, returns a null string if !isValid()
        QString toString() const;

        static void test();
    };

    /// for Qt QSet support of type UTXO
    inline uint qHash(const UTXO &key, uint seed = 0) {
        if (key.isValid())
            return ::qHash(QPair<quint32, quint32>(key.txid().left(8).toUInt(nullptr, 16) , key.n()), seed);
            //return key.txid().left(8).toUInt(nullptr, 16) + key.n();
        return 0;
    }

    /// Make a bitcoin unsigned tx. Returns the total amount sent (sum of outputs). Note that
    /// no enforcement is done to make sure the tx is sane, so be sure to pass valid UTXO and Address values,
    /// as well as amounts >= 546 sats.  If any of the UTXOs !.isValid or any of the addresses !.isValid,
    /// or any of the outputs are below 546 sats, the resulting tx is empty and 0 is returned.
    extern
    int64_t MakeUnsignedTransaction(bitcoin::CMutableTransaction & tx,
                                    const QList<UTXO> & inputs, const QList<QPair<Address, int64_t> > & outputs,
                                    quint32 nLockTime = 0, ///< nLockTime can by anything in the present or past, but 0 is a good historical default
                                    int nVersion = 1,// nVersion will be set to this. 1=most tx's in the universe 2=some bip68 stuff i don't understand. we'll do nVersion=1 to be compatible with EC
                                    quint32 nSequence = 0xfffffffe);  // Should not be 0xffffffff

    /// Verify a tx signature for a specific input.  Returns true on verification success, false otherwise.
    /// *errorString is set to explain what went wrong (if not nullptr).
    ///
    /// Note the tx's signature script (if any) for the specified input is not at all inspected.
    ///
    /// Instead, a new signature script is constructed from the signature and the
    /// passed-in pubKey.  It is assumed later, after VerifyTxSignature succeeds, that callers of this
    /// function will use the signature that passed to generate a new valid signature script.
    ///
    /// As a convenience, the last parameter, `sigScript_out` may be passed-in to receive the valid
    /// signature script.  (Is only set if this function returns true, however.)
    ///
    /// `nInput` is which input to apply the check to (0, 1, 2, etc), and
    /// `inputValSatoshis` is required; it is the original UTXO value of the coin in question.
    extern
    bool VerifyTxSignature(const bitcoin::CMutableTransaction & tx,
                           const ByteArray & signature, const ByteArray & pubKey,
                           uint nInput, int64_t inputValSatoshis,
                           QString *errorString = nullptr,
                           bitcoin::CScript * scriptSig_out = nullptr);


    /// -- Template Serialization / Deserialization methods to/from QByteArray --

    /// Serialize to a passed-in buffer. from_pos should be the position in the buffer to overwrite the serialized data
    /// into.  Note if from_pos is larger than the buffer, the buffer will be grown to encompass from_pos!
    /// In any case, the buffer will always be grown to accomodate the data if it's not big enough to hold it.
    /// Specify from_pos=-1 for appending at the end.  Returns a reference to the passed-in buffer.  This is very fast
    /// and done in-place.
    template <typename BitcoinObject>
    QByteArray & Serialize(QByteArray &buf, const BitcoinObject &thing, int from_pos = -1)
    {
        if (from_pos < 0) from_pos = buf.size();
        bitcoin::GenericVectorWriter<QByteArray> vw(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, buf, from_pos);
        thing.Serialize(vw);
        return buf;
    }
    /// Convenience for above -- serialize to a new QByteArray directly
    template <typename BitcoinObject>
    QByteArray Serialize(const BitcoinObject &thing)
    {
        QByteArray ret;
        Serialize(ret, thing);
        return ret;
    }
    /// Deserialize to a pre-allocated bitcoin object such as bitcoin::CBlock, bitcoin::CBlockHeader, bitcoin::CMutableTransaction, etc
    template <typename BitcoinObject,
              /// NB: This in-place Deserialization does *NOT* work with CTransaction because if has const-fields. (use the non-in-place specialization instead)
              std::enable_if_t<!std::is_same_v<BitcoinObject, bitcoin::CTransaction>, int> = 0 >
    void Deserialize(BitcoinObject &thing, const QByteArray &bytes, int pos = 0)
    {
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, pos);
        thing.Unserialize(vr);
    }
    /// Convenience for above.  Create an instance of object and deserialize to it
    template <typename BitcoinObject>
    BitcoinObject Deserialize(const QByteArray &bytes, int pos = 0)
    {
        BitcoinObject ret;
        Deserialize(ret, bytes, pos);
        return ret;
    }
    /// Template specialization for CTransaction which has const fields and works a little differently (impl. in BTC.cpp)
    template <> bitcoin::CTransaction Deserialize(const QByteArray &, int pos);

    /// Helper -- returns the size of a block header. Should always be 80.  Returns an internal constant after first call.
    /// (this returns an int because we mostly compare it to QByteArray.size() whose size_type is int)
    extern int GetBlockHeaderSize();

    /// Returns the sha256 double hash (not reveresed) of the input QByteArray. The results are copied once from the
    /// hasher into the returned QByteArray.  This is faster than obtaining a uint256 from bitcoin::Hash then converting
    /// to a QByteArray manually.
    /// Optionally, can hash once (a-la ElectrumX) if once=true
    extern QByteArray Hash(const QByteArray &, bool once = false);
    /// Identical to the above except it returns the REVERSED hash (which is what bitcoind gives you via JSON RPC or
    /// when doing uint256.ToString()).
    extern QByteArray HashRev(const QByteArray &, bool once = false);
    /// Convenient alias for Hash(b, true)
    inline QByteArray HashOnce(const QByteArray &b) { return Hash(b, true); }
    /// Like the Hash() function above, except does hash160 once. (not reversed).
    extern QByteArray Hash160(const QByteArray &);

    /// Takes a hash in bitcoin memory order and returns a deep copy QByteArray of the data, reversed
    /// (this is intended to keep our representation of bitcoin data closer to how we will send it to clients down
    /// the wire -- we send all hex encoded hashes in reverse order as is customary when representing bitcoin
    /// hashes in hex). See BlockProc.cpp for an example of where this is used.
    template <class BitcoinHashT>
    QByteArray Hash2ByteArrayRev(const BitcoinHashT &hash) {
        QByteArray ret(reinterpret_cast<const char *>(hash.begin()), hash.width()); // deep copy
        std::reverse(ret.begin(), ret.end()); // reverse it
        return ret;
    };

    /// returns true iff cscript is OP_RETURN, false otherwise
    inline bool IsOpReturn(const bitcoin::CScript &cs) {
        return cs.size() > 0 && *cs.begin() == bitcoin::opcodetype::OP_RETURN;
    }

    inline QByteArray HashXFromCScript(const bitcoin::CScript &cs) {
        return QByteArray(BTC::HashRev(QByteArray::fromRawData(reinterpret_cast<const char *>(cs.data()), int(cs.size())), true));
    }

    /// Header Chain Verifier -
    /// To use: Basically keep calling operator() on it with subsequent headers and it will make sure
    /// hashPrevBlock of the current header matches the computed hash of the last header.
    /// If that is ever not the case, operator() returns false. Returns true otherwise.
    class HeaderVerifier {
        QByteArray prev; // 80 byte header data or empty
        long prevHeight = -1;

        bool checkInner(long height, const bitcoin::CBlockHeader &, QString *err);
    public:
        HeaderVerifier() = default;
        HeaderVerifier(unsigned fromHeight) : prevHeight(long(fromHeight)-1) {}

        /// keep calling this from a loop. Returns false if current header's hashPrevBlock  != the last header's hash.
        bool operator()(const QByteArray & header, QString *err = nullptr);
        bool operator()(const bitcoin::CBlockHeader & header, QString *err = nullptr);
        /// returns the height, 80 byte header of the last header seen. If no headers seen, returns (-1, Empty QByteArray)
        std::pair<int, QByteArray> lastHeaderProcessed() const;

        bool isValid() const { return prev.length() == GetBlockHeaderSize(); }
        void reset(unsigned nextHeight = 0, QByteArray prevHeader = QByteArray()) { prevHeight = long(nextHeight)-1; prev = prevHeader; }
    };

    /// Trivial hasher for sha256, rmd160, etc hashed byte arrays (for use with std::unordered_map,
    /// std::unordered_set, etc) -- just returns the first 8 bytes reinterpreted as size_t since hashed data is
    /// already randomized.
    template <typename BytesT>
    struct GenericTrivialHashHasher {
        std::size_t operator()(const BytesT &b) const noexcept {
            if (LIKELY(std::size_t(b.size()) >= sizeof(std::size_t))) {
                // common case, just return the first 8 bytes reinterpreted as size_t since this is already
                // a random hash.
                static_assert (std::is_scalar_v<std::remove_pointer_t<decltype (b.begin())>>,
                               "GenericTrivialHasher must be used with a container type where .begin() returns a pointer to its data." );
                return *reinterpret_cast<const std::size_t *>(b.begin());
            }
            return qHash(b, 0xf1234567); // this should not normally be reached.
        }
    };

    // useful type aliases to be passed as template args to eg std::unordered_map, robin_hood::unordered_flat_map, etc
    using QByteArrayHashHasher = GenericTrivialHashHasher<QByteArray>;
    using uint256HashHasher = GenericTrivialHashHasher<bitcoin::uint256>;
    using uint160HashHasher = GenericTrivialHashHasher<bitcoin::uint160>;


    /// Tests
    namespace Tests {
        void SigCheck();
        bool Base58(bool silent = false, bool throws = false);
        void CashAddr();
        bool Addr();
        void TestBlock();
        void HexParsers(const QString &jsonDataFileName);
    }

} // end namespace

Q_DECLARE_METATYPE(BTC::Address);

#endif // BTC_H
