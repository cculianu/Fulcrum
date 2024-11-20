// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "serialize.h"

#include <algorithm>
#include <cassert>
#include <cstddef> // std::byte
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

namespace bitcoin {

namespace util {
inline void Xor(Span<std::byte> write, const Span<const std::byte> key, size_t key_offset) {
    if (key.empty()) return;
    key_offset %= key.size();

    while (!write.empty()) {
        write.pop_front() ^= key[key_offset++];

        // This potentially acts on very many bytes of data, so it's
        // important that we calculate the `key` index in this way instead
        // of doing a %, which would effectively be a division for each
        // byte Xor'd -- much slower than need be.
        if (key_offset == key.size()) key_offset = 0u;
    }
}
} // namespace util

template <typename Stream> class OverrideStream {
    Stream *stream;

    const int nType;
    const int nVersion;

public:
    OverrideStream(Stream *stream_, int nType_, int nVersion_)
        : stream(stream_), nType(nType_), nVersion(nVersion_) {}

    template <typename T> OverrideStream<Stream> &operator<<(const T &obj) {
        // Serialize to this stream
        bitcoin::Serialize(*this, obj);
        return (*this);
    }

    template <typename T> OverrideStream<Stream> &operator>>(T &&obj) {
        // Unserialize from this stream
        bitcoin::Unserialize(*this, obj);
        return (*this);
    }

    void write(const char *pch, size_t nSize) { stream->write(pch, nSize); }

    void read(char *pch, size_t nSize) { stream->read(pch, nSize); }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
};

template <typename S> OverrideStream<S> WithOrVersion(S *s, int nVersionFlag) {
    return OverrideStream<S>(s, s->GetType(), s->GetVersion() | nVersionFlag);
}

/**
 * Minimal stream for overwriting and/or appending to an existing byte vector.
 *
 * The referenced vector will grow as necessary.
 *
 * This was made into a template by Calin in anticipation of also using this with QByteArray.
 */
template <typename ByteVectorT>
class GenericVectorWriter {
    const int nType;
    const int nVersion;
    ByteVectorT &m_data;
    using size_type = typename ByteVectorT::size_type;
    size_type nPos;

public:
    /**
     * @param[in]  nTypeIn Serialization Type
     * @param[in]  nVersionIn Serialization Version (including any flags)
     * @param[in]  dataIn  Referenced byte vector to overwrite/append
     * @param[in]  nPosIn Starting position. Vector index where writes should
     * start. The vector will initially grow as necessary to  max(nPosIn,
     * vec.size()). So to append, use vec.size().
     */
    GenericVectorWriter(int nTypeIn, int nVersionIn, ByteVectorT &dataIn,
                        size_type nPosIn)
        : nType(nTypeIn), nVersion(nVersionIn), m_data(dataIn),
          nPos(nPosIn) {
        if (nPos > m_data.size()) m_data.resize(nPos);
    }
    /**
     * (other params same as above)
     * @param[in]  args  A list of items to serialize starting at nPosIn.
     */
    template <typename... Args>
    GenericVectorWriter(int nTypeIn, int nVersionIn, ByteVectorT & dataIn,
                        size_type nPosIn, Args &&... args)
        : GenericVectorWriter(nTypeIn, nVersionIn, dataIn, nPosIn) {
        bitcoin::SerializeMany(*this, std::forward<Args>(args)...);
    }
    void write(const char *pch, size_t nSize) {
        // this method was re-written by Calin to also work with QByteArray potentially.
        assert(nPos <= m_data.size());
        size_t nOverwrite = size_t(std::min(size_type(nSize), m_data.size() - nPos));
        if (nOverwrite) {
            std::memcpy(m_data.data() + nPos, pch, nOverwrite);
            nPos += size_type(nOverwrite);
        }
        if (nOverwrite < nSize) {
            const auto nLeftOver = size_type(nSize-nOverwrite);
            m_data.resize(nPos + nLeftOver);
            std::memcpy(m_data.data() + nPos, pch + nOverwrite, size_t(nLeftOver));
            nPos += nLeftOver;
        }
    }
    template <typename T> GenericVectorWriter &operator<<(const T &obj) {
        // Serialize to this stream
        bitcoin::Serialize(*this, obj);
        return (*this);
    }
    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    void seek(size_t nSize) {
        nPos += size_type(nSize);
        if (nPos > m_data.size()) m_data.resize(nPos);
    }
};

using VectorWriter = GenericVectorWriter<std::vector<uint8_t>>;
using CVectorWriter = VectorWriter; ///< compatibility with existing bitcoin code.

/**
 * Minimal stream for reading from an existing vector by reference.
 * This was made into a template by Calin for use with QByteArray as well as bitcoin's std::vector<uint8_t>.
 */
template <typename ByteVectorT>
class GenericVectorReader {
private:
    const int m_type;
    const int m_version;
    const ByteVectorT &m_data;
    using size_type = typename ByteVectorT::size_type;
    size_type m_pos = 0;

public:
    /**
     * @param[in]  type Serialization Type
     * @param[in]  version Serialization Version (including any flags)
     * @param[in]  data Referenced byte vector to overwrite/append
     * @param[in]  pos Starting position. Vector index where reads should start.
     */
    GenericVectorReader(int type, int version, const ByteVectorT &data,
                        size_type pos)
        : m_type(type), m_version(version), m_data(data), m_pos(pos) {
        if (m_pos > m_data.size()) {
            throw std::ios_base::failure(
                "VectorReader(...): end of data (m_pos > m_data.size())");
        }
    }

    /**
     * (other params same as above)
     * @param[in]  args  A list of items to deserialize starting at pos.
     */
    template <typename... Args>
    GenericVectorReader(int type, int version, const ByteVectorT &data,
                        size_type pos, Args &&... args)
        : GenericVectorReader(type, version, data, pos) {
        bitcoin::UnserializeMany(*this, std::forward<Args>(args)...);
    }

    template <typename T> GenericVectorReader &operator>>(T &obj) {
        // Unserialize from this stream
        bitcoin::Unserialize(*this, obj);
        return (*this);
    }

    int GetVersion() const { return m_version; }
    int GetType() const { return m_type; }

    size_type size() const { return m_data.size() - m_pos; }
    bool empty() const { return m_data.size() == m_pos; }

    void read(char *dst, size_t n) {
        if (n == 0) {
            return;
        }

        // Read from the beginning of the buffer
        size_type pos_next = m_pos + n;
        if (pos_next > m_data.size()) {
            throw std::ios_base::failure("VectorReader::read(): end of data");
        }
        std::memcpy(dst, m_data.data() + m_pos, n);
        m_pos = pos_next;
    }

    size_type GetPos() const { return m_pos; }

    void seek(size_type new_pos) {
        if (new_pos < 0) throw std::ios_base::failure("Cannot seek to a negative offset");
        m_pos = new_pos;
    }
};


/**
 * Minimal stream for reading from an existing vector by reference
 */
using VectorReader = GenericVectorReader<std::vector<uint8_t>>;

using CSerializeData = std::vector<char>; ///< for compatibility with legacy code
/**
 * Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization
 * templates. Fills with data in linear time; some stringstream implementations
 * take N^2 time.
 */
class CDataStream {
protected:
    using vector_type = CSerializeData;
    vector_type vch;
    unsigned int nReadPos;

    int nType;
    int nVersion;

public:
    typedef vector_type::allocator_type allocator_type;
    typedef vector_type::size_type size_type;
    typedef vector_type::difference_type difference_type;
    typedef vector_type::reference reference;
    typedef vector_type::const_reference const_reference;
    typedef vector_type::value_type value_type;
    typedef vector_type::iterator iterator;
    typedef vector_type::const_iterator const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit CDataStream(int nTypeIn, int nVersionIn) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn,
                int nVersionIn)
        : vch(pbegin, pend) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const char *pbegin, const char *pend, int nTypeIn,
                int nVersionIn)
        : vch(pbegin, pend) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<char> &vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end()) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<uint8_t> &vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end()) {
        Init(nTypeIn, nVersionIn);
    }

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args &&... args) {
        Init(nTypeIn, nVersionIn);
        bitcoin::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void Init(int nTypeIn, int nVersionIn) {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;
    }

    CDataStream &operator+=(const CDataStream &b) {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CDataStream operator+(const CDataStream &a, const CDataStream &b) {
        CDataStream ret = a;
        ret += b;
        return (ret);
    }

    std::string str() const { return (std::string(begin(), end())); }

    //
    // Vector subset
    //
    const_iterator begin() const { return vch.begin() + nReadPos; }
    iterator begin() { return vch.begin() + nReadPos; }
    const_iterator end() const { return vch.end(); }
    iterator end() { return vch.end(); }
    size_type size() const { return vch.size() - nReadPos; }
    bool empty() const { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c = 0) { vch.resize(n + nReadPos, c); }
    void reserve(size_type n) { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const {
        return vch[pos + nReadPos];
    }
    reference operator[](size_type pos) { return vch[pos + nReadPos]; }
    void clear() {
        vch.clear();
        nReadPos = 0;
    }
    iterator insert(iterator it, const char x = char()) {
        return vch.insert(it, x);
    }
    void insert(iterator it, size_type n, const char x) {
        vch.insert(it, n, x);
    }
    value_type *data() { return vch.data() + nReadPos; }
    const value_type *data() const { return vch.data() + nReadPos; }

    void insert(iterator it, std::vector<char>::const_iterator first,
                std::vector<char>::const_iterator last) {
        if (last == first) {
            return;
        }

        assert(last - first > 0);
        if (it == vch.begin() + nReadPos &&
            (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            std::memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }

    void insert(iterator it, const char *first, const char *last) {
        if (last == first) {
            return;
        }

        assert(last - first > 0);
        if (it == vch.begin() + nReadPos &&
            (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            std::memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }

    iterator erase(iterator it) {
        if (it == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if (++nReadPos >= vch.size()) {
                // whenever we reach the end, we take the opportunity to clear
                // the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        } else {
            return vch.erase(it);
        }
    }

    iterator erase(iterator first, iterator last) {
        if (first == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if (last == vch.end()) {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            } else {
                nReadPos = (last - vch.begin());
                return last;
            }
        } else
            return vch.erase(first, last);
    }

    inline void Compact() {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    bool Rewind(size_type n) {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos) return false;
        nReadPos -= n;
        return true;
    }

    //
    // Stream subset
    //
    bool eof() const { return size() == 0; }
    CDataStream *rdbuf() { return this; }
    int in_avail() const { return size(); }

    void SetType(int n) { nType = n; }
    int GetType() const { return nType; }
    void SetVersion(int n) { nVersion = n; }
    int GetVersion() const { return nVersion; }

    void read(char *pch, size_t nSize) {
        if (nSize == 0) {
            return;
        }

        // Read from the beginning of the buffer
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext > vch.size()) {
            throw std::ios_base::failure("CDataStream::read(): end of data");
        }
        std::memcpy(pch, &vch[nReadPos], nSize);
        if (nReadPosNext == vch.size()) {
            nReadPos = 0;
            vch.clear();
            return;
        }
        nReadPos = nReadPosNext;
    }

    void ignore(int nSize) {
        // Ignore from the beginning of the buffer
        if (nSize < 0) {
            throw std::ios_base::failure(
                "CDataStream::ignore(): nSize negative");
        }
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size()) {
            if (nReadPosNext > vch.size())
                throw std::ios_base::failure(
                    "CDataStream::ignore(): end of data");
            nReadPos = 0;
            vch.clear();
            return;
        }
        nReadPos = nReadPosNext;
    }

    void write(const char *pch, size_t nSize) {
        // Write to the end of the buffer
        vch.insert(vch.end(), pch, pch + nSize);
    }

    template <typename Stream> void Serialize(Stream &s) const {
        // Special case: stream << stream concatenates like stream += stream
        if (!vch.empty()) {
            s.write((char *)vch.data(), vch.size() * sizeof(value_type));
        }
    }

    template <typename T> CDataStream &operator<<(const T &obj) {
        // Serialize to this stream
        bitcoin::Serialize(*this, obj);
        return (*this);
    }

    template <typename T> CDataStream &operator>>(T &&obj) {
        // Unserialize from this stream
        bitcoin::Unserialize(*this, obj);
        return (*this);
    }

    void GetAndClear(CSerializeData &d) {
        d.insert(d.end(), begin(), end());
        clear();
    }

    /**
     * XOR the contents of this stream with a certain key.
     *
     * @param[in] key    The key used to XOR the data in this stream.
     */
    void Xor(const std::vector<uint8_t> &key) {
        util::Xor(MakeWritableByteSpan(vch), MakeByteSpan(key), 0u);
    }
};

template <typename IStream> class BitStreamReader {
private:
    IStream &m_istream;

    /// Buffered byte read in from the input stream. A new byte is read into the
    /// buffer when m_offset reaches 8.
    uint8_t m_buffer{0};

    /// Number of high order bits in m_buffer already returned by previous
    /// Read() calls. The next bit to be returned is at this offset from the
    /// most significant bit position.
    int m_offset{8};

public:
    explicit BitStreamReader(IStream &istream) : m_istream(istream) {}

    /**
     * Read the specified number of bits from the stream. The data is returned
     * in the nbits least significant bits of a 64-bit uint.
     */
    uint64_t Read(int nbits) {
        if (nbits < 0 || nbits > 64) {
            throw std::out_of_range("nbits must be between 0 and 64");
        }

        uint64_t data = 0;
        while (nbits > 0) {
            if (m_offset == 8) {
                m_istream >> m_buffer;
                m_offset = 0;
            }

            int bits = std::min(8 - m_offset, nbits);
            data <<= bits;
            data |= static_cast<uint8_t>(m_buffer << m_offset) >> (8 - bits);
            m_offset += bits;
            nbits -= bits;
        }
        return data;
    }
};

template <typename OStream> class BitStreamWriter {
private:
    OStream &m_ostream;

    /// Buffered byte waiting to be written to the output stream. The byte is
    /// written buffer when m_offset reaches 8 or Flush() is called.
    uint8_t m_buffer{0};

    /// Number of high order bits in m_buffer already written by previous
    /// Write() calls and not yet flushed to the stream. The next bit to be
    /// written to is at this offset from the most significant bit position.
    int m_offset{0};

public:
    explicit BitStreamWriter(OStream &ostream) : m_ostream(ostream) {}

    ~BitStreamWriter() { Flush(); }

    /**
     * Write the nbits least significant bits of a 64-bit int to the output
     * stream. Data is buffered until it completes an octet.
     */
    void Write(uint64_t data, int nbits) {
        if (nbits < 0 || nbits > 64) {
            throw std::out_of_range("nbits must be between 0 and 64");
        }

        while (nbits > 0) {
            int bits = std::min(8 - m_offset, nbits);
            m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset);
            m_offset += bits;
            nbits -= bits;

            if (m_offset == 8) {
                Flush();
            }
        }
    }

    /**
     * Flush any unwritten bits to the output stream, padding with 0's to the
     * next byte boundary.
     */
    void Flush() {
        if (m_offset == 0) {
            return;
        }

        m_ostream << m_buffer;
        m_buffer = 0;
        m_offset = 0;
    }
};

/**
 * Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null. If
 * you're returning the file pointer, return file.release(). If you need to
 * close the file early, use file.fclose() instead of fclose(file).
 */
class CAutoFile {
private:
    const int nType;
    const int nVersion;

    std::FILE *file;
    std::vector<std::byte> xor_key;
    size_t xor_offset = 0u;

public:
    CAutoFile(std::FILE *filenew, int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn) {
        file = filenew;
    }

    ~CAutoFile() { fclose(); }

    // Disallow copies
    CAutoFile(const CAutoFile &) = delete;
    CAutoFile &operator=(const CAutoFile &) = delete;

    void fclose() {
        if (file) {
            std::fclose(file);
            file = nullptr;
        }
    }

    /**
     * Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the CAutoFile object, and makes it the
     * responsibility of the caller of this function to clean up the returned
     * FILE*.
     */
    std::FILE *release() {
        std::FILE *ret = file;
        file = nullptr;
        return ret;
    }

    /**
     * Get wrapped FILE* without transfer of ownership.
     * @note Ownership of the FILE* will remain with this class. Use this only
     * if the scope of the CAutoFile outlives use of the passed pointer.
     */
    std::FILE *Get() const { return file; }

    /** Return true if the wrapped FILE* is nullptr, false otherwise. */
    bool IsNull() const { return file == nullptr; }

    /** Continue with a different XOR key */
    void SetXor(std::vector<std::byte> data_xor) { xor_key = std::move(data_xor); }

    //
    // Stream subset
    //
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void read(char * const pch, const size_t nSize) {
        if (!file)
            throw std::ios_base::failure("CAutoFile::read: file handle is nullptr");
        if (std::fread(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure(std::feof(file) ? "CAutoFile::read: end of file"
                                                         : "CAutoFile::read: fread failed");
        if (!xor_key.empty())
            util::Xor(MakeWritableByteSpan(Span{pch, nSize}), xor_key, xor_offset);
        xor_offset += nSize; // maintain accurate xor_offset
    }

    void ignore(size_t nSize) {
        if (!file)
            throw std::ios_base::failure("CAutoFile::ignore: file handle is nullptr");
        uint8_t data[4096];
        while (nSize > 0) {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (std::fread(data, 1, nNow, file) != nNow)
                throw std::ios_base::failure(std::feof(file) ? "CAutoFile::ignore: end of file"
                                                             : "CAutoFile::read: fread failed");
            nSize -= nNow;
            xor_offset += nNow; // maintain accurate xor_offset
        }
    }

    void write(const char * const pch, const size_t nSize) {
        if (!file)
            throw std::ios_base::failure("CAutoFile::write: file handle is nullptr");
        if (xor_key.empty()) {
            // normal write
            if (std::fwrite(pch, 1, nSize, file) != nSize)
                throw std::ios_base::failure("CAutoFile::write: write failed");
            xor_offset += nSize; // maintain accurate xor_offset just in case xor_key is later enabled
        } else {
            // Write using xor_key
            std::array<std::byte, 4096> buf;
            Span<const std::byte> src = MakeByteSpan(Span{pch, nSize});
            while (!src.empty()) {
                auto buf_now = Span{buf}.first(std::min<size_t>(src.size(), buf.size()));
                std::copy(src.begin(), src.begin() + buf_now.size(), buf_now.begin());
                util::Xor(buf_now, xor_key, xor_offset);
                if (std::fwrite(buf_now.data(), 1, buf_now.size(), file) != buf_now.size()) {
                    throw std::ios_base::failure{"CAutoFile::write: XorFile::write: failed"};
                }
                xor_offset += buf_now.size();
                src = src.subspan(buf_now.size());
            }
        }
    }

    template <typename T> CAutoFile &operator<<(const T &obj) {
        // Serialize to this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator<<: file handle is nullptr");
        bitcoin::Serialize(*this, obj);
        return *this;
    }

    template <typename T> CAutoFile &operator>>(T &&obj) {
        // Unserialize from this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator>>: file handle is nullptr");
        bitcoin::Unserialize(*this, obj);
        return *this;
    }
};

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
