//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "base58.h"

#include "App.h"
#include "Util.h"

#include <QByteArray>

#include <cstring>
#include <string>
#include <vector>

namespace bitcoin {
    bool TestBase58(bool silent, bool throws)
    {
        using Print = Log;
        std::vector<unsigned char> result;
        constexpr auto anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        if (!bitcoin::DecodeBase58Check(anAddress, result)) {
            constexpr auto err = "Base58 decode check fail!";
            if (throws) throw InternalError(err);
            if (!silent) Print() << err;
            return false;
        }
        QByteArray ba;
        ba.insert(0, reinterpret_cast<char *>(&result[0]), int(result.size()));
        const auto hexDecoded = ba.toHex();
        if (!silent) Print() << anAddress << "  ->  " << hexDecoded << "  (decoded)";
        ba = QByteArray::fromHex("00791fc195e712c142df4c4e14fd4ec5b302733832");
        result.resize(size_t(ba.length()));
        std::memcpy(&result[0], ba.constData(), size_t(ba.length()));
        auto str = bitcoin::EncodeBase58Check(result);
        std::vector<unsigned char> result2;
        if (!bitcoin::DecodeBase58Check(str, result2) || result2 != result) {
            constexpr auto err = "Base58 Decode -> Encode results differ! Fail!";
            if (throws) throw InternalError(err);
            if (!silent) Print() << err;
            return false;
        }
        if (!silent) Print() << ba.toHex() << "  ->  " << str << "  (encoded)";
        bool ret = ba.toHex() == hexDecoded && str == std::string(anAddress);
        if (!silent) Print() << (ret ? "Compare ok, success." : "Values differ -- ERROR!!");
        return ret;
    }
}

#ifdef ENABLE_TESTS

#include "copyable_ptr.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/common.h"
#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "hash.h"
#include "prevector.h"
#include "reverse_iterator.h"
#include "serialize.h"
#include "streams.h"
#include "transaction.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "version.h"

#include <QRandomGenerator>

#include <array>
#include <cassert>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <new>
#include <stdexcept>
#include <sstream>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
    const auto t1 = App::registerTest("base58", []{
        const bool res = bitcoin::TestBase58(false, true);
        if (!res) throw Exception("base58 failed");
    });

    template <typename ByteT, std::enable_if_t<sizeof(ByteT) == 1, int> = 0>
    void GetRandBytes(ByteT *dest, std::size_t count) {
        if (const auto sz = count / sizeof(quint32) + bool(count % sizeof(quint32)); sz > 0) {
            std::vector<quint32> tmp(sz, 0u);
            assert(tmp.size() * sizeof(quint32) >= count);
            QRandomGenerator::global()->fillRange(tmp.data(), tmp.size());
            std::memcpy(dest, tmp.data(), count);
        }
    }

    /// BCHN Unit Test work-alike support ...
    struct TestContext {
        const QString name;
        unsigned  nChecks = 0, nChecksFailed = 0, nChecksOk = 0;
        using VoidFunc = std::function<void()>;
        std::list<std::pair<QString, VoidFunc>> tests;
        static std::list<TestContext *> stack;
        static void throwIfStackEmpty() {
            if (stack.empty() || stack.back() == nullptr)
                throw Exception("TestContext stack is empty!");
        }

        static TestContext & cur() { throwIfStackEmpty(); return *stack.back(); }

        explicit TestContext(const QString &name) : name(name) { stack.push_back(this); }
        ~TestContext() { throwIfStackEmpty(); stack.pop_front(); }

        void checkExpr(const char * const estr, const bool expr, unsigned line, const char * const file, const std::string &msg = {}) {
            ++nChecks;
            auto msgStr = [&msg]() -> QString {
                return (msg.empty() ? QString("") : QString(", msg: \"") + QString::fromStdString(msg) + "\"");
            };
            if (!expr) {
                ++nChecksFailed;
                Warning() << "Check failed (" << file << ":" << line << "): " << estr << msgStr();
            } else {
                ++nChecksOk;
                Trace() << "Check success (" << file << ":" << line << "): " << estr << msgStr();
            }
        }

        void runAll() {
            unsigned nTests = 0;
            std::tie(nChecks, nChecksOk, nChecksFailed) = std::tuple(0u, 0u, 0u); // stats
            Tic t0;
            for (const auto & [tname, func] : tests) {
                Tic t1;
                ++nTests;
                Log() << "Running " << name << " test: " << tname << " ...";
                const auto [b4checks, b4ok, b4failed] = std::tuple(nChecks, nChecksOk, nChecksFailed);
                func();
                const auto [checks, ok, failed] = std::tuple(nChecks, nChecksOk, nChecksFailed);
                if (failed > b4failed)
                    throw Exception(QString::number(failed - b4failed) + " checks failed for test: " + tname);
                Log() << (ok - b4ok) << "/" << (checks - b4checks) << " checks ok for " << tname << " in "
                        << t1.msecStr() << " msec";
            }
            Log() << name << ": ran " << nTests << " tests total."
                  << " Checks: " << nChecksOk << " passed, " << nChecksFailed << " failed."
                  << " Elapsed: " << t0.msecStr() << " msec.";
        }
    };

    /* static */ std::list<TestContext *> TestContext::stack;

    // Some macros used below so we can just copy-paste unit tests from BCHN without changing them
#   define RUN_CONTEXT() TestContext::cur().runAll()
#   if defined(__LINE__) && defined(__FILE__)
#       define SETUP_CONTEXT(name) TestContext testContext ## __LINE__(name)
#       define BOOST_CHECK(expr) TestContext::cur().checkExpr(#expr, (expr), __LINE__, __FILE__)
#       define BOOST_CHECK_MESSAGE(expr, msg) TestContext::cur().checkExpr(#expr, (expr), __LINE__, __FILE__, msg)
#   else
#       define SETUP_CONTEXT(name) TestContext testContext(name)
#       define BOOST_CHECK(expr) TestContext::cur().checkExpr(#expr, (expr), 0, "???")
#       define BOOST_CHECK_MESSAGE(expr, msg) TestContext::cur().checkExpr(#expr, (expr), 0, "???", msg)
#   endif
#   define BOOST_CHECK_EQUAL(a, b) BOOST_CHECK((a) == (b))
#   define BOOST_CHECK_EXCEPTION(expr, exc, pred) \
            do { \
                try { \
                    expr; \
                } catch (const exc &e) { \
                    BOOST_CHECK_MESSAGE(pred(e), "Expression: \"" #expr "\" did not throw \"" #exc "\" as expected"); \
                } \
            } while (0)
#   define BOOST_AUTO_TEST_CASE(name) \
            TestContext::cur().tests.emplace_back( #name, TestContext::VoidFunc{} ); \
            TestContext::cur().tests.back().second = [&]


    // The below tests are taken from BCHN sources: src/test/uint256_tests.cpp, hence the BOOST workalike macros below...
    void uint256_tests() {
        using namespace bitcoin;
        const uint8_t R1Array[] =
            "\x9c\x52\x4a\xdb\xcf\x56\x11\x12\x2b\x29\x12\x5e\x5d\x35\xd2\xd2"
            "\x22\x81\xaa\xb5\x33\xf0\x08\x32\xd5\x56\xb1\xf9\xea\xe5\x1d\x7d";
        const char R1ArrayHex[] =
            "7D1DE5EAF9B156D53208F033B5AA8122D2d2355d5e12292b121156cfdb4a529c";
        const uint256 R1L = uint256(std::vector<uint8_t>(R1Array, R1Array + 32));
        const uint160 R1S = uint160(std::vector<uint8_t>(R1Array, R1Array + 20));

        const uint8_t R2Array[] =
            "\x70\x32\x1d\x7c\x47\xa5\x6b\x40\x26\x7e\x0a\xc3\xa6\x9c\xb6\xbf"
            "\x13\x30\x47\xa3\x19\x2d\xda\x71\x49\x13\x72\xf0\xb4\xca\x81\xd7";
        const uint256 R2L = uint256(std::vector<uint8_t>(R2Array, R2Array + 32));
        const uint160 R2S = uint160(std::vector<uint8_t>(R2Array, R2Array + 20));

        const uint8_t ZeroArray[] =
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        const uint256 ZeroL = uint256(std::vector<uint8_t>(ZeroArray, ZeroArray + 32));
        const uint160 ZeroS = uint160(std::vector<uint8_t>(ZeroArray, ZeroArray + 20));

        const uint8_t OneArray[] =
            "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        const uint256 OneL = uint256(std::vector<uint8_t>(OneArray, OneArray + 32));
        const uint160 OneS = uint160(std::vector<uint8_t>(OneArray, OneArray + 20));

        const uint8_t MaxArray[] =
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        const uint256 MaxL = uint256(std::vector<uint8_t>(MaxArray, MaxArray + 32));
        const uint160 MaxS = uint160(std::vector<uint8_t>(MaxArray, MaxArray + 20));

        auto ArrayToString = [](const uint8_t A[], unsigned int width) -> std::string {
            std::stringstream Stream;
            Stream << std::hex;
            for (unsigned int i = 0; i < width; ++i) {
                Stream << std::setw(2) << std::setfill('0')
                       << (unsigned int)A[width - i - 1];
            }
            return Stream.str();
        };

        SETUP_CONTEXT("uint256");

        // constructors, equality, inequality
        BOOST_AUTO_TEST_CASE(basics) {
            BOOST_CHECK(1 == 0 + 1);
            // constructor uint256(vector<char>):
            BOOST_CHECK(R1L.ToString() == ArrayToString(R1Array, 32));
            BOOST_CHECK(R1S.ToString() == ArrayToString(R1Array, 20));
            BOOST_CHECK(R2L.ToString() == ArrayToString(R2Array, 32));
            BOOST_CHECK(R2S.ToString() == ArrayToString(R2Array, 20));
            BOOST_CHECK(ZeroL.ToString() == ArrayToString(ZeroArray, 32));
            BOOST_CHECK(ZeroS.ToString() == ArrayToString(ZeroArray, 20));
            BOOST_CHECK(OneL.ToString() == ArrayToString(OneArray, 32));
            BOOST_CHECK(OneS.ToString() == ArrayToString(OneArray, 20));
            BOOST_CHECK(MaxL.ToString() == ArrayToString(MaxArray, 32));
            BOOST_CHECK(MaxS.ToString() == ArrayToString(MaxArray, 20));
            BOOST_CHECK(OneL.ToString() != ArrayToString(ZeroArray, 32));
            BOOST_CHECK(OneS.ToString() != ArrayToString(ZeroArray, 20));

            // .GetUint64
            for (int i = 0; i < 4; ++i) {
                if (i < 2) BOOST_CHECK(R1L.GetUint64(i) == R1S.GetUint64(i));
                const uint64_t val = ReadLE64(R1Array + i*8);
                BOOST_CHECK_EQUAL(R1L.GetUint64(i), val);
            }

            // == and !=
            BOOST_CHECK(R1L != R2L && R1S != R2S);
            BOOST_CHECK(ZeroL != OneL && ZeroS != OneS);
            BOOST_CHECK(OneL != ZeroL && OneS != ZeroS);
            BOOST_CHECK(MaxL != ZeroL && MaxS != ZeroS);

            // String Constructor and Copy Constructor
            BOOST_CHECK(uint256S("0x" + R1L.ToString()) == R1L);
            BOOST_CHECK(uint256S("0x" + R2L.ToString()) == R2L);
            BOOST_CHECK(uint256S("0x" + ZeroL.ToString()) == ZeroL);
            BOOST_CHECK(uint256S("0x" + OneL.ToString()) == OneL);
            BOOST_CHECK(uint256S("0x" + MaxL.ToString()) == MaxL);
            BOOST_CHECK(uint256S(R1L.ToString()) == R1L);
            BOOST_CHECK(uint256S("   0x" + R1L.ToString() + "   ") == R1L);
            BOOST_CHECK(uint256S("") == ZeroL);
            BOOST_CHECK(R1L == uint256S(R1ArrayHex));
            BOOST_CHECK(uint256(R1L) == R1L);
            BOOST_CHECK(uint256(ZeroL) == ZeroL);
            BOOST_CHECK(uint256(OneL) == OneL);

            BOOST_CHECK(uint160S("0x" + R1S.ToString()) == R1S);
            BOOST_CHECK(uint160S("0x" + R2S.ToString()) == R2S);
            BOOST_CHECK(uint160S("0x" + ZeroS.ToString()) == ZeroS);
            BOOST_CHECK(uint160S("0x" + OneS.ToString()) == OneS);
            BOOST_CHECK(uint160S("0x" + MaxS.ToString()) == MaxS);
            BOOST_CHECK(uint160S(R1S.ToString()) == R1S);
            BOOST_CHECK(uint160S("   0x" + R1S.ToString() + "   ") == R1S);
            BOOST_CHECK(uint160S("") == ZeroS);
            BOOST_CHECK(R1S == uint160S(R1ArrayHex));

            BOOST_CHECK(uint160(R1S) == R1S);
            BOOST_CHECK(uint160(ZeroS) == ZeroS);
            BOOST_CHECK(uint160(OneS) == OneS);

            // ensure a string with a short, odd number of hex digits parses ok, and clears remaining bytes ok
            const std::string oddHex = "12a4507c9";
            uint256 oddHexL;
            uint160 oddHexS;
            GetRandBytes(oddHexL.begin(), 32);
            GetRandBytes(oddHexS.begin(), 20);
            oddHexL.SetHex(oddHex);
            oddHexS.SetHex(oddHex);
            BOOST_CHECK_EQUAL(oddHexL.ToString(), std::string(64 - oddHex.size(), '0') + oddHex);
            BOOST_CHECK_EQUAL(oddHexS.ToString(), std::string(40 - oddHex.size(), '0') + oddHex);
            // also test GetUint64
            BOOST_CHECK_EQUAL(oddHexL.GetUint64(0), 5004134345ull);
            BOOST_CHECK_EQUAL(oddHexS.GetUint64(0), 5004134345ull);
        };

        auto CheckComparison = [&](const auto &a, const auto &b) {
            static_assert (std::is_same_v<decltype(a), decltype(b)>);
            using T = std::decay_t<decltype(a)>;
            static_assert (std::is_same_v<T, uint256> || std::is_same_v<T, uint160>);
            BOOST_CHECK(a < b);
            BOOST_CHECK(a <= b);
            BOOST_CHECK(b > a);
            BOOST_CHECK(b >= a);
        };

        // <= >= < >
        BOOST_AUTO_TEST_CASE(comparison) {
            uint256 LastL;
            for (int i = 0; i < 256; i++) {
                uint256 TmpL;
                *(TmpL.begin() + (i >> 3)) |= 1 << (i & 7);
                CheckComparison(LastL, TmpL);
                LastL = TmpL;
                BOOST_CHECK(LastL <= LastL);
                BOOST_CHECK(LastL >= LastL);
            }

            CheckComparison(ZeroL, R1L);
            CheckComparison(R1L, R2L);
            CheckComparison(ZeroL, OneL);
            CheckComparison(OneL, MaxL);
            CheckComparison(R1L, MaxL);
            CheckComparison(R2L, MaxL);

            uint160 LastS;
            for (int i = 0; i < 160; i++) {
                uint160 TmpS;
                *(TmpS.begin() + (i >> 3)) |= 1 << (i & 7);
                CheckComparison(LastS, TmpS);
                LastS = TmpS;
                BOOST_CHECK(LastS <= LastS);
                BOOST_CHECK(LastS >= LastS);
            }

            CheckComparison(ZeroS, R1S);
            CheckComparison(R2S, R1S);
            CheckComparison(ZeroS, OneS);
            CheckComparison(OneS, MaxS);
            CheckComparison(R1S, MaxS);
            CheckComparison(R2S, MaxS);
        };

        // GetHex SetHex begin() end() size() GetLow64 GetSerializeSize, Serialize,
        // Unserialize
        BOOST_AUTO_TEST_CASE(methods) {
            BOOST_CHECK(R1L.GetHex() == R1L.ToString());
            BOOST_CHECK(R2L.GetHex() == R2L.ToString());
            BOOST_CHECK(OneL.GetHex() == OneL.ToString());
            BOOST_CHECK(MaxL.GetHex() == MaxL.ToString());
            uint256 TmpL(R1L);
            BOOST_CHECK(TmpL == R1L);
            TmpL.SetHex(R2L.ToString());
            BOOST_CHECK(TmpL == R2L);
            TmpL.SetHex(ZeroL.ToString());
            BOOST_CHECK(TmpL == uint256());

            TmpL.SetHex(R1L.ToString());
            BOOST_CHECK(std::memcmp(R1L.begin(), R1Array, 32) == 0);
            BOOST_CHECK(std::memcmp(TmpL.begin(), R1Array, 32) == 0);
            BOOST_CHECK(std::memcmp(R2L.begin(), R2Array, 32) == 0);
            BOOST_CHECK(std::memcmp(ZeroL.begin(), ZeroArray, 32) == 0);
            BOOST_CHECK(std::memcmp(OneL.begin(), OneArray, 32) == 0);
            BOOST_CHECK(R1L.size() == sizeof(R1L));
            BOOST_CHECK(sizeof(R1L) == 32);
            BOOST_CHECK(R1L.size() == 32);
            BOOST_CHECK(R2L.size() == 32);
            BOOST_CHECK(ZeroL.size() == 32);
            BOOST_CHECK(MaxL.size() == 32);
            BOOST_CHECK(R1L.begin() + 32 == R1L.end());
            BOOST_CHECK(R2L.begin() + 32 == R2L.end());
            BOOST_CHECK(OneL.begin() + 32 == OneL.end());
            BOOST_CHECK(MaxL.begin() + 32 == MaxL.end());
            BOOST_CHECK(TmpL.begin() + 32 == TmpL.end());
            BOOST_CHECK(GetSerializeSize(R1L, PROTOCOL_VERSION) == 32);
            BOOST_CHECK(GetSerializeSize(ZeroL, PROTOCOL_VERSION) == 32);

            CDataStream ss(0, PROTOCOL_VERSION);
            ss << R1L;
            BOOST_CHECK(ss.str() == std::string(R1Array, R1Array + 32));
            ss >> TmpL;
            BOOST_CHECK(R1L == TmpL);
            ss.clear();
            ss << ZeroL;
            BOOST_CHECK(ss.str() == std::string(ZeroArray, ZeroArray + 32));
            ss >> TmpL;
            BOOST_CHECK(ZeroL == TmpL);
            ss.clear();
            ss << MaxL;
            BOOST_CHECK(ss.str() == std::string(MaxArray, MaxArray + 32));
            ss >> TmpL;
            BOOST_CHECK(MaxL == TmpL);
            ss.clear();

            BOOST_CHECK(R1S.GetHex() == R1S.ToString());
            BOOST_CHECK(R2S.GetHex() == R2S.ToString());
            BOOST_CHECK(OneS.GetHex() == OneS.ToString());
            BOOST_CHECK(MaxS.GetHex() == MaxS.ToString());
            uint160 TmpS(R1S);
            BOOST_CHECK(TmpS == R1S);
            TmpS.SetHex(R2S.ToString());
            BOOST_CHECK(TmpS == R2S);
            TmpS.SetHex(ZeroS.ToString());
            BOOST_CHECK(TmpS == uint160());

            TmpS.SetHex(R1S.ToString());
            BOOST_CHECK(std::memcmp(R1S.begin(), R1Array, 20) == 0);
            BOOST_CHECK(std::memcmp(TmpS.begin(), R1Array, 20) == 0);
            BOOST_CHECK(std::memcmp(R2S.begin(), R2Array, 20) == 0);
            BOOST_CHECK(std::memcmp(ZeroS.begin(), ZeroArray, 20) == 0);
            BOOST_CHECK(std::memcmp(OneS.begin(), OneArray, 20) == 0);
            BOOST_CHECK(R1S.size() == sizeof(R1S));
            BOOST_CHECK(sizeof(R1S) == 20);
            BOOST_CHECK(R1S.size() == 20);
            BOOST_CHECK(R2S.size() == 20);
            BOOST_CHECK(ZeroS.size() == 20);
            BOOST_CHECK(MaxS.size() == 20);
            BOOST_CHECK(R1S.begin() + 20 == R1S.end());
            BOOST_CHECK(R2S.begin() + 20 == R2S.end());
            BOOST_CHECK(OneS.begin() + 20 == OneS.end());
            BOOST_CHECK(MaxS.begin() + 20 == MaxS.end());
            BOOST_CHECK(TmpS.begin() + 20 == TmpS.end());
            BOOST_CHECK(GetSerializeSize(R1S, PROTOCOL_VERSION) == 20);
            BOOST_CHECK(GetSerializeSize(ZeroS, PROTOCOL_VERSION) == 20);

            ss << R1S;
            BOOST_CHECK(ss.str() == std::string(R1Array, R1Array + 20));
            ss >> TmpS;
            BOOST_CHECK(R1S == TmpS);
            ss.clear();
            ss << ZeroS;
            BOOST_CHECK(ss.str() == std::string(ZeroArray, ZeroArray + 20));
            ss >> TmpS;
            BOOST_CHECK(ZeroS == TmpS);
            ss.clear();
            ss << MaxS;
            BOOST_CHECK(ss.str() == std::string(MaxArray, MaxArray + 20));
            ss >> TmpS;
            BOOST_CHECK(MaxS == TmpS);
            ss.clear();

            // Check that '0x' or '0X', and leading spaces are correctly skipped in
            // SetHex
            const auto baseHexstring{uint256S(
                "0x7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c")};
            const auto hexstringWithCharactersToSkip{uint256S(
                " 0X7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c")};
            const auto wrongHexstringWithCharactersToSkip{uint256S(
                " 0X7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529d")};

            BOOST_CHECK(baseHexstring.GetHex() == "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c");
            BOOST_CHECK(baseHexstring == hexstringWithCharactersToSkip);
            BOOST_CHECK(baseHexstring != wrongHexstringWithCharactersToSkip);

            // Test IsNull, SetNull, operator==, operator!=, and size()
            auto hexCpy = baseHexstring;
            BOOST_CHECK(hexCpy != ZeroL);
            BOOST_CHECK(ZeroL.IsNull());
            BOOST_CHECK(!hexCpy.IsNull());
            hexCpy.SetNull();
            BOOST_CHECK(hexCpy.IsNull());
            BOOST_CHECK(hexCpy == ZeroL);
            BOOST_CHECK(0 == std::memcmp(hexCpy.begin(), ZeroL.begin(), hexCpy.size()));
            BOOST_CHECK(0 == std::memcmp(hexCpy.begin(), ZeroArray, hexCpy.size()));
            BOOST_CHECK(hexCpy.size() == 32);
            BOOST_CHECK(uint160::size() == 20);

            // check the uninitilized vs initialized constructor
            constexpr size_t wordSize = sizeof(void *);
            constexpr size_t dataSize = sizeof(uint256) + wordSize;
            std::array<uint8_t, dataSize> rawBuf;
            uint8_t *alignedPtr = rawBuf.data();
            // ensure aligned data pointer
            if (std::size_t(alignedPtr) % wordSize) {
                // not aligned, move forward by wordSize bytes, then back by the unaligned bytes
                const auto unaligned = std::size_t(alignedPtr) + wordSize;
                alignedPtr = reinterpret_cast<uint8_t *>(unaligned - unaligned % wordSize);
            }
            // check sanity of align code above
            const bool alignedOk = std::size_t(alignedPtr) % wordSize == 0
                                   && rawBuf.end() - alignedPtr >= std::ptrdiff_t(sizeof(uint256))
                                   && alignedPtr >= rawBuf.begin();
            BOOST_CHECK(alignedOk);
            if (alignedOk) {
                constexpr uint8_t uninitializedByte = 0xfa;
                const auto end = alignedPtr + sizeof(uint256);
                // 1. check that the Uninitialized constructor in fact does not initialize memory
                std::fill(alignedPtr, end, uninitializedByte); // set memory area to clearly uninitialized data
                // the below line prevents the above std::fill from being optimized away
                BOOST_CHECK(end > alignedPtr && *alignedPtr == uninitializedByte && end[-1] == uninitializedByte);
        /* GCC 8.3.x warns here if compiling with -O3 -- but the warning is a false positive. We intentionally
         * are testing the uninitialized case here.  So we suppress the warning.
         * Note that clang doesn't know about -Wmaybe-uninitialized so we limit this pragma to GNUC only. */
#       if defined(__GNUC__) && !defined(__clang__)
#           pragma GCC diagnostic push
#           pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#       endif
                {
                    // Note: this pointer is to data on the stack and should not be freed!
                    uint256 *uninitialized = new (alignedPtr) uint256(uint256::Uninitialized); // explicitly does not initialize the data
                    unsigned uninitializedCtr = 0;
                    // ensure the uninitialized c'tor left the data buffer unmolested
                    for (const auto ch : *uninitialized) {
                        uninitializedCtr += unsigned(ch == uninitializedByte); // false = 0, true = 1
                    }
                    BOOST_CHECK(uninitializedCtr == uint256::size());
                }
#       if defined(__GNUC__) && !defined(__clang__)
#           pragma GCC diagnostic pop
#       endif
                // 2. while we are here, check the default constructor zeroes out data
                std::fill(alignedPtr, end, uninitializedByte); // set memory area to clearly uninitialized data
                // the below line prevents the above std::fill from being optimized away
                BOOST_CHECK(end > alignedPtr && *alignedPtr == uninitializedByte && end[-1] == uninitializedByte);
                {
                    // Note: this pointer is to data on the stack and should not be freed!
                    uint256 *initialized = new (alignedPtr) uint256(); // implicitly zero-initializes the data
                    unsigned initializedCtr = 0;
                    // ensure the regular default c'tor zero-initialized the very same buffer
                    for (const auto ch : *initialized) {
                        initializedCtr += unsigned(ch == 0x0); // false = 0, true = 1
                    }
                    BOOST_CHECK(initializedCtr == uint256::size());
                }
            }
        };

        RUN_CONTEXT();
    }

    const auto t2 = App::registerTest("uint256", uint256_tests); // register test with app-wide test system

    /** Generate a random 64-bit integer. */
    inline uint64_t rand64() noexcept { return QRandomGenerator::global()->generate64(); }

    inline uint64_t InsecureRandRange(uint64_t range) { return rand64() % range; }

    inline uint64_t InsecureRandBits(int bits) {
        if (bits == 0)
            return 0;
        else if (bits > 32)
            return rand64() >> (64 - bits);
        else
            return rand64() & (~uint64_t(0) >> (64 - bits));
    }

    template <typename Hasher, typename In, typename Out>
    void TestVector(const Hasher &h, const In &in, const Out &out) {
        using namespace bitcoin;
        Out hash;
        BOOST_CHECK(out.size() == h.OUTPUT_SIZE);
        hash.resize(out.size());
        {
            // Test that writing the whole input string at once works.
            Hasher(h).Write((uint8_t *)&in[0], in.size()).Finalize(&hash[0]);
            BOOST_CHECK(hash == out);
        }
        for (int i = 0; i < 32; ++i) {
            // Test that writing the string broken up in random pieces works.
            Hasher hasher(h);
            size_t pos = 0;
            while (pos < in.size()) {
                size_t len = InsecureRandRange((in.size() - pos + 1) / 2 + 1);
                hasher.Write((uint8_t *)&in[pos], len);
                pos += len;
                if (pos > 0 && pos + 2 * out.size() > in.size() &&
                    pos < in.size()) {
                    // Test that writing the rest at once to a copy of a hasher
                    // works.
                    Hasher(hasher)
                        .Write((uint8_t *)&in[pos], in.size() - pos)
                        .Finalize(&hash[0]);
                    BOOST_CHECK(hash == out);
                }
            }
            hasher.Finalize(&hash[0]);
            BOOST_CHECK(hash == out);
        }
    }


    // the below is taken from BCHN sources: src/test/crypto_tests.cpp
    void crypto_tests()
    {
        using namespace bitcoin;
        auto TestSHA1 = [](const std::string &in, const std::string &hexout) {
            TestVector(CSHA1(), in, ParseHex(hexout));
        };
        auto TestSHA256 = [](const std::string &in, const std::string &hexout) {
            TestVector(CSHA256(), in, ParseHex(hexout));
        };
        auto TestSHA512 = [](const std::string &in, const std::string &hexout) {
            TestVector(CSHA512(), in, ParseHex(hexout));
        };
        auto TestRIPEMD160 = [](const std::string &in, const std::string &hexout) {
            TestVector(CRIPEMD160(), in, ParseHex(hexout));
        };
        auto TestHMACSHA256 = [](const std::string &hexkey, const std::string &hexin, const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            TestVector(CHMAC_SHA256(key.data(), key.size()), ParseHex(hexin), ParseHex(hexout));
        };
        auto TestHMACSHA512 = [](const std::string &hexkey, const std::string &hexin, const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            TestVector(CHMAC_SHA512(key.data(), key.size()), ParseHex(hexin), ParseHex(hexout));
        };
        auto TestAES128 = [](const std::string &hexkey, const std::string &hexin, const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            std::vector<uint8_t> in = ParseHex(hexin);
            std::vector<uint8_t> correctout = ParseHex(hexout);
            std::vector<uint8_t> buf, buf2;

            assert(key.size() == 16);
            assert(in.size() == 16);
            assert(correctout.size() == 16);
            AES128Encrypt enc(key.data());
            buf.resize(correctout.size());
            buf2.resize(correctout.size());
            enc.Encrypt(buf.data(), in.data());
            BOOST_CHECK_EQUAL(HexStr(buf), HexStr(correctout));
            AES128Decrypt dec(key.data());
            dec.Decrypt(buf2.data(), buf.data());
            BOOST_CHECK_EQUAL(HexStr(buf2), HexStr(in));
        };
        auto TestAES256 = [](const std::string &hexkey, const std::string &hexin, const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            std::vector<uint8_t> in = ParseHex(hexin);
            std::vector<uint8_t> correctout = ParseHex(hexout);
            std::vector<uint8_t> buf;

            assert(key.size() == 32);
            assert(in.size() == 16);
            assert(correctout.size() == 16);
            AES256Encrypt enc(key.data());
            buf.resize(correctout.size());
            enc.Encrypt(buf.data(), in.data());
            BOOST_CHECK(buf == correctout);
            AES256Decrypt dec(key.data());
            dec.Decrypt(buf.data(), buf.data());
            BOOST_CHECK(buf == in);
        };
        auto TestAES128CBC = [](const std::string &hexkey, const std::string &hexiv, bool pad, const std::string &hexin,
                                const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            std::vector<uint8_t> iv = ParseHex(hexiv);
            std::vector<uint8_t> in = ParseHex(hexin);
            std::vector<uint8_t> correctout = ParseHex(hexout);
            std::vector<uint8_t> realout(in.size() + AES_BLOCKSIZE);

            // Encrypt the plaintext and verify that it equals the cipher
            AES128CBCEncrypt enc(key.data(), iv.data(), pad);
            int size = enc.Encrypt(in.data(), in.size(), realout.data());
            realout.resize(size);
            BOOST_CHECK(realout.size() == correctout.size());
            BOOST_CHECK_MESSAGE(realout == correctout,
                                HexStr(realout) + std::string(" != ") + hexout);

            // Decrypt the cipher and verify that it equals the plaintext
            std::vector<uint8_t> decrypted(correctout.size());
            AES128CBCDecrypt dec(key.data(), iv.data(), pad);
            size = dec.Decrypt(correctout.data(), correctout.size(), decrypted.data());
            decrypted.resize(size);
            BOOST_CHECK(decrypted.size() == in.size());
            BOOST_CHECK_MESSAGE(decrypted == in,
                                HexStr(decrypted) + std::string(" != ") + hexin);

            // Encrypt and re-decrypt substrings of the plaintext and verify that they
            // equal each-other
            for (std::vector<uint8_t>::iterator i(in.begin()); i != in.end(); ++i) {
                std::vector<uint8_t> sub(i, in.end());
                std::vector<uint8_t> subout(sub.size() + AES_BLOCKSIZE);
                int size_ = enc.Encrypt(sub.data(), sub.size(), subout.data());
                if (size_ != 0) {
                    subout.resize(size_);
                    std::vector<uint8_t> subdecrypted(subout.size());
                    size_ = dec.Decrypt(subout.data(), subout.size(), subdecrypted.data());
                    subdecrypted.resize(size_);
                    BOOST_CHECK(decrypted.size() == in.size());
                    BOOST_CHECK_MESSAGE(subdecrypted == sub,
                                        HexStr(subdecrypted) + std::string(" != ") + HexStr(sub));
                }
            }
        };
        auto TestAES256CBC = [](const std::string &hexkey, const std::string &hexiv, bool pad, const std::string &hexin,
                                const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            std::vector<uint8_t> iv = ParseHex(hexiv);
            std::vector<uint8_t> in = ParseHex(hexin);
            std::vector<uint8_t> correctout = ParseHex(hexout);
            std::vector<uint8_t> realout(in.size() + AES_BLOCKSIZE);

            // Encrypt the plaintext and verify that it equals the cipher
            AES256CBCEncrypt enc(key.data(), iv.data(), pad);
            int size = enc.Encrypt(in.data(), in.size(), realout.data());
            realout.resize(size);
            BOOST_CHECK(realout.size() == correctout.size());
            BOOST_CHECK_MESSAGE(realout == correctout,
                                HexStr(realout) + std::string(" != ") + hexout);

            // Decrypt the cipher and verify that it equals the plaintext
            std::vector<uint8_t> decrypted(correctout.size());
            AES256CBCDecrypt dec(key.data(), iv.data(), pad);
            size = dec.Decrypt(correctout.data(), correctout.size(), decrypted.data());
            decrypted.resize(size);
            BOOST_CHECK(decrypted.size() == in.size());
            BOOST_CHECK_MESSAGE(decrypted == in,
                                HexStr(decrypted) + std::string(" != ") + hexin);

            // Encrypt and re-decrypt substrings of the plaintext and verify that they
            // equal each-other
            for (std::vector<uint8_t>::iterator i(in.begin()); i != in.end(); ++i) {
                std::vector<uint8_t> sub(i, in.end());
                std::vector<uint8_t> subout(sub.size() + AES_BLOCKSIZE);
                int size_ = enc.Encrypt(sub.data(), sub.size(), subout.data());
                if (size_ != 0) {
                    subout.resize(size_);
                    std::vector<uint8_t> subdecrypted(subout.size());
                    size_ = dec.Decrypt(subout.data(), subout.size(), subdecrypted.data());
                    subdecrypted.resize(size_);
                    BOOST_CHECK(decrypted.size() == in.size());
                    BOOST_CHECK_MESSAGE(subdecrypted == sub,
                                        HexStr(subdecrypted) + std::string(" != ") + HexStr(sub));
                }
            }
        };
        auto TestChaCha20 = [](const std::string &hexkey, uint64_t nonce, uint64_t seek, const std::string &hexout) {
            std::vector<uint8_t> key = ParseHex(hexkey);
            ChaCha20 rng(key.data(), key.size());
            rng.SetIV(nonce);
            rng.Seek(seek);
            std::vector<uint8_t> out = ParseHex(hexout);
            std::vector<uint8_t> outres;
            outres.resize(out.size());
            rng.Output(outres.data(), outres.size());
            BOOST_CHECK(out == outres);
        };

        auto LongTestString = []() -> std::string {
            std::string ret;
            for (int i = 0; i < 200000; i++) {
                ret += uint8_t(i);
                ret += uint8_t(i >> 4);
                ret += uint8_t(i >> 8);
                ret += uint8_t(i >> 12);
                ret += uint8_t(i >> 16);
            }
            return ret;
        };

        const std::string test1 = LongTestString();

        SETUP_CONTEXT("crypto");

        BOOST_AUTO_TEST_CASE(ripemd160_testvectors) {
            TestRIPEMD160("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
            TestRIPEMD160("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
            TestRIPEMD160("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
            TestRIPEMD160("secure hash algorithm",
                          "20397528223b6a5f4cbc2808aba0464e645544f9");
            TestRIPEMD160("RIPEMD160 is considered to be safe",
                          "a7d78608c7af8a8e728778e81576870734122b66");
            TestRIPEMD160("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                          "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
            TestRIPEMD160(
                "For this sample, this 63-byte string will be used as input data",
                "de90dbfee14b63fb5abf27c2ad4a82aaa5f27a11");
            TestRIPEMD160(
                "This is exactly 64 bytes long, not counting the terminating byte",
                "eda31d51d3a623b81e19eb02e24ff65d27d67b37");
            TestRIPEMD160(std::string(1000000, 'a'),
                          "52783243c1697bdbe16d37f97f68f08325dc1528");
            TestRIPEMD160(test1, "464243587bd146ea835cdf57bdae582f25ec45f1");
        };

        BOOST_AUTO_TEST_CASE(sha1_testvectors) {
            TestSHA1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            TestSHA1("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
            TestSHA1("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3");
            TestSHA1("secure hash algorithm",
                     "d4d6d2f0ebe317513bbd8d967d89bac5819c2f60");
            TestSHA1("SHA1 is considered to be safe",
                     "f2b6650569ad3a8720348dd6ea6c497dee3a842a");
            TestSHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                     "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
            TestSHA1("For this sample, this 63-byte string will be used as input data",
                     "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49");
            TestSHA1("This is exactly 64 bytes long, not counting the terminating byte",
                     "fb679f23e7d1ce053313e66e127ab1b444397057");
            TestSHA1(std::string(1000000, 'a'),
                     "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
            TestSHA1(test1, "b7755760681cbfd971451668f32af5774f4656b5");
        };

        BOOST_AUTO_TEST_CASE(sha256_testvectors) {
            TestSHA256(
                "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            TestSHA256(
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            TestSHA256(
                "message digest",
                "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
            TestSHA256(
                "secure hash algorithm",
                "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
            TestSHA256(
                "SHA256 is considered to be safe",
                "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
            TestSHA256(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
            TestSHA256(
                "For this sample, this 63-byte string will be used as input data",
                "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
            TestSHA256(
                "This is exactly 64 bytes long, not counting the terminating byte",
                "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
            TestSHA256(
                "As Bitcoin relies on 80 byte header hashes, we want to have an "
                "example for that.",
                "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
            TestSHA256(
                std::string(1000000, 'a'),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
            TestSHA256(
                test1,
                "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26");
        };

        BOOST_AUTO_TEST_CASE(sha512_testvectors) {
            TestSHA512(
                "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
            TestSHA512(
                "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
            TestSHA512(
                "message digest",
                "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
                "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
            TestSHA512(
                "secure hash algorithm",
                "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3"
                "d5db502e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e");
            TestSHA512(
                "SHA512 is considered to be safe",
                "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a9964"
                "6b4a3901caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2");
            TestSHA512(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
                "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
            TestSHA512(
                "For this sample, this 63-byte string will be used as input data",
                "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e"
                "6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766");
            TestSHA512(
                "This is exactly 64 bytes long, not counting the terminating byte",
                "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38"
                "7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030");
            TestSHA512(
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
            TestSHA512(
                std::string(1000000, 'a'),
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
            TestSHA512(
                test1,
                "40cac46c147e6131c5193dd5f34e9d8bb4951395f27b08c558c65ff4ba2de594"
                "37de8c3ef5459d76a52cedc02dc499a3c9ed9dedbfb3281afd9653b8a112fafc");
        };

        BOOST_AUTO_TEST_CASE(hmac_sha256_testvectors) {
            // test cases 1, 2, 3, 4, 6 and 7 of RFC 4231
            TestHMACSHA256(
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
            TestHMACSHA256(
                "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
            TestHMACSHA256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                "dddddddddddddddddddddddddddddddddddd",
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
            TestHMACSHA256(
                "0102030405060708090a0b0c0d0e0f10111213141516171819",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
            TestHMACSHA256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaa",
                "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                "65204b6579202d2048617368204b6579204669727374",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
            TestHMACSHA256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaa",
                "5468697320697320612074657374207573696e672061206c6172676572207468"
                "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
                "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
                "647320746f20626520686173686564206265666f7265206265696e6720757365"
                "642062792074686520484d414320616c676f726974686d2e",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
            // Test case with key length 63 bytes.
            TestHMACSHA256(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "9de4b546756c83516720a4ad7fe7bdbeac4298c6fdd82b15f895a6d10b0769a6");
            // Test case with key length 64 bytes.
            TestHMACSHA256(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "528c609a4c9254c274585334946b7c2661bad8f1fc406b20f6892478d19163dd");
            // Test case with key length 65 bytes.
            TestHMACSHA256(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "d06af337f359a2330deffb8e3cbe4b5b7aa8ca1f208528cdbd245d5dc63c4483");
        };

        BOOST_AUTO_TEST_CASE(hmac_sha512_testvectors) {
            // test cases 1, 2, 3, 4, 6 and 7 of RFC 4231
            TestHMACSHA512(
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
            TestHMACSHA512(
                "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
            TestHMACSHA512(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                "dddddddddddddddddddddddddddddddddddd",
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
            TestHMACSHA512(
                "0102030405060708090a0b0c0d0e0f10111213141516171819",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
            TestHMACSHA512(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaa",
                "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                "65204b6579202d2048617368204b6579204669727374",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
            TestHMACSHA512(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "aaaaaa",
                "5468697320697320612074657374207573696e672061206c6172676572207468"
                "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
                "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
                "647320746f20626520686173686564206265666f7265206265696e6720757365"
                "642062792074686520484d414320616c676f726974686d2e",
                "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
                "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
            // Test case with key length 127 bytes.
            TestHMACSHA512(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "267424dfb8eeb999f3e5ec39a4fe9fd14c923e6187e0897063e5c9e02b2e624a"
                "c04413e762977df71a9fb5d562b37f89dfdfb930fce2ed1fa783bbc2a203d80e");
            // Test case with key length 128 bytes.
            TestHMACSHA512(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "43aaac07bb1dd97c82c04df921f83b16a68d76815cd1a30d3455ad43a3d80484"
                "2bb35462be42cc2e4b5902de4d204c1c66d93b47d1383e3e13a3788687d61258");
            // Test case with key length 129 bytes.
            TestHMACSHA512(
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
                "4a",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "0b273325191cfc1b4b71d5075c8fcad67696309d292b1dad2cd23983a35feb8e"
                "fb29795e79f2ef27f68cb1e16d76178c307a67beaad9456fac5fdffeadb16e2c");
        };

        BOOST_AUTO_TEST_CASE(aes_testvectors) {
            // AES test vectors from FIPS 197.
            TestAES128("000102030405060708090a0b0c0d0e0f",
                       "00112233445566778899aabbccddeeff",
                       "69c4e0d86a7b0430d8cdb78070b4c55a");
            TestAES256(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");

            // AES-ECB test vectors from NIST sp800-38a.
            TestAES128("2b7e151628aed2a6abf7158809cf4f3c",
                       "6bc1bee22e409f96e93d7e117393172a",
                       "3ad77bb40d7a3660a89ecaf32466ef97");
            TestAES128("2b7e151628aed2a6abf7158809cf4f3c",
                       "ae2d8a571e03ac9c9eb76fac45af8e51",
                       "f5d3d58503b9699de785895a96fdbaaf");
            TestAES128("2b7e151628aed2a6abf7158809cf4f3c",
                       "30c81c46a35ce411e5fbc1191a0a52ef",
                       "43b1cd7f598ece23881b00e3ed030688");
            TestAES128("2b7e151628aed2a6abf7158809cf4f3c",
                       "f69f2445df4f9b17ad2b417be66c3710",
                       "7b0c785e27e8ad3f8223207104725dd4");
            TestAES256(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8");
            TestAES256(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870");
            TestAES256(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d");
            TestAES256(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7");
        };

        BOOST_AUTO_TEST_CASE(aes_cbc_testvectors) {
            // NIST AES CBC 128-bit encryption test-vectors
            TestAES128CBC("2b7e151628aed2a6abf7158809cf4f3c",
                          "000102030405060708090A0B0C0D0E0F", false,
                          "6bc1bee22e409f96e93d7e117393172a",
                          "7649abac8119b246cee98e9b12e9197d");
            TestAES128CBC("2b7e151628aed2a6abf7158809cf4f3c",
                          "7649ABAC8119B246CEE98E9B12E9197D", false,
                          "ae2d8a571e03ac9c9eb76fac45af8e51",
                          "5086cb9b507219ee95db113a917678b2");
            TestAES128CBC("2b7e151628aed2a6abf7158809cf4f3c",
                          "5086cb9b507219ee95db113a917678b2", false,
                          "30c81c46a35ce411e5fbc1191a0a52ef",
                          "73bed6b8e3c1743b7116e69e22229516");
            TestAES128CBC("2b7e151628aed2a6abf7158809cf4f3c",
                          "73bed6b8e3c1743b7116e69e22229516", false,
                          "f69f2445df4f9b17ad2b417be66c3710",
                          "3ff1caa1681fac09120eca307586e1a7");

            // The same vectors with padding enabled
            TestAES128CBC(
                "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F",
                true, "6bc1bee22e409f96e93d7e117393172a",
                "7649abac8119b246cee98e9b12e9197d8964e0b149c10b7b682e6e39aaeb731c");
            TestAES128CBC(
                "2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D",
                true, "ae2d8a571e03ac9c9eb76fac45af8e51",
                "5086cb9b507219ee95db113a917678b255e21d7100b988ffec32feeafaf23538");
            TestAES128CBC(
                "2b7e151628aed2a6abf7158809cf4f3c", "5086cb9b507219ee95db113a917678b2",
                true, "30c81c46a35ce411e5fbc1191a0a52ef",
                "73bed6b8e3c1743b7116e69e22229516f6eccda327bf8e5ec43718b0039adceb");
            TestAES128CBC(
                "2b7e151628aed2a6abf7158809cf4f3c", "73bed6b8e3c1743b7116e69e22229516",
                true, "f69f2445df4f9b17ad2b417be66c3710",
                "3ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012");

            // NIST AES CBC 256-bit encryption test-vectors
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090A0B0C0D0E0F", false,
                "6bc1bee22e409f96e93d7e117393172a", "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "F58C4C04D6E5F1BA779EABFB5F7BFBD6", false,
                "ae2d8a571e03ac9c9eb76fac45af8e51", "9cfc4e967edb808d679f777bc6702c7d");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "9CFC4E967EDB808D679F777BC6702C7D", false,
                "30c81c46a35ce411e5fbc1191a0a52ef", "39f23369a9d9bacfa530e26304231461");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "39F23369A9D9BACFA530E26304231461", false,
                "f69f2445df4f9b17ad2b417be66c3710", "b2eb05e2c39be9fcda6c19078c6a9d1b");

            // The same vectors with padding enabled
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090A0B0C0D0E0F", true,
                "6bc1bee22e409f96e93d7e117393172a",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "F58C4C04D6E5F1BA779EABFB5F7BFBD6", true,
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "9cfc4e967edb808d679f777bc6702c7d3a3aa5e0213db1a9901f9036cf5102d2");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "9CFC4E967EDB808D679F777BC6702C7D", true,
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "39f23369a9d9bacfa530e263042314612f8da707643c90a6f732b3de1d3f5cee");
            TestAES256CBC(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "39F23369A9D9BACFA530E26304231461", true,
                "f69f2445df4f9b17ad2b417be66c3710",
                "b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644");
        };

        BOOST_AUTO_TEST_CASE(chacha20_testvector) {
            // Test vector from RFC 7539
            TestChaCha20(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                0x4a000000UL, 1,
                "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0a"
                "a372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b769a6749f3f63"
                "0f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c1"
                "67eacd901d7e2bf363");

            // Test vectors from
            // https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
            TestChaCha20(
                "0000000000000000000000000000000000000000000000000000000000000000", 0,
                0,
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da4"
                "1597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
            TestChaCha20(
                "0000000000000000000000000000000000000000000000000000000000000001", 0,
                0,
                "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe"
                "2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963");
            TestChaCha20(
                "0000000000000000000000000000000000000000000000000000000000000000",
                0x0100000000000000ULL, 0,
                "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a05"
                "0278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
            TestChaCha20(
                "0000000000000000000000000000000000000000000000000000000000000000", 1,
                0,
                "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111"
                "e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
            TestChaCha20(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                0x0706050403020100ULL, 0,
                "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a454"
                "7b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc"
                "35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563e"
                "b9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750"
                "32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d"
                "6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c89"
                "4c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d"
                "38407a6deb3ab78fab78c9");
        };

        BOOST_AUTO_TEST_CASE(countbits_tests) {
            for (unsigned int i = 0; i <= 64; ++i) {
                if (i == 0) {
                    // Check handling of zero.
                    BOOST_CHECK_EQUAL(CountBits(0), 0U);
                } else if (i < 10) {
                    for (uint64_t j = 1 << (i - 1); (j >> i) == 0; ++j) {
                        // Exhaustively test up to 10 bits
                        BOOST_CHECK_EQUAL(CountBits(j), i);
                    }
                } else {
                    for (int k = 0; k < 1000; ++k) {
                        // Randomly test 1000 samples of each length above 10 bits.
                        uint64_t j = uint64_t(1) << (i - 1) | InsecureRandBits(i - 1);
                        BOOST_CHECK_EQUAL(CountBits(j), i);
                    }
                }
            }
        };

        BOOST_AUTO_TEST_CASE(sha256d64) {
            for (int i = 0; i <= 32; ++i) {
                uint8_t in[64 * 32];
                uint8_t out1[32 * 32], out2[32 * 32];
                for (int j = 0; j < 64 * i; ++j) {
                    in[j] = InsecureRandBits(8);
                }
                for (int j = 0; j < i; ++j) {
                    CHash256().Write(in + 64 * j, 64).Finalize(out1 + 32 * j);
                }
                SHA256D64(out2, in, i);
                BOOST_CHECK(std::memcmp(out1, out2, 32 * i) == 0);
            }
        };

        RUN_CONTEXT();
    }

    const auto t3 = App::registerTest("crypto", crypto_tests); // register test with app-wide test system

    // -- prevectror_tests utility
    auto InsecureRand256() {
        bitcoin::uint256 ret{bitcoin::uint256::Uninitialized};
        QRandomGenerator::global()->generate(ret.begin(), ret.end());
        return ret;
    }
    template <unsigned int N, typename T> class prevector_tester {
        using realtype = std::vector<T>;
        realtype real_vector;
        realtype real_vector_alt;

        using pretype = bitcoin::prevector<N, T>;
        pretype pre_vector;
        pretype pre_vector_alt;

        using Size = typename pretype::size_type;
        bool passed = true;
        bitcoin::uint256 rand_seed;

        template <typename A, typename B> void local_check_equal(A a, B b) {
            local_check(a == b);
        }
        void local_check(bool b) { passed = passed && b; }
        void test() {
            const pretype &const_pre_vector = pre_vector;
            local_check_equal(real_vector.size(), pre_vector.size());
            local_check_equal(real_vector.empty(), pre_vector.empty());
            for (Size s = 0; s < real_vector.size(); ++s) {
                local_check(real_vector[s] == pre_vector[s]);
                local_check(&(pre_vector[s]) == &(pre_vector.begin()[s]));
                local_check(&(pre_vector[s]) == &*(pre_vector.begin() + s));
                local_check(&(pre_vector[s]) ==
                            &*((pre_vector.end() + s) - real_vector.size()));
            }
            // local_check(realtype(pre_vector) == real_vector);
            local_check(pretype(real_vector.begin(), real_vector.end()) ==
                        pre_vector);
            local_check(pretype(pre_vector.begin(), pre_vector.end()) ==
                        pre_vector);
            size_t pos = 0;
            for (const T &v : pre_vector) {
                local_check(v == real_vector[pos++]);
            }
            for (const T &v : reverse_iterate(pre_vector)) {
                local_check(v == real_vector[--pos]);
            }
            for (const T &v : const_pre_vector) {
                local_check(v == real_vector[pos++]);
            }
            for (const T &v : reverse_iterate(const_pre_vector)) {
                local_check(v == real_vector[--pos]);
            }
            bitcoin::CDataStream ss1(bitcoin::SER_DISK, 0);
            bitcoin::CDataStream ss2(bitcoin::SER_DISK, 0);
            ss1 << real_vector;
            ss2 << pre_vector;
            local_check_equal(ss1.size(), ss2.size());
            for (Size s = 0; s < ss1.size(); ++s) {
                local_check_equal(ss1[s], ss2[s]);
            }
            // check that unserialing again works, and yields identical results
            realtype deser_real_vector;
            pretype deser_pre_vector;
            ss1 >> deser_pre_vector;
            ss2 >> deser_real_vector;
            local_check_equal(real_vector, deser_real_vector);
            local_check_equal(pre_vector, deser_pre_vector);
        }

    public:
        void resize(Size s) {
            real_vector.resize(s);
            local_check_equal(real_vector.size(), s);
            pre_vector.resize(s);
            local_check_equal(pre_vector.size(), s);
            test();
        }

        void reserve(Size s) {
            real_vector.reserve(s);
            local_check(real_vector.capacity() >= s);
            pre_vector.reserve(s);
            local_check(pre_vector.capacity() >= s);
            test();
        }

        void insert(Size position, const T &value) {
            real_vector.insert(real_vector.begin() + position, value);
            pre_vector.insert(pre_vector.begin() + position, value);
            test();
        }

        void insert(Size position, Size count, const T &value) {
            real_vector.insert(real_vector.begin() + position, count, value);
            pre_vector.insert(pre_vector.begin() + position, count, value);
            test();
        }

        template <typename I> void insert_range(Size position, I first, I last) {
            real_vector.insert(real_vector.begin() + position, first, last);
            pre_vector.insert(pre_vector.begin() + position, first, last);
            test();
        }

        void erase(Size position) {
            real_vector.erase(real_vector.begin() + position);
            pre_vector.erase(pre_vector.begin() + position);
            test();
        }

        void erase(Size first, Size last) {
            real_vector.erase(real_vector.begin() + first,
                              real_vector.begin() + last);
            pre_vector.erase(pre_vector.begin() + first, pre_vector.begin() + last);
            test();
        }

        void update(Size pos, const T &value) {
            real_vector[pos] = value;
            pre_vector[pos] = value;
            test();
        }

        void push_back(const T &value) {
            real_vector.push_back(value);
            pre_vector.push_back(value);
            test();
        }

        void pop_back() {
            real_vector.pop_back();
            pre_vector.pop_back();
            test();
        }

        void clear() {
            real_vector.clear();
            pre_vector.clear();
        }

        void assign(Size n, const T &value) {
            real_vector.assign(n, value);
            pre_vector.assign(n, value);
        }

        Size size() const { return real_vector.size(); }

        Size capacity() const { return pre_vector.capacity(); }

        void shrink_to_fit() {
            pre_vector.shrink_to_fit();
            test();
        }

        void swap() {
            real_vector.swap(real_vector_alt);
            pre_vector.swap(pre_vector_alt);
            test();
        }

        void move() {
            real_vector = std::move(real_vector_alt);
            real_vector_alt.clear();
            pre_vector = std::move(pre_vector_alt);
            pre_vector_alt.clear();
        }

        void copy() {
            real_vector = real_vector_alt;
            pre_vector = pre_vector_alt;
        }

        ~prevector_tester() {
            BOOST_CHECK_MESSAGE(passed, "insecure_rand: " + rand_seed.ToString());
        }

        prevector_tester() {
            rand_seed = InsecureRand256();
        }
    };

    std::uint32_t InsecureRand32() { return QRandomGenerator::global()->generate(); }
    bool InsecureRandBool() { return QRandomGenerator::global()->generate() & 0x1; }

    void prevectorTests()
    {

        SETUP_CONTEXT("prevector");

        using namespace bitcoin;
        BOOST_AUTO_TEST_CASE(PrevectorTestInt) {
            for (int j = 0; j < 64; j++) {
                prevector_tester<8, int> test;
                for (int i = 0; i < 2048; i++) {
                    if (InsecureRandBits(2) == 0) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(2) == 1) {
                        test.erase(InsecureRandRange(test.size()));
                    }
                    if (InsecureRandBits(3) == 2) {
                        int new_size = std::max(
                            0, std::min(30, int(test.size()) +
                                                int(InsecureRandRange(5)) - 2));
                        test.resize(new_size);
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    1 + InsecureRandBool(), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 4) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBool()));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(4) == 5) {
                        test.push_back(InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(4) == 6) {
                        test.pop_back();
                    }
                    if (InsecureRandBits(5) == 7) {
                        int values[4];
                        int num = 1 + (InsecureRandBits(2));
                        for (int k = 0; k < num; k++) {
                            values[k] = InsecureRand32();
                        }
                        test.insert_range(InsecureRandRange(test.size() + 1), values,
                                          values + num);
                    }
                    if (InsecureRandBits(5) == 8) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBits(2)));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(5) == 9) {
                        test.reserve(InsecureRandBits(5));
                    }
                    if (InsecureRandBits(6) == 10) {
                        test.shrink_to_fit();
                    }
                    if (test.size() > 0) {
                        test.update(InsecureRandRange(test.size()), InsecureRand32());
                    }
                    if (InsecureRandBits(10) == 11) {
                        test.clear();
                    }
                    if (InsecureRandBits(9) == 12) {
                        test.assign(InsecureRandBits(5), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.swap();
                    }
                    if (InsecureRandBits(4) == 8) {
                        test.copy();
                    }
                    if (InsecureRandBits(5) == 18) {
                        test.move();
                    }
                }
            }
        };
        BOOST_AUTO_TEST_CASE(PrevectorTestShort) {
            for (int j = 0; j < 64; j++) {
                prevector_tester<18, short> test;
                for (int i = 0; i < 2048; i++) {
                    if (InsecureRandBits(2) == 0) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(2) == 1) {
                        test.erase(InsecureRandRange(test.size()));
                    }
                    if (InsecureRandBits(3) == 2) {
                        int new_size = std::max(
                            0, std::min(30, int(test.size()) +
                                                int(InsecureRandRange(5)) - 2));
                        test.resize(new_size);
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    1 + InsecureRandBool(), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 4) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBool()));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(4) == 5) {
                        test.push_back(InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(4) == 6) {
                        test.pop_back();
                    }
                    if (InsecureRandBits(5) == 7) {
                        int values[4];
                        int num = 1 + (InsecureRandBits(2));
                        for (int k = 0; k < num; k++) {
                            values[k] = InsecureRand32();
                        }
                        test.insert_range(InsecureRandRange(test.size() + 1), values,
                                          values + num);
                    }
                    if (InsecureRandBits(5) == 8) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBits(2)));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(5) == 9) {
                        test.reserve(InsecureRandBits(5));
                    }
                    if (InsecureRandBits(6) == 10) {
                        test.shrink_to_fit();
                    }
                    if (test.size() > 0) {
                        test.update(InsecureRandRange(test.size()), InsecureRand32());
                    }
                    if (InsecureRandBits(10) == 11) {
                        test.clear();
                    }
                    if (InsecureRandBits(9) == 12) {
                        test.assign(InsecureRandBits(5), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.swap();
                    }
                    if (InsecureRandBits(4) == 8) {
                        test.copy();
                    }
                    if (InsecureRandBits(5) == 18) {
                        test.move();
                    }
                }
            }
        };
        BOOST_AUTO_TEST_CASE(PrevectorTestUInt8) {
            for (int j = 0; j < 64; j++) {
                prevector_tester<28, uint8_t> test;
                for (int i = 0; i < 2048; i++) {
                    if (InsecureRandBits(2) == 0) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(2) == 1) {
                        test.erase(InsecureRandRange(test.size()));
                    }
                    if (InsecureRandBits(3) == 2) {
                        int new_size = std::max(
                            0, std::min(30, int(test.size()) +
                                                int(InsecureRandRange(5)) - 2));
                        test.resize(new_size);
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    1 + InsecureRandBool(), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 4) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBool()));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(4) == 5) {
                        test.push_back(InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(4) == 6) {
                        test.pop_back();
                    }
                    if (InsecureRandBits(5) == 7) {
                        int values[4];
                        int num = 1 + (InsecureRandBits(2));
                        for (int k = 0; k < num; k++) {
                            values[k] = InsecureRand32();
                        }
                        test.insert_range(InsecureRandRange(test.size() + 1), values,
                                          values + num);
                    }
                    if (InsecureRandBits(5) == 8) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBits(2)));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(5) == 9) {
                        test.reserve(InsecureRandBits(5));
                    }
                    if (InsecureRandBits(6) == 10) {
                        test.shrink_to_fit();
                    }
                    if (test.size() > 0) {
                        test.update(InsecureRandRange(test.size()), InsecureRand32());
                    }
                    if (InsecureRandBits(10) == 11) {
                        test.clear();
                    }
                    if (InsecureRandBits(9) == 12) {
                        test.assign(InsecureRandBits(5), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.swap();
                    }
                    if (InsecureRandBits(4) == 8) {
                        test.copy();
                    }
                    if (InsecureRandBits(5) == 18) {
                        test.move();
                    }
                }
            }
        };
        BOOST_AUTO_TEST_CASE(PrevectorTestInt64) {
            for (int j = 0; j < 64; j++) {
                prevector_tester<99, std::int64_t> test;
                for (int i = 0; i < 2048; i++) {
                    if (InsecureRandBits(2) == 0) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(2) == 1) {
                        test.erase(InsecureRandRange(test.size()));
                    }
                    if (InsecureRandBits(3) == 2) {
                        int new_size = std::max(
                            0, std::min(30, int(test.size()) +
                                                int(InsecureRandRange(5)) - 2));
                        test.resize(new_size);
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    1 + InsecureRandBool(), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 4) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBool()));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(4) == 5) {
                        test.push_back(InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(4) == 6) {
                        test.pop_back();
                    }
                    if (InsecureRandBits(5) == 7) {
                        int values[4];
                        int num = 1 + (InsecureRandBits(2));
                        for (int k = 0; k < num; k++) {
                            values[k] = InsecureRand32();
                        }
                        test.insert_range(InsecureRandRange(test.size() + 1), values,
                                          values + num);
                    }
                    if (InsecureRandBits(5) == 8) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBits(2)));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(5) == 9) {
                        test.reserve(InsecureRandBits(5));
                    }
                    if (InsecureRandBits(6) == 10) {
                        test.shrink_to_fit();
                    }
                    if (test.size() > 0) {
                        test.update(InsecureRandRange(test.size()), InsecureRand32());
                    }
                    if (InsecureRandBits(10) == 11) {
                        test.clear();
                    }
                    if (InsecureRandBits(9) == 12) {
                        test.assign(InsecureRandBits(5), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.swap();
                    }
                    if (InsecureRandBits(4) == 8) {
                        test.copy();
                    }
                    if (InsecureRandBits(5) == 18) {
                        test.move();
                    }
                }
            }
        };
        BOOST_AUTO_TEST_CASE(PrevectorTestChar) {
            for (int j = 0; j < 64; j++) {
                prevector_tester<17, char> test;
                for (int i = 0; i < 2048; i++) {
                    if (InsecureRandBits(2) == 0) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(2) == 1) {
                        test.erase(InsecureRandRange(test.size()));
                    }
                    if (InsecureRandBits(3) == 2) {
                        int new_size = std::max(
                            0, std::min(30, int(test.size()) +
                                                int(InsecureRandRange(5)) - 2));
                        test.resize(new_size);
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.insert(InsecureRandRange(test.size() + 1),
                                    1 + InsecureRandBool(), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 4) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBool()));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(4) == 5) {
                        test.push_back(InsecureRand32());
                    }
                    if (test.size() > 0 && InsecureRandBits(4) == 6) {
                        test.pop_back();
                    }
                    if (InsecureRandBits(5) == 7) {
                        int values[4];
                        int num = 1 + (InsecureRandBits(2));
                        for (int k = 0; k < num; k++) {
                            values[k] = InsecureRand32();
                        }
                        test.insert_range(InsecureRandRange(test.size() + 1), values,
                                          values + num);
                    }
                    if (InsecureRandBits(5) == 8) {
                        int del = std::min<int>(test.size(), 1 + (InsecureRandBits(2)));
                        int beg = InsecureRandRange(test.size() + 1 - del);
                        test.erase(beg, beg + del);
                    }
                    if (InsecureRandBits(5) == 9) {
                        test.reserve(InsecureRandBits(5));
                    }
                    if (InsecureRandBits(6) == 10) {
                        test.shrink_to_fit();
                    }
                    if (test.size() > 0) {
                        test.update(InsecureRandRange(test.size()), InsecureRand32());
                    }
                    if (InsecureRandBits(10) == 11) {
                        test.clear();
                    }
                    if (InsecureRandBits(9) == 12) {
                        test.assign(InsecureRandBits(5), InsecureRand32());
                    }
                    if (InsecureRandBits(3) == 3) {
                        test.swap();
                    }
                    if (InsecureRandBits(4) == 8) {
                        test.copy();
                    }
                    if (InsecureRandBits(5) == 18) {
                        test.move();
                    }
                }
            }
        };

        BOOST_AUTO_TEST_CASE(ThrowsBadAllocPlusComparisons) {
            auto LogBadAlloc = [](const std::bad_alloc &e) {
                Debug() << "Caught bad_alloc as expected: " << e.what();
                return true;
            };
            using PV = prevector<28, uint8_t, std::size_t, std::ptrdiff_t>;
            PV pv;
            pv.assign(100u, uint8_t(0x2f));
            BOOST_CHECK(pv == PV(100u, uint8_t(0x2f)));

            const auto *origptr = pv.data();
            BOOST_CHECK_EXCEPTION(pv.assign(std::numeric_limits<std::size_t>::max()-29, uint8_t(0)), std::bad_alloc,
                                  LogBadAlloc);
            // ensure that catching the bad_alloc didn't leak the old pointer
            BOOST_CHECK(pv.data() == origptr);
            BOOST_CHECK(pv.size() == 0); // but it should have set size to 0
            BOOST_CHECK(pv != PV(100u, uint8_t(0x2f))); // ensure !=
            BOOST_CHECK(pv != PV(100u, uint8_t(0))); // also not cleared
            BOOST_CHECK(pv == PV(0u, uint8_t(0))); // also should == empty vector
            BOOST_CHECK(std::memcmp(pv.data(), PV(100u, uint8_t(0x2f)).data(), 100) == 0);

            // check throws in c'tor
            BOOST_CHECK_EXCEPTION(PV(std::numeric_limits<std::size_t>::max()-29, uint8_t(0)), std::bad_alloc,
                                  LogBadAlloc);

            // check that our new handler was called on alloc failure
            static unsigned newHandlerCtr;
            auto myNewHandler = [] {
                if (++newHandlerCtr >= 5) {
                    Debug() << "New handler called 5 times, setting to nullptr to exit alloc-fail loop";
                    std::set_new_handler(nullptr);
                }
            };
            newHandlerCtr = 0;
            auto *oldHandler = std::set_new_handler(myNewHandler);
            BOOST_CHECK_EXCEPTION(PV(std::numeric_limits<std::size_t>::max()-29, uint8_t(0)), std::bad_alloc,
                                  LogBadAlloc);
            BOOST_CHECK(newHandlerCtr == 5);
            newHandlerCtr = 0;
            std::set_new_handler(oldHandler);

            pv = PV(40u, uint8_t(1));
            PV pv2(40u, uint8_t(1));

            BOOST_CHECK(pv == pv2);
            BOOST_CHECK(!(pv < pv2));
            pv2[39] = 2;
            BOOST_CHECK(pv != pv2);
            BOOST_CHECK(pv < pv2);
            pv[39] = 2;
            BOOST_CHECK(pv == pv2);
            BOOST_CHECK(!(pv < pv2));
            pv[38] = 0;
            BOOST_CHECK(pv != pv2);
            BOOST_CHECK(pv < pv2);

            pv2.resize(35);
            BOOST_CHECK(pv != pv2);
            BOOST_CHECK(pv2 < pv);
        };

        RUN_CONTEXT();
    }

    const auto t4 = App::registerTest("prevector", prevectorTests); // register test with app-wide test system

    void copyablePtrTests() {
        static const auto RandomData = []() -> std::vector<uint8_t> {
            bitcoin::uint256 r = InsecureRand256();
            return {r.begin(), r.end()};
        };
        SETUP_CONTEXT("copyable_ptr");

        BOOST_AUTO_TEST_CASE(copyable_ptr_test) {
            using bitcoin::CopyablePtr;
            // Test basic operation
            CopyablePtr<std::vector<uint8_t>> p, p2;
            // default constructed value should have nothing in it
            BOOST_CHECK(!p);
            BOOST_CHECK(p.get() == nullptr);
            BOOST_CHECK(p == p2); // nulls compare equal
            BOOST_CHECK(!(p != p2)); // nulls are never not equal (test operator!=)
            BOOST_CHECK(!(p < p2)); // nulls are not less than

            // assign a real value to p but not to p2
            const std::vector<uint8_t> data1 = RandomData();
            BOOST_CHECK(!p);
            p = data1;
            BOOST_CHECK(bool(p));
            // Test comparison ops ==, !=, and <
            BOOST_CHECK(*p == data1);
            BOOST_CHECK(p == data1);
            BOOST_CHECK(!(p < data1)); // operator< should return false
            BOOST_CHECK(!(p != data1));
            BOOST_CHECK(p.get() != &data1);
            BOOST_CHECK(p2 < data1); // nullptr p2 is always less than data1
            BOOST_CHECK(p2 != data1); // nullptr p2 is always not equal to data1
            BOOST_CHECK(!(p2 == data1)); // nullptr p2 is always not equal to data1 (test opeerator==)
            // decrement the last byte(s) of *p
            BOOST_CHECK(!p->empty());
            for (auto rit = p->rbegin(); rit != p->rend(); ++rit)
                if ((*rit)-- != 0) break;
            // p should now compare less
            BOOST_CHECK(p < data1);
            BOOST_CHECK(p != data1);
            BOOST_CHECK(!(p == data1)); // operator==
            BOOST_CHECK(data1 > *p);

            // assign p2 from p
            BOOST_CHECK(!p2);
            p2 = p;
            BOOST_CHECK(bool(p2));
            BOOST_CHECK(p.get() != p2.get());
            BOOST_CHECK(p == p2);
            BOOST_CHECK(!(p != p2));
            BOOST_CHECK(!(p < p2));

            // assign data1 to p2
            p2 = data1;
            BOOST_CHECK(bool(p2));
            BOOST_CHECK(p.get() != p2.get());
            BOOST_CHECK(!(p == p2));
            BOOST_CHECK(p != p2);
            BOOST_CHECK(p < p2);

            // check reset and emplace
            p.reset();
            const void *oldp2_ptr = p2.get();
            p2.emplace(data1.size(), 0x0); // assign all 0's to p2 using the emplace() method
            BOOST_CHECK(p2.get() != oldp2_ptr); // emplacing should have created a new object in a different heap location (and deleted the old)
            BOOST_CHECK(!p);
            BOOST_CHECK(!p.get());
            BOOST_CHECK(p2);
            BOOST_CHECK(p2.get());
            BOOST_CHECK(p != p2);
            BOOST_CHECK(p < p2); // p is null, should always be less than p2
            BOOST_CHECK(!(p == p2)); // operator== where p is nullptr
            BOOST_CHECK((p2 == std::vector<uint8_t>(data1.size(), 0x0)));
            BOOST_CHECK((p2 != std::vector<uint8_t>(data1.size(), 0x1)));
            BOOST_CHECK((p2 < std::vector<uint8_t>(data1.size(), 0x1)));

            p2.reset();
            BOOST_CHECK(!p2);
            BOOST_CHECK(p == p2);
            BOOST_CHECK(p.get() == nullptr && p2.get() == nullptr);

            // test construction in-place
            BOOST_CHECK(CopyablePtr<std::vector<uint8_t>>(100, 0x80) == CopyablePtr<std::vector<uint8_t>>(100, 0x80));
            BOOST_CHECK(CopyablePtr<std::vector<uint8_t>>(100, 0x80) != CopyablePtr<std::vector<uint8_t>>(100, 0x81));
            BOOST_CHECK(CopyablePtr<std::vector<uint8_t>>(100, 0x80) < CopyablePtr<std::vector<uint8_t>>(100, 0x81));
        };

        RUN_CONTEXT();
    }

    const auto t5 = App::registerTest("copyable_ptr", copyablePtrTests); // register test with app-wide test system
}
#endif
