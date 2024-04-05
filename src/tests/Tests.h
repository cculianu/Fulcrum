//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#pragma once

#ifndef ENABLE_TESTS
static_assert(false, "This header requires preprocessor define: ENABLE_TESTS");
#endif

#include "App.h"
#include "Common.h"
#include "Util.h"

#include <QRandomGenerator>
#include <QString>

#include <cassert>
#include <cstring>
#include <functional>
#include <list>
#include <vector>

namespace Tests {

    template <typename ByteT, std::enable_if_t<sizeof(ByteT) == 1, int> = 0>
    void GetRandBytes(ByteT *dest, std::size_t count) { Util::getRandomBytes(dest, count); }

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
    inline std::uint32_t InsecureRand32() { return QRandomGenerator::global()->generate(); }
    inline bool InsecureRandBool() { return QRandomGenerator::global()->generate() & 0x1; }

    /// BCHN Unit Test work-alike support ...
    struct Context {
        const QString name;
        unsigned  nChecks = 0, nChecksFailed = 0, nChecksOk = 0;
        using VoidFunc = std::function<void()>;
        std::list<std::pair<QString, VoidFunc>> tests;
        inline static std::list<Context *> stack;
        static void throwIfStackEmpty() {
            if (stack.empty() || stack.back() == nullptr)
                throw Exception("Context stack is empty!");
        }

        static Context & cur() { throwIfStackEmpty(); return *stack.back(); }

        explicit Context(const QString &name) : name(name) { stack.push_back(this); }
        ~Context() { throwIfStackEmpty(); stack.pop_front(); }

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

    // Some macros used below so we can just copy-paste unit tests from BCHN without changing them
#define TEST_RUN_CONTEXT() Tests::Context::cur().runAll()
#if defined(__LINE__) && defined(__FILE__)
#    define TEST_SETUP_CONTEXT(name) Tests::Context testContext ## __LINE__(name)
#    define TEST_CHECK(expr) Tests::Context::cur().checkExpr(#expr, (expr), __LINE__, __FILE__)
#    define TEST_CHECK_MESSAGE(expr, msg) Tests::Context::cur().checkExpr(#expr, (expr), __LINE__, __FILE__, msg)
#else
#    define TEST_SETUP_CONTEXT(name) Tests::Context testContext(name)
#    define TEST_CHECK(expr) Tests::Context::cur().checkExpr(#expr, (expr), 0, "???")
#    define TEST_CHECK_MESSAGE(expr, msg) Tests::Context::cur().checkExpr(#expr, (expr), 0, "???", msg)
#endif
#define TEST_CHECK_EQUAL(a, b) TEST_CHECK((a) == (b))
#define TEST_CHECK_EXCEPTION(expr, exc, pred) \
    do { \
            bool is_ok_ = false; \
        try { \
                expr; \
        } catch (const exc &e) { \
                is_ok_ = pred(e); \
        } \
            TEST_CHECK_MESSAGE(is_ok_, "Expression: \"" #expr "\" should throw \"" #exc "\" and satisfy pred"); \
    } while (0)
#define TEST_CHECK_THROW(expr, exc) TEST_CHECK_EXCEPTION(expr, exc, [](auto &&){ return true; })
#define TEST_CHECK_NO_THROW(expr) \
        do { \
            bool is_ok_ = true; \
        try { \
                expr; \
        } catch (...) { \
                is_ok_ = false; \
        } \
            TEST_CHECK_MESSAGE(is_ok_, "Expression: \"" #expr "\" should not throw"); \
    } while (0)
#define TEST_CASE(name) \
        Tests::Context::cur().tests.emplace_back( #name, Tests::Context::VoidFunc{} ); \
        Tests::Context::cur().tests.back().second = [&]

#define TEST_SUITE(name) \
    namespace { \
        void name ## _test_func(); \
        const auto name ## __COUNTER__ = ::App::registerTest( #name , name ## _test_func ); \
        void name ## _test_func() { \
            using namespace Tests; \
            TEST_SETUP_CONTEXT( #name );
#define TEST_SUITE_END() \
            TEST_RUN_CONTEXT(); \
        } /* end name_test_func */ \
    } // namespace

} // namespace Tests
