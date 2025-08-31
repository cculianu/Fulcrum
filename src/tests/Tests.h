//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstring>
#include <functional>
#include <list>

namespace Tests {

    template <Util::ByteLike ByteT>
    void GetRandBytes(ByteT *dest, std::size_t count) { Util::getRandomBytes(dest, count); }

    /** Generate a random 64-bit integer. */
    inline uint64_t rand64() noexcept { return QRandomGenerator::global()->generate64(); }
    inline uint64_t InsecureRandRange(uint64_t range) { return rand64() % range; }
    inline uint64_t InsecureRandBits(unsigned bits) {
        if (bits == 0) return 0;
        return rand64() >> (64u - std::min(bits, 64u));
    }
    inline uint32_t InsecureRand32() { return QRandomGenerator::global()->generate(); }
    inline bool InsecureRandBool() { return QRandomGenerator::global()->generate() & 0x1; }

    enum Type { Test, Bench };

    /// BCHN Unit Test work-alike support ...
    struct Context {
        const QString name;
        const Type type;
        std::atomic_uint  nChecks = 0, nChecksFailed = 0, nChecksOk = 0;
        using VoidFunc = std::function<void()>;
        std::list<std::pair<QString, VoidFunc>> tests;
        inline static std::list<Context *> stack;
        static void throwIfStackEmpty() {
            if (stack.empty() || stack.back() == nullptr)
                throw Exception("Context stack is empty!");
        }

        static Context & cur() { throwIfStackEmpty(); return *stack.back(); }

        Context(const QString &name, const Type t) : name(name), type{t} { stack.push_back(this); }
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

        QString typeName(bool plural = false) const {
            switch(type) {
            case Bench: return plural ? "benches" : "bench"; break;
            case Test: return plural ? "tests" : "test"; break;
            }
        }

        void runAll() {
            unsigned nTests = 0;
            std::tie(nChecks, nChecksOk, nChecksFailed) = std::tuple(0u, 0u, 0u); // stats
            Tic t0;
            for (const auto & [tname, func] : tests) {
                Tic t1;
                ++nTests;
                if (tests.size() > 1 || tname != name)
                    // Only print the "running" like if we have more than 1 test or bench to run
                    Log(Log::BrightCyan) << "Running " << name << " " << typeName() << ": " << tname << " ...";
                const auto [b4checks, b4ok, b4failed] = std::tuple(nChecks.load(), nChecksOk.load(), nChecksFailed.load());
                func();
                const auto [checks, ok, failed] = std::tuple(nChecks.load(), nChecksOk.load(), nChecksFailed.load());
                if (failed > b4failed)
                    throw Exception(QString::number(failed - b4failed) + " checks failed for " + typeName() + ": " + tname);
                if (type == Test || checks - b4checks) {
                    Log() << (ok - b4ok) << "/" << (checks - b4checks) << " checks ok for " << tname << " in "
                          << t1.msecStr() << " msec";
                } else {
                    Log() << typeName() << " " << tname << " elapsed: " << t1.msecStr() << " msec";
                }
            }
            Log(!nChecksFailed ? Log::BrightCyan : Log::BrightRed) << name << ": ran " << nTests << " " << typeName(nTests > 1) << " total."
                  << [&]{
                         if (type == Test || nChecksOk || nChecksFailed)
                             return QString(" Checks: %1 passed, %2 failed.").arg(nChecksOk.load()).arg(nChecksFailed.load());
                        return QString("");
                     }() << " Elapsed: " << t0.msecStr() << " msec.";
        }
    };

// Some macros used below so we can just copy-paste unit tests from BCHN without changing them
#define TEST_RUN_CONTEXT() Tests::Context::cur().runAll()
#if defined(__LINE__) && defined(__FILE__)
#    define TEST_SETUP_CONTEXT(name, typ) Tests::Context testContext ## __LINE__(name, typ)
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

#define TEST_OR_BENCH_SUITE(NAME, RFUNC, TYPE) \
    namespace { \
        void NAME ## _test_func(); \
        const auto NAME ## __COUNTER__ = ::App:: RFUNC ( #NAME , NAME ## _test_func ); \
        void NAME ## _test_func() { \
            using namespace Tests; \
            TEST_SETUP_CONTEXT( #NAME , TYPE );
#define TEST_SUITE(name) TEST_OR_BENCH_SUITE(name, registerTest, Test)
#define TEST_SUITE_END() \
            TEST_RUN_CONTEXT(); \
        } /* end name_test_func */ \
    } // namespace

#define BENCH_SUITE(name) TEST_OR_BENCH_SUITE(name, registerBench, Bench)
#define BENCHMARK(name) TEST_CASE(name)
#define BENCH_SUITE_END() TEST_SUITE_END()

} // namespace Tests
