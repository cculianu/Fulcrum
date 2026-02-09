//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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
// Portions of the below code are adapted from Bitcoin Cash Node's custom
// "UniValue" library, and they have the following copyrights and license:
// Copyright 2014 BitPay Inc.
// Copyright 2015 Bitcoin Core Developers
// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.
//
#ifdef ENABLE_TESTS
#include "App.h"
#include "Json.h"
#include "Util.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>

#include <cstdlib>
#include <cstdint>

namespace Json {
namespace {
    void bench() {
        const char * const dir = std::getenv("DATADIR");
        if (!dir) {
            Warning() << "Json benchmark requires the DATADIR environment variable, which should be a directory on the "
                         "filesystem containing *.json and/or *.json.qz files to use for the benchmark.";
            throw Exception("No DATADIR specified");
        }

        // print simdjson info, if any, to log
        if (App::logSimdJsonInfo())
            Log() << "---"; // something was logged, so separate it with ---

        QDir dataDir(dir);
        if (!dataDir.exists()) throw BadArgs(QString("DATADIR '%1' does not exist").arg(dir));
        const QStringList glob{{"*.json", "*.json.qz"}};
        auto files = dataDir.entryList(glob, QDir::Filter::Files);
        if (files.isEmpty()) throw BadArgs(QString("DATADIR '%1' does not have any %2 files").arg(dir).arg(glob.join(", ")));
        std::vector<QByteArray> fileData;
        std::size_t total = 0;
        Log() << "Reading " << files.size() << " " << glob.join(", ") << " files from DATADIR=" << dir << " ...";

        for (auto & fn : files) {
            const bool isqz = fn.endsWith(".qz");
            QFile f(dataDir.path() + QDir::separator() + fn);
            QFile::OpenMode flags = QFile::ReadOnly;
            if (!isqz) flags |= QFile::Text;
            if (!f.open(flags))
                throw Exception(QString("Cannot open %1").arg(f.fileName()));
            fileData.push_back(f.readAll());
            if (isqz) {
                fileData.back() = qUncompress(fileData.back());
                if (fileData.back().isEmpty())
                    throw Exception(QString("Error uncompressing %1").arg(fn));
            }
            total += fileData.back().size();
        }
        Log() << "Read " << total << " bytes total";
        std::vector<QVariant> parsed;
        parsed.reserve(fileData.size());
        int iters = 1;
        {
            auto itenv = std::getenv("ITERS");
            if (itenv) {
                bool ok;
                iters = QString(itenv).toInt(&ok);
                if (!ok || iters <= 0)
                    throw BadArgs("Expected ITERS= to be a positive integer");
            }
        }
        Log() << "---";
        Log() << "Benching custom Json lib parse: Iterating " << iters << " times ...";
        double t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & ba : fileData) {
                auto var = parseUtf8(ba, ParseOption::AcceptAnyValue, ParserBackend::Default);
                if (var.isNull()) throw Exception("Parse result is null");
                if (parsed.size() != fileData.size())
                    parsed.emplace_back(std::move(var)); // save parsed data
            }
        }
        double tf = Util::getTimeSecs();
        Log() << "Custom lib parse - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";


        Log() << "---";
        decltype (parsed) qparsed;
        qparsed.reserve(fileData.size());
        Log() << "Benching Qt Json parse: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & ba : fileData) {
                QJsonParseError err;
                auto d = QJsonDocument::fromJson(ba, &err);
                if (d.isNull())
                    throw Exception(QString("Could not parse: %1").arg(err.errorString()));
                auto var = d.toVariant();
                if (var.isNull()) throw Exception("Parse result is null");
                if (qparsed.size() != fileData.size())
                    qparsed.emplace_back(std::move(var)); // save parsed data
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Qt Json parse - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        decltype (parsed) sjparsed;
        if (isParserAvailable(ParserBackend::SimdJson)) {
            Log() << "---";
            Log() << "Benching simdjson Json parse: Iterating " << iters << " times ...";
            sjparsed.reserve(fileData.size());
            t0 = Util::getTimeSecs();
            for (int i = 0; i < iters; ++i) {
                for (const auto & ba : fileData) {
                    auto var = parseUtf8(ba, ParseOption::AcceptAnyValue, ParserBackend::SimdJson);
                    if (var.isNull()) throw Exception("Parse result is null");
                    if (sjparsed.size() != fileData.size())
                        sjparsed.emplace_back(std::move(var));
                }
            }
            tf = Util::getTimeSecs();
            Log() << "simdjson Json parse - total: " << (tf-t0) << " secs" << " - per-iter: "
                  << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";
        }

        Log() << "---";
        Log() << "Benching custom Json lib serialize: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & var : parsed) {
                auto json = serialize(var, 4); // throw on error
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Custom lib serialize - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        Log() << "---";
        Log() << "Benching Qt lib serialize: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & var : qparsed) {
                auto d = QJsonDocument::fromVariant(var);
                auto json = d.toJson(QJsonDocument::JsonFormat::Indented);
                if (json.isEmpty()) throw Exception("Serializaiton error");
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Qt lib serialize - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        Log() << "---";
    }

    void testImpl(bool useSimdJson)
    {
        const auto parser = useSimdJson ? ParserBackend::SimdJson : ParserBackend::Default;
        Log() << (useSimdJson ? "Testing with simdjson backend ..." : "Testing with default backend ...");
        // basic tests
        {
            const auto expect1 = "[\"astring\",\"anotherstring\",\"laststring\",null]";
            const auto expect2 = "[\"astringl1\",\"anotherstringl2\",\"laststringl3\",\"\"]";
            const auto expect3 = "{\"7 item list\":[1,true,false,1.4e-07,null,{},[-777777.293678102,null,1.000000000000001,"
                                 "-999999999999999999]],\"a bytearray\":\"bytearray\",\"a null\":null,"
                                 "\"a null bytearray\":null,\"a null string\":\"\",\"a string\":\"hello\","
                                 "\"an empty bytearray\":null,\"an empty string\":\"\",\"another empty bytearray\":"
                                 "null,\"empty balist\":[],\"empty strlist\":[],\"empty vlist\":[],\"nested map key\":"
                                 "3.140000001,\"u64_max\":18446744073709551615,\"z_i64_min\":-9223372036854775808}";
            QByteArray json;
            QByteArrayList bal = {{ "astring", "anotherstring", "laststring", QByteArray{} }};
            QVariant v;
            v.setValue(bal);
            Log() << "QByteArrayList -> JSON: " << (json=toUtf8(v, true, SerOption::BareNullOk));
            if (json != expect1) throw Exception(QString("Json does not match, excpected: %1").arg(expect1));
            QStringList sl = {{ "astringl1", "anotherstringl2", "laststringl3", QString{} }};
            v.setValue(sl);
            Log() << "QStringList -> JSON: " << (json=toUtf8(v, true, SerOption::BareNullOk));
            if (json != expect2) throw Exception(QString("Json does not match, excpected: %1").arg(expect2));
            Log() << "Parse \"1.01000\": " << (json=toUtf8(parseUtf8("1.01000", ParseOption::AcceptAnyValue, parser), true, SerOption::BareNullOk));
            if (json != "1.01") throw Exception(QString("Json does not match, excpected: %1").arg("1.01"));
            QVariantHash h;
            QByteArray empty; empty.resize(10); empty.resize(0);
            h["key1"] = 1.2345;
            h["another key"] = sl;
            h["mapkey"] = QVariantMap{{
               {"nested map key", 3.140000001},
               {"a null", QVariant{}},
               {"a null bytearray", QByteArray{}},
               {"a null string", QString{}},
               {"an empty string", QString{""}},
               {"an empty bytearray", QByteArray{""}},
               {"another empty bytearray", empty},
               {"a string", QString{"hello"}},
               {"a bytearray", QByteArray{"bytearray"}},
               {"empty vlist", QVariantList{}},
               {"empty strlist", QStringList{}},
               {"empty balist", QVariant::fromValue(QByteArrayList{})},
               {"7 item list", QVariantList{{
                    1,true,false,14e-8,QVariant{}, QVariantMap{}, QVariantList{{-777777.293678102, QVariant{},
                    1.000000000000001, qlonglong(-999999999999999999)}}}},
               },
               {"u64_max", qulonglong(18446744073709551615ULL)},
               {"z_i64_min", qlonglong(0x8000000000000000LL)},
            }};
            Log() << "QVariantHash -> JSON: " << toUtf8(h, true, SerOption::BareNullOk);
            // we can't do the top-level hash since that has random order based on hash seed.. so we do this
            json = toUtf8(h, false /* !compact */, SerOption::BareNullOk);
            auto hh = parseUtf8(json, ParseOption::RequireObject, parser).toMap();
            json = toUtf8(hh["mapkey"], true, SerOption::BareNullOk);
            if (json != expect3) throw Exception(QString("Json \"mapkey\" does not match\nexcpected:\n%1\n\ngot:\n%2").arg(expect3).arg(QString(json)));
            Log() << "Basic tests: passed";
        }
        // /end basic tests
        const char *dir = std::getenv("DATADIR");
        if (!dir) dir = "test/json";
        QDir dataDir(dir);
        if (!dataDir.exists()) throw BadArgs(QString("DATADIR '%1' does not exist").arg(dir));
        struct TFile {
            QString path;
            bool wantsFail{}, wantsRound{};
        };
        std::list<TFile> files;
        for (auto & file : dataDir.entryList({{"*.json"}}, QDir::Filter::Files)) {
            TFile t;
            if (file.startsWith("pass"))
                t.wantsFail = false;
            else if (file.startsWith("fail")) {
                if (useSimdJson) {
                    t.wantsRound = file.contains("_round_sj.");
                    t.wantsFail = !t.wantsRound && !file.contains("_pass_sj.");
                } else
                    t.wantsFail = true;
            } else if (file.startsWith("round"))
                t.wantsFail = false, t.wantsRound = true;
            else
                // skip unrelated json file
                continue;
            t.path = dataDir.path() + QDir::separator() + file;
            files.push_back(std::move(t));
        }
        if (files.empty()) throw BadArgs(QString("DATADIR '%1' does not have any [pass/fail/round]*.json files").arg(dir));
        Log() << "Found " << files.size() << " json test files, running extended tests ...";
        const auto runTest = [parser](const TFile &t) {
            QFile f(t.path);
            auto baseName = QFileInfo(t.path).baseName();
            if (!f.open(QFile::ReadOnly|QFile::Text))
                throw Exception(QString("Cannot open %1").arg(f.fileName()));
            const QByteArray json = f.readAll();
            QVariant var;
            bool didFail = false;
            try {
                var = parseUtf8(json, ParseOption::AcceptAnyValue, parser);
            } catch (...) {
                if (!t.wantsFail)
                    throw;
                didFail = true;
            }
            if (t.wantsFail && !didFail)
                throw Exception(QString("Expected to fail test: %1 (Json: %2)").arg(baseName).arg(QString(toUtf8(var, true, SerOption::BareNullOk))));
            if (t.wantsRound) {
                if (auto json2 = toUtf8(var, true, SerOption::BareNullOk); json.trimmed() != json2.trimmed())
                    throw Exception(QString("Round-trip deser/ser failed for: %1\n\nExpected:\n%2\nHex: %3\n\nGot:\n%4\nHex: %5").arg(baseName)
                                    .arg(QString(json)).arg(QString(json.toHex()))
                                    .arg(QString(json2)).arg(QString(json2.toHex())));
            }
            Log() << baseName << ": passed";
        };
        for (const auto & t : files)
            runTest(t);
    }

    void test() {
        // run tests twice both without and with simdjson (if available)
        testImpl(false); // regular backend
        if (isParserAvailable(ParserBackend::SimdJson))
                testImpl(true); // simdjson backend
    }

    static const auto bench_ = App::registerBench("json", &bench);
    static const auto test_  = App::registerTest("json", &test);
}
}
#endif
