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
#include "Common.h"
#include "RPCMsgId.h"
#include "Util.h"

#include <QHash>
#include <QMetaType>
#include <QtGlobal>

#include <cmath>
#include <limits>

/* static */
RPCMsgId RPCMsgId::fromVariant(const QVariant &qvar)
{
    static const double Epsilon = std::nextafter(0., 1.);
    RPCMsgId ret;

    if (!qvar.isNull()) {
        if (!qvar.isValid())
            throw BadArgs(QString("Invalid QVariant specified in %1").arg(__func__));
        // note as per JSON-RPC 2.0 spec, we squash floats down to ints, discarding the fractional part
        // we will throw if the id is not a string, integer, or null
        bool ok{};
        int64_t id_ll;
        if (auto mtype = Compat::GetVarType(qvar); mtype == QMetaType::QString) {
            ret = qvar.toString();
        } else if (UNLIKELY(mtype == QMetaType::QByteArray)) {
            ret = QString::fromUtf8(qvar.toByteArray());
        } else if (mtype == QMetaType::Bool) {
            throw BadArgs("Booleans are not supported");
        } else if (mtype == QMetaType::Int || mtype == QMetaType::UInt || mtype == QMetaType::Long || mtype == QMetaType::LongLong) {
            ret = int64_t(qvar.toLongLong(&ok));
            if (!ok) throw BadArgs("QVariant::toLongLong returned false");
        } else if (mtype == QMetaType::ULong || mtype == QMetaType::ULongLong) {
            qulonglong qull = qvar.toULongLong(&ok);
            if (!ok || qull > qulonglong(std::numeric_limits<int64_t>::max()))
                throw BadArgs("Unable to convert to int64 from qulong/qulonglong");
            ret = int64_t(qull);
        // note the below will fail at non-fractional integers > 2^53 (or 9 quadrillion)
        } else if (double id_dbl = qvar.toDouble(&ok); ok && std::abs(double(id_ll=int64_t(id_dbl)) - id_dbl) <= Epsilon) { // this checks that fractional part not present
            ret = id_ll;
        } else {
            // if we get here, id is not a valid type as per our restricted JSON RPC 2.0 (we don't accept fractional parts for id)
            throw BadArgs("Expected a string, a non-fractional number, or null");
        }
    }

    return ret;
}

QVariant RPCMsgId::toVariant() const
{
    QVariant ret;
    std::visit(Overloaded{
                   [](Null) {},
                   [&ret](const QString &s) { ret.setValue(s); },
                   [&ret](const int64_t i) { ret.setValue(i); }
               }, var);
    return ret;
}

int64_t RPCMsgId::toInt() const
{
    return std::visit(Overloaded{
                          [](Null) { return int64_t{0}; },
                          [](const QString &s) { return int64_t(s.toLongLong()); },
                          [](const int64_t i) { return i; }
                      }, var);
}

QString RPCMsgId::toString() const
{
    return std::visit(Overloaded{
                          [](Null) { return QStringLiteral("null"); },
                          [](const QString &s) { return s; },
                          [](const int64_t i) { return QString::number(qint64(i)); }
                      }, var);
}

#ifdef ENABLE_TESTS
#include "App.h"

#include <unordered_set>

namespace {
    using Print = Log;

    bool doTest()
    {
        size_t ctr = 0;
        const Tic t0;
#undef STR
#undef CHK
#define STR(x) #x
#define CHK(x) \
        do { \
                ++ctr; \
                if ( ! (x) ) { \
                    Error() << "Test: \"" << STR(x) << "\" failed!"; \
                    return false; \
            } else { \
                    Print() << "Test: \"" << STR(x) << "\"" << " passed"; \
            } \
        } while(0)
#define CHKEXC(x, exc) \
        do { \
            try { \
                (x); \
            } catch (const exc &) { \
                ++ctr; \
                Print() << "Test \"" << STR(x) << "\" throws \"" << STR(exc) << "\" passed"; \
            } catch (...) {\
                Error() << "Test: \"" << STR(x) << "\" throws \"" << STR(exc) << "\" failed!"; \
                return false; \
            } \
        } while (0)

        CHK(RPCMsgId().isNull());
        CHK(!RPCMsgId(123).isNull());
        CHK(!RPCMsgId("hello").isNull());

        RPCMsgId r;
        CHK(r.isNull());
        CHK(RPCMsgId() == r);
        r = RPCMsgId::fromVariant(QVariant{123});
        CHK(RPCMsgId() != r);
        CHK(!r.isNull());
        RPCMsgId r2 = r;
        CHK(r == r2);
        r2.setNull();
        CHK(r2.isNull());
        CHK(r2 != r);
        CHK(RPCMsgId{} == r2);
        CHK(RPCMsgId{} < r);
        CHK(r.toInt() == 123);
        CHK(r2.toInt() == 0);
        CHK(r.toString() == "123");
        CHK(r2.toString() == "null");
        CHK(r < RPCMsgId::fromVariant(QVariant(124)));
        CHK(r != RPCMsgId::fromVariant(QVariant(124)));
        CHK(RPCMsgId::fromVariant(QVariant(124)) > r);
        CHK(RPCMsgId::fromVariant(QVariant(124)) < RPCMsgId::fromVariant(QVariant(125)));
        CHK(r != RPCMsgId("123"));
        CHK(RPCMsgId("123").toInt() == 123);
        CHK(RPCMsgId("123").toString() == "123");
        CHK(r < RPCMsgId("123"));
        CHK(r != RPCMsgId::fromVariant("123"));
        CHK(r == RPCMsgId::fromVariant(123.0));
        CHKEXC(RPCMsgId::fromVariant(123.01), BadArgs);
        CHKEXC(RPCMsgId::fromVariant(2.000000000000001), BadArgs);
        CHK(RPCMsgId::fromVariant("2.000000000000001").toString() == "2.000000000000001");
        CHK(RPCMsgId::fromVariant(2.0000000000000001) == RPCMsgId{2}); // impl. quirk: if the fractional part is too small, we map to integer :/
        CHK(RPCMsgId::fromVariant("2.0000000000000001") != RPCMsgId{2});
        CHK(RPCMsgId::fromVariant("2.0000000000000001").toString() ==  "2.0000000000000001");
        const auto metaTypeForInt64 = []{
            QVariant v;
            v.setValue(int64_t{});
            return Compat::GetVarType(v); // this varies depending on platform, not always LongLong
        }();
        CHK(metaTypeForInt64 == QMetaType::Long || metaTypeForInt64 == QMetaType::LongLong);
        CHK(Compat::GetVarType(r.toVariant()) == metaTypeForInt64);
        CHK(Compat::GetVarType(RPCMsgId::fromVariant("123").toVariant()) == QMetaType::QString);
        CHK(Compat::GetVarType(RPCMsgId::fromVariant(123.0).toVariant()) == metaTypeForInt64);
        CHK(RPCMsgId::fromVariant(QVariant{}).toVariant().isNull());
        CHK(r.toVariant() == QVariant(123));
        CHK(r.toVariant() == QVariant(123.0));
        CHK(r.toVariant() != QVariant("123.0"));
        CHK(r.toVariant() == QVariant("123"));

        // operator=, .isint(), .isString(), .isNull()
        r.setNull();
        CHK(r.isNull());
        CHK(!r.isString());
        CHK(!r.isInt());
        r = "foo";
        CHK(!r.isNull());
        CHK(r.isString());
        CHK(!r.isInt());
        CHK(r.toString() == "foo");
        CHK(r.toInt() == 0);
        CHK(RPCMsgId("foo") == r);
        r.setNull();
        CHK(r.isNull());
        r = 999;
        CHK(!r.isNull());
        CHK(!r.isString());
        CHK(r.isInt());
        CHK(r.toString() == "999");
        CHK(r.toInt() == 999);
        CHK(RPCMsgId(999) == r);
        CHK(RPCMsgId("999") != r);

        std::unordered_set<RPCMsgId> s;

        s.emplace("hello");
        s.emplace("1");
        s.emplace("1.2");
        s.emplace("2");
        CHKEXC(s.emplace(RPCMsgId::fromVariant(1.2)), BadArgs);
        s.emplace(1);
        s.emplace(2);
        s.emplace();

        CHK(s.size() == 7);
        CHK(s.emplace(RPCMsgId::fromVariant(QVariant{})).second == false);
        CHK(s.size() == 7);

        QSet<RPCMsgId> qs;
        qs.insert(QString{"hello"});
        qs.insert(QString{"1"});
        qs.insert(QString{"1.2"});
        qs.insert(QString{"2"});
        CHKEXC(qs.insert(RPCMsgId::fromVariant(1.2)), BadArgs);
        qs.insert(1);
        qs.insert(2);
        qs.insert(RPCMsgId{});

        CHK(qs.size() == 7);
        CHK(qs.contains(RPCMsgId::fromVariant(QVariant{})));

        Print() << "rpcmsgid passed " << ctr << " checks ok in " << t0.msecStr() << " msecs";
        return true;
#undef STR
#undef CHK
    }

    const auto t = App::registerTest("rpcmsgid", []{
        if (!doTest()) throw Exception("rpcmsgid test failed");
    });
} // namespace

#endif
