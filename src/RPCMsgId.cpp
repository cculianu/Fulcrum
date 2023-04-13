//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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
