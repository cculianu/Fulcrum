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
#include "Compat.h"
#include "Util.h"

#include <QHash>
#include <QString>
#include <QVariant>

#include <cstdint>
#include <functional> // for std::hash
#include <utility>
#include <variant>

/// This class is designed to be basically a constrained variant: either null,
/// an integer, or a string suitable for using with a JSON-RPC 2.0 "id".
class RPCMsgId
{
    using Null = std::monostate;
    std::variant<Null, int64_t, QString> var;

    friend Compat::qhuint qHash(const RPCMsgId &, Compat::qhuint);
    friend struct std::hash<RPCMsgId>;

public:
    RPCMsgId() = default;
    RPCMsgId(int64_t intVal) : var{intVal} {}
    RPCMsgId(const QString &str) : var{str} {}
    RPCMsgId(QString &&str) : var{std::move(str)} {}

    // copy/move
    RPCMsgId(const RPCMsgId &) = default;
    RPCMsgId(RPCMsgId &&) = default;

    bool isNull() const { return std::holds_alternative<Null>(var); }
    void setNull() { var.emplace<Null>(); }

    bool isInt() const { return std::holds_alternative<int64_t>(var); }
    bool isString() const { return std::holds_alternative<QString>(var); }

    auto operator<=>(const RPCMsgId & o) const = default;

    // assign from compatible type
    RPCMsgId &operator=(const QString &s) { var = s; return *this; }
    RPCMsgId &operator=(QString &&s) { var = std::move(s); return *this; }
    RPCMsgId &operator=(int64_t i) { var = i; return *this; }

    // copy assign/move assign
    RPCMsgId &operator=(const RPCMsgId &) = default;
    RPCMsgId &operator=(RPCMsgId &&) = default;

    /// return a QVariant for JSONification
    QVariant toVariant() const;
    /// Will throw BadArgs if the QVariant is not either QString or a numeric that is an integer, or null
    static RPCMsgId fromVariant(const QVariant &) noexcept(false);

    // getters
    int64_t toInt() const; // returns the value if it was an integer, or tries to parse the value if QString, or returns 0 if cannot parse or Null
    QString toString() const; // returns the string value (may return a number string if we have an integer, or 'null' if .isNull())
};

/// template specialization for std::hash of RPCMsgId (for std::unordered_map, std::unordered_set, etc)
template<> struct std::hash<RPCMsgId> {
    std::size_t operator()(const RPCMsgId &r) const {
        return std::visit(Overloaded{
                              [](const QString &s) { return Util::hashForStd(s); },
                              [](const int64_t i) { return Util::hashForStd(i); },
                              [](RPCMsgId::Null) { return std::size_t{0u}; }
                          }, r.var);
    }
};

/// overload for Qt's hashtable containers (QHash, QMultiHash, etc)
inline Compat::qhuint qHash(const RPCMsgId &r, Compat::qhuint seed = 0)
{
    return std::visit(Overloaded{
                          [seed](const QString &s) { return qHash(s, seed); },
                          [seed](const int64_t i) { return qHash(i, seed); },
                          [seed](RPCMsgId::Null) { return seed; }
                      }, r.var);
}

/// overload to support writing RpcMsgId to a text stream
inline QTextStream &operator<<(QTextStream &ts, const RPCMsgId &rid) { return ts << rid.toString(); }
