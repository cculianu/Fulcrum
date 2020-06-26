//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
#include <QHash>
#include <QString>
#include <QVariant>

#include <cstdint>
#include <functional>
#include <utility>

/// This class is designed to be a constrained sort of variant: either an integer or string
/// suitable for using with a JSONRPC 2.0 "id".
class RPCMsgId
{
public:
    enum Type : uint8_t {
        Null = 0, Integer, String
    };
    RPCMsgId() = default;
    RPCMsgId(int64_t intVal) : typ(Integer), idata(intVal) {}
    RPCMsgId(const QString &str) : typ(Integer), sdata(str) {}
    RPCMsgId(QString &&str) : typ(String) , sdata(std::move(str)) {}

    // copy/move
    RPCMsgId(const RPCMsgId &) = default;
    RPCMsgId(RPCMsgId &&) = default;

    bool isNull() const { return typ == Null; }
    Type type() const { return typ; }

    void clear() { *this = RPCMsgId(); }

    bool operator<(const RPCMsgId & o) const;
    bool operator>(const RPCMsgId & o) const;
    bool operator<=(const RPCMsgId & o) const;
    bool operator>=(const RPCMsgId & o) const;
    bool operator==(const RPCMsgId & o) const;
    bool operator!=(const RPCMsgId & o) const;

    // assign from compatible type
    RPCMsgId &operator=(const QString &s) {
        typ = String;
        sdata = s;
        idata = {};
        return *this;
    }
    RPCMsgId &operator=(QString &&s) {
        typ = String;
        sdata = std::move(s);
        idata = {};
        return *this;
    }
    RPCMsgId &operator=(int64_t i) {
        typ = Integer;
        sdata.clear();
        idata = i;
        return *this;
    }

    // copy assign/move assign
    RPCMsgId &operator=(const RPCMsgId &) = default;
    RPCMsgId &operator=(RPCMsgId &&) = default;

    /// return a QVariant for JSONification
    QVariant toVariant() const;
    /// Will throw BadArgs if the QVariant is not either QString or a numeric that is an integer, or null
    static RPCMsgId fromVariant(const QVariant &) noexcept(false);

    std::size_t hashValue(uint seed = 0) const;

    // getters
    int64_t toInt() const; // returns the value if type() == Integer, or tries to parse the value if String, or returns 0 if cannot parse or Null
    QString toString() const; // returns the string value (may return a number string if type() == Integer or 'null' if type() == Null

private:
    Type typ = Null;
    int64_t idata{};
    QString sdata{};
};

/// template specialization for std::hash of RPCMsgId (for std::unordered_map, std::unordered_set, etc)
template<> struct std::hash<RPCMsgId> { std::size_t operator()(const RPCMsgId &r) const { return r.hashValue(); } };
/// overload for Qt's hashtable containers (QHash, QMultiHash, etc)
inline uint qHash(const RPCMsgId &r, uint seed = 0) {
    return uint(r.hashValue(seed));
}
