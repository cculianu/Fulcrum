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
#include <QAbstractSocket>
#include <QMetaType>
#include <QtCore>

#include <compare>
#include <type_traits>
#include <utility>

/// This is here to manage API differences between Qt 5.15 and earlier.
namespace Compat {

    inline constexpr auto SplitBehaviorSkipEmptyParts =
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        Qt::SplitBehaviorFlags::SkipEmptyParts
#else
        QString::SplitBehavior::SkipEmptyParts
#endif
    ; // <-- statement-ending semicolon
    inline constexpr auto SplitBehaviorKeepEmptyParts =
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        Qt::SplitBehaviorFlags::KeepEmptyParts
#else
        QString::SplitBehavior::KeepEmptyParts
#endif
    ; // <-- statement-ending semicolon

    /// Unites `other` into map `m`, returning a reference to map `m`.
    /// This does it the slow way in order to keep API differences between Qt 5.15 and earlier from warning about
    /// deprecated calls.
    template <typename K, typename V>
    QMap<K,V> & MapUnite(QMap<K, V> & m, const QMap<K, V> & other) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        QMultiMap<K, V> mm{std::move(m)};
        mm.unite(other); // this one warns on Qt 5.15 if not done to a QMultiMap
        m = std::move(mm);
#else
        for (auto it = other.begin(); it != other.end(); ++it)
            m.insert(it.key(), it.value());
#endif
        return m;
    }

    template <class SocketClass = QAbstractSocket>
    constexpr inline auto SocketErrorSignalFunctionPtr() noexcept {
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        return &SocketClass::errorOccurred;
#else
        return qOverload<QAbstractSocket::SocketError>(&SocketClass::error);  // Deprecated in Qt 5.15
#endif
    }

    // qHash return/seed type differs: Qt5 == uint, Qt6 == size_t
    using qhuint = decltype(qHash(std::declval<QString>(), 0));

    inline auto GetVarType(const QVariant &var) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        return QMetaType::Type(var.type());
#else
        return QMetaType::Type(var.typeId());
#endif
    }

    inline bool IsMetaType(const QVariant & var, QMetaType::Type type) {
        return GetVarType(var) == type;
    }

    template <typename T>
    concept QStrOrQBA = std::is_same_v<T, QString> || std::is_same_v<T, QByteArray>;

} // end namespace Compat

// Implement operator<=> for QString and QByteArray, so that we can get synthesized operator<=> for types containing
// these types. Note: We do this as a template so that we don't get compile errors in the future should Qt later
// implement operator<=> overloads for these types.
template <Compat::QStrOrQBA T>
std::strong_ordering operator<=>(const T & a, const T & b) noexcept {
    if (const int r = a.compare(b); r == 0) return std::strong_ordering::equal;
    else if (r < 0) return std::strong_ordering::less;
    return std::strong_ordering::greater;
}
