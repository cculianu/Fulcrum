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

#include "Common.h"

#include <QByteArray>
#include <QString>
#include <QVariant>

/// Note that Qt's JSON parser/serializer has a hard limit of ~128MB on json documents.
/// See: https://bugreports.qt.io/browse/QTBUG-47629
/// TODO: use an alternate code path (with an alternate parser) in the case where the Json document hits this limit.
/// For now, all calling code that calls into the below functions must also be prepared to catch bad_alloc (std::exception)
namespace Json {
    /// Generic Json error (usually if expectMap is violated)
    struct Error : public Exception { using Exception::Exception; };
    /// More specific Json error -- usually if trying to parse malformed JSON text.
    struct ParseError : public Error { using Error::Error; };

    enum class ParseOption {
        RequireObject,     ///< Reject any JSON that is not embeded in a JSON object { ... }
        RequireArray,      ///< Reject any JSON that is not embeded in a JSON array [ ... ]
        AcceptAnyValue     ///< Do not require a root-level container: accept any JSON value that is valid e.g. "str", null, true, etc
    };

    /// If ParseOption is not satisfied, throws Error. May also throw Error on invalid JSON or throw
    /// std::exception too on low-level error (bad_alloc, etc).
    extern QVariant parseUtf8(const QByteArray &json, ParseOption);
    /// Convenience method -- loads all data from file and calls parseUtf8 on it.
    extern QVariant parseFile(const QString &file, ParseOption);

    enum class SerOption { NoBareNull, BareNullOk };
    /// Serialization, may throw Error, may throw std::exception on low-level error (bad_alloc, etc).
    /// Will throw also if given an empty QVariant{}, unless BareNullOk is specified.
    extern QByteArray toUtf8(const QVariant &, bool compact = false, SerOption = SerOption::NoBareNull);
}
