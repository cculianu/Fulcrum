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
#include "Json.h"
#include <QFile>
#include <QJsonDocument>

namespace Json {
    QVariant parseUtf8(const QByteArray &ba, bool expectMap)
    {
        QJsonParseError e;
        QJsonDocument d = QJsonDocument::fromJson(ba, &e);
        if (d.isNull())
            throw ParseError(QString("Error parsing Json from string: %1").arg(e.errorString()));
        auto v = d.toVariant();
        if (expectMap && v.type() != QVariant::Map)
            throw Error("Json Error, expected map, got a list instead");
        if (!expectMap && v.type() != QVariant::List)
            throw Error("Json Error, expected list, got a map instead");
        return v;
    }
    QVariant parseFile(const QString &file, bool expectMap) {
        QFile f(file);
        if (!f.open(QFile::ReadOnly))
            throw Error(QString("Could not open file: %1").arg(file));
        const QByteArray ba{f.readAll()};
        return parseUtf8(ba, expectMap);
    }
    QByteArray toJsonUtf8(const QVariant &v, bool compact) {
        if (v.isNull() || !v.isValid()) throw Error("Empty or invalid QVariant passed to Json::toString");
        auto d = QJsonDocument::fromVariant(v);
        if (d.isNull())
            throw Error("Bad QVariant pased to Json::toString");
        return d.toJson(compact ? QJsonDocument::Compact : QJsonDocument::Indented);
    }

} // end namespace Json
