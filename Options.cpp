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
#include "Options.h"

#include <QFile>
#include <QIODevice>
#include <QTextStream>


std::optional<QString> ConfigFile::optValue(const QString &name, Qt::CaseSensitivity cs) const
{
    std::optional<QString> ret;

    if (cs == Qt::CaseSensitive) {
        if (auto it = map.find(name); it != map.end())
            ret = it.value();
    } else {
        for (auto it = map.begin(); it != map.end(); ++it) {
            if (it.key().compare(name, cs) == 0) {
                ret = it.value();
                break;
            }
        }
    }
    return ret;
}

bool ConfigFile::hasValue(const QString &name, Qt::CaseSensitivity cs) const
{
    return optValue(name, cs).has_value();
}

QString ConfigFile::value(const QString &name, const QString & def, Qt::CaseSensitivity cs) const
{
    return optValue(name, cs).value_or(def);
}

bool ConfigFile::open(const QString &filePath)
{
    static const QChar comment('#'), eq('='), bracket('[');
    clear();
    QList<QByteArray> lines;
    {
        QFile f(filePath);
        if (!f.exists() || !f.open(QIODevice::ReadOnly|QIODevice::Text))
            return false;
        auto fileData = f.read(1024*1024*1); // read up to 1 MB
        if (fileData.isEmpty())
            return f.error() == QFile::FileError::NoError;
        lines = fileData.split('\n');
    }
    for (const auto & lineData : lines) {
        QString line = QString::fromUtf8(lineData).trimmed();
        if (!line.isEmpty() && line.at(0) == bracket)
            continue; // ignore "[section]" headers in case the user thinks we support these
        if (const int cpos = line.indexOf(comment); cpos > -1) // find and throw away comments (everything after '#' char)
            line = line.left(cpos).trimmed();
        if (line.isEmpty())
            continue;
        QString name, value;
        if (const int eqpos = line.indexOf(eq); eqpos > -1) {
            name = line.left(eqpos).trimmed();
            if (name.isEmpty())
                continue;
            value = line.mid(eqpos+1).trimmed();
        } else
            // a name by itself on a line with no equal sign, becomes name=(emptystring), which might be useful to
            // indicate the name was present (can act like a bool flag if present)
            name = line;
        // save item
        map[name] = value;
    }

    map.squeeze();

    return true;
}

bool ConfigFile::boolValue(const QString & name, bool def, bool *parsedOk, Qt::CaseSensitivity cs) const
{
    bool dummy;
    bool & ok ( parsedOk ? *parsedOk : dummy );
    ok = false;
    const auto opt = optValue(name, cs);
    if (!opt.has_value())
        return def;
    const auto val = opt.value().toLower();
    if (val == "true" || val == "yes" || val.isEmpty() /* "" means true! */) { ok = true; return true; }
    else if (val == "false" || val == "no") { ok = true; return false; }
    bool ret = val.toInt(&ok);
    if (!ok) ret = def;
    return ret;
}

int ConfigFile::intValue(const QString & name, int def, bool *parsedOk, Qt::CaseSensitivity cs) const
{
    bool dummy;
    bool & ok ( parsedOk ? *parsedOk : dummy );
    ok = false;
    const auto opt = optValue(name, cs);
    if (!opt.has_value())
        return def;
    const auto val = opt.value().toLower();
    int ret = val.toInt(&ok);
    if (!ok) ret = def;
    return ret;
}

double ConfigFile::doubleValue(const QString & name, double def, bool *parsedOk, Qt::CaseSensitivity cs) const
{
    bool dummy;
    bool & ok ( parsedOk ? *parsedOk : dummy );
    ok = false;
    const auto opt = optValue(name, cs);
    if (!opt.has_value())
        return def;
    const auto val = opt.value().toLower();
    double ret = val.toDouble(&ok);
    if (!ok) ret = def;
    return ret;
}
