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
#include <QHostAddress>
#include <QList>
#include <QPair>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>
#include <QStringList>

#include <atomic>
#include <optional>
#include <tuple>


struct Options {
    static constexpr quint16 DEFAULT_PORT_TCP = 50001, DEFAULT_PORT_SSL = 50002;

    std::atomic_bool verboseDebug =
#ifdef QT_DEBUG
        true; ///< gets set to true on debug builds
#else
        false; ///< gets set to false on release builds
#endif
    std::atomic_bool verboseTrace = false; ///< this gets set if -d -d specified
    std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

    using Interface = QPair<QHostAddress, quint16>;
    QList<Interface> interfaces, ///< TCP interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT_TCP
                     sslInterfaces;  ///< SSL interfaces to use for binding SSL ports. Defaults to nothing.
    QList<Interface> statsInterfaces; ///< 'stats' server, defaults to empty (no stats server)
    QSslCertificate sslCert; ///< this must be valid if we have any SSL interfaces.
    QSslKey sslKey; ///< this must be valid if we have any SSL interfaces.
    Interface bitcoind;
    QString rpcuser, rpcpassword;
    QString datadir; ///< The directory to store the database. It exists and has appropriate permissions (otherwise the app would have quit on startup).
    /// If true, on db open/startup, we will perform some slow/paranoid db consistency checks
    bool doSlowDbChecks = false;

    static constexpr unsigned minPollTimeSecs = 1, maxPollTimeSecs = 30, defaultPollTimeSecs = 2;
    /// bitcoin poll time interval. This value will always be in the range [minPollTimeSecs, maxPollTimeSecs] aka [1, 30]
    unsigned pollTimeSecs = defaultPollTimeSecs;
};


/// A class encapsulating a simple read-only config file format.  The format is similar to the bitcoin.conf format
/// with "name = value" pairs, one per line. Section headers, e.g. [MySection] are not supported (they are simply
/// discarded).  The file's text encoding should be UTF-8.
///
/// Whitespace in the file is ignored/trimmed.  Comments lines start with a '#' character.  There is no support for
/// quoting or platform-independent file paths or any of the Qt data types.  All names and values are interpreted as
/// UTF-8 strings.  Names appearing on a line by themselves without an '=' sign are picked up as name=(empty string).
///
/// Internally, the names encountered are stored in a case-sensitive manner.  That is, "Name=1" is different from
/// "name=2", and if both are encountered, they are both accepted as two separate name=value pairs.  You can, however,
/// query the name/value pairs in a case insensitive manner.  If the file contains both "Name=1" and "name=2", and you
/// ask for "name" (case insensitive) -- an arbitrary value may be returned for "name" (either "1" or "2" in this case).
///
/// If multiple, same-case versions of the same name appear in the file, e.g.:  "MyFoo=1", "MyFoo=2", "MyFoo=3", etc,
/// only the last one encountered is used (the previous ones seen are overwritten as the file is parsed).
///
/// A note about boolean values (obtained from boolValue()) -- they are parsed as an int and if nonzero, they are true.
/// The keywords 'true', 'yes', 'false' and 'no' are all supported.  Additionally the mere presence of a name by
/// itself with no value in a file is treated as true as well.  For example:
///
///    debug  # by itself this is equal to debug = true or debug = 1 or debug = yes
///
/// This class is minimalistic. It only supports reading files of up to 1MB in size as a safety measure.
class ConfigFile
{
public:
    ConfigFile() = default;

    /// Opens the file at filePath as readonly.  If the opening or parsing of the file fails, false is returned,
    /// otherwise the file is read and parsed and the internal name/value pair map is updated.  In either case the
    /// existing internal name/value pair map is cleared (and populated with the new values on success).
    bool open(const QString & filePath);

    /// Checks if the name/value pair for `name` exists/was found in the parsed file.  Note that CaseInsensitive lookups
    /// involve a linear O(N) search, whereas CaseSensitive lookups are O(1).
    bool hasValue(const QString &name, Qt::CaseSensitivity = Qt::CaseInsensitive) const;
    /// Returns the value if found, or returns a default value if not found. CaseSensitive lookups are constant time
    /// whereas CaseInsensitive lookups are linear.
    QString value(const QString &name, const QString & defaultIfNotFound = QString(), Qt::CaseSensitivity = Qt::CaseInsensitive) const;
    /// Like the above but returns an empty optional if name is not found. CaseSensitive lookups are constant time
    /// whereas CaseInsensitive lookups are linear.
    std::optional<QString> optValue(const QString &name, Qt::CaseSensitivity = Qt::CaseInsensitive) const;

    /// Parses the string as a boolean and returns what was found, or the default if not found or if not parsed ok.
    /// Note that "true", "yes", "false", "no" and numeric strings are supported as possible boolean values.  If
    /// there was a parse error or if the value was not found for the specified name, *parseOk is set to false,
    /// otherwise it is set to true (if supplied).
    /// Note: If the value is "", it indicates the value exists in the file, and that a human went to the effort to
    /// type it in (even if they left out the "= true" part), so it is treated as TRUE for convenience.
    bool boolValue(const QString & name, bool def = false, bool *parsedOk = nullptr, Qt::CaseSensitivity = Qt::CaseInsensitive) const;
    /// Parses the value as an int and returns it, or returns the default if missing/not parsed.  Sets *parseOk = false if parse error or not found.
    int intValue(const QString & name, int def = 0, bool *parsedOk = nullptr, Qt::CaseSensitivity = Qt::CaseInsensitive) const;
    /// Parses the value as a double and returns it, or returns the default if missing/not parsed.  Sets *parseOk = false if parse error or not found.
    double doubleValue(const QString & name, double def = 0.0, bool *parsedOk = nullptr, Qt::CaseSensitivity = Qt::CaseInsensitive) const;

    /// Returns all the names in the file.  Dupe names of different cases (if any) are all included in the returned list.
    QStringList allNames() const { return map.keys(); }
    /// Returns the entire parsed name/value pair dictionary.  Dupe names of different cases (if any) are all in the returned hash map.
    QHash<QString, QString> all() const { return map; }

    bool isEmpty() const { return map.isEmpty(); }
    void clear() { map.clear(); }

private:
    QHash<QString, QString> map; ///< name/value pairs read/parsed
};
