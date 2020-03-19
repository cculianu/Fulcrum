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

#include <QMultiHash>
#include <QHostAddress>
#include <QList>
#include <QPair>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <algorithm>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <tuple>


struct Options {
private:
    static void test();
public:
    /// Return this object as a QVariantMap suitable for serializing as JSON. Controller::stats() uses this to
    /// output the configured options to the /stats output JSON, for example.
    QVariantMap toMap() const;

    static constexpr quint16 DEFAULT_PORT_TCP = 50001, DEFAULT_PORT_SSL = 50002;

    std::atomic_bool verboseDebug =
#ifdef QT_DEBUG
        true; ///< gets set to true on debug builds
#else
        false; ///< gets set to false on release builds
#endif
    std::atomic_bool verboseTrace = false; ///< this gets set if -d -d specified
    std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

    bool hasIPv6Listener = false; ///< used internally -- set to true by argParser if at least one of the specified listening interfaces is IPv6, false otherwise

    using Interface = QPair<QHostAddress, quint16>;
    QList<Interface> interfaces, ///< TCP interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT_TCP
                     sslInterfaces;  ///< SSL interfaces to use for binding SSL ports. Defaults to nothing.
    QList<Interface> statsInterfaces; ///< 'stats' server, defaults to empty (no stats server)
    QList<Interface> adminInterfaces; ///< the admin server, defaults to empty (no admin RPC)
    QSslCertificate sslCert; ///< this must be valid if we have any SSL interfaces.
    QString certFile; ///< saved here for toMap() to remember what was specified in config file
    QSslKey sslKey; ///< this must be valid if we have any SSL interfaces.
    QString keyFile; ///< saved here for toMap() to remember what was specified in config file
    QPair<QString, quint16> bitcoind; ///< hostname, port pair. We resolve bitcoind's actual IP address each time if it's a hostname and not an IP address string.
    QString rpcuser, rpcpassword;
    QString datadir; ///< The directory to store the database. It exists and has appropriate permissions (otherwise the app would have quit on startup).
    /// If true, on db open/startup, we will perform some slow/paranoid db consistency checks
    bool doSlowDbChecks = false;

    static constexpr double minPollTimeSecs = 0.5, maxPollTimeSecs = 30., defaultPollTimeSecs = 2.;
    /// bitcoin poll time interval. This value will always be in the range [minPollTimeSecs, maxPollTimeSecs] aka [0.5, 30]
    double pollTimeSecs = defaultPollTimeSecs;

    /// Used for the server.donation_address RPC response. Specified via conf file only via the "donation=" variable.
    QString donationAddress = "bitcoincash:qplw0d304x9fshz420lkvys2jxup38m9symky6k028";
    /// Used for the server.banner RPC response. Specified via conf file only via the "banner=" variable. If empty,
    /// or if the file cannot be opened, the default banner text will be emitted to the client as a fallback.
    QString bannerFile = "",
            torBannerFile = ""; ///< same as above, but configured from tor_banner=

    bool peerDiscovery = true, peerAnnounceSelf = true; ///< comes from config setting: 'peering' and 'announce'
    bool peeringEnforceUniqueIPs = true; ///< comes from config 'peering_enforce_unique_ip'

    std::optional<QString> hostName; ///< corresponds to hostname in server config
    std::optional<QString> torHostName; ///< corresponds to tor_hostname in server config. Must end in .onion. If unset, will not announce ourselves as .onion.
    std::optional<quint16> publicTcp;   ///< corresponds to public_tcp_port in server config -- if unspecified will default to the first TCP interface, if !has_value, it will not be announced
    std::optional<quint16> publicSsl;   ///< corresponds to public_ssl_port in server config -- if unspecified will default to the first SSL interface, if !has_value, it will not be announced
    std::optional<quint16> torTcp;   ///< corresponds to tor_tcp_port in server config -- if unspecified will not announce tcp on tor route.
    std::optional<quint16> torSsl;   ///< corresponds to tor_ssl_port in server config -- if unspecified will not announce ssl on tor route.

    // Max clients per IP related
    static constexpr int defaultMaxClientsPerIP = 12;
    int maxClientsPerIP = defaultMaxClientsPerIP; ///< corresponds to max_clients_per_ip in config file

    struct Subnet {
        QHostAddress subnet;
        int mask = -1; ///< default invalid mask. IPv4 is [0,32] and IPv6 is [0, 128]
        inline bool isValid() const { return !subnet.isNull() && mask >= 0 && mask <= 128; }
        /// Parses the supplied netmask string "11.56.24." or "11.45.24.0/24", etc and returns a valid Subnet iff parsed ok.
        static Subnet fromString(const QString &netmaskString);
        QString toString() const;
    };
    /// Default: do not apply IP address connection limits (and other limits) to clients originating from localhost (for Tor)
    /// Note that multiple threads may read this data structure -- so if we ever decide to mutate it at runtime
    /// after initial setup -- we must remember to guard it with a mutex!
    QList<Subnet> subnetsExcludedFromPerIPLimits = {{QHostAddress::LocalHost,32}, {QHostAddress::LocalHostIPv6,128}};
    /// Returns true if addr matches one of the subnets in subnetsExcludedFromPerIPLimits, false otherwise
    /// Optionally sets the pointer *matched = theMatchedSubnet (if !nullptr). This is potentially called from
    /// multiple threads and is thread-safe, since subnetsExcludedFromPerIPLimits is never changes after app init.
    bool isAddrInPerIPLimitExcludeSet(const QHostAddress & addr, Subnet * matched = nullptr) const;

    // Max history & max buffer
    static constexpr int defaultMaxBuffer = 4000000, maxBufferMin = 64000, maxBufferMax = 100000000;
    static constexpr int defaultMaxHistory = 125000, maxHistoryMin = 1000, maxHistoryMax = 100000000;

    static constexpr bool isMaxBufferSettingInBounds(int m) { return m >= maxBufferMin && m <= maxBufferMax; }
    static constexpr int clampMaxBufferSetting(int m) { return std::max(std::min(m, maxBufferMax), maxBufferMin); }

    std::atomic_int maxBuffer = defaultMaxBuffer; ///< this can be set at runtime by FulcrumAdmin as of Fulcrum 1.0.4, hence why it's an atomic.
    int maxHistory = defaultMaxHistory;

    // Work queue options as configured by user; these are the saved values from config (if any) and are not
    // necessarily the options used in practice (those can be determined by querying the Util::ThreadPool).
    int workQueue = -1;
    int workerThreads = -1;

    static constexpr int defaultMaxPendingConnections = 60, minMaxPendingConnections = 10, maxMaxPendingConnections = 9999;
    int maxPendingConnections = defaultMaxPendingConnections; ///< comes from config 'max_pending_connections'.

    Interface torProxy = {QHostAddress::SpecialAddress::LocalHost, 9050};  // tor_proxy e.g. 127.0.0.1:9050
    QString torUser, torPass;  // tor_user, tor_pass in config -- most tor installs have this blank

    static constexpr int defaultBDReqHi = 50, defaultBDReqLo = 20, defaultBDReqDecayPerSec = 5;
    static constexpr int maxBDReqHi = 10000, maxBDReqLo = 9999, maxBDReqDecayPerSec = 9999;
    static constexpr int minBDReqHi = 5, minBDReqLo = 1, minBDReqDecayPerSec = 1;
    /// BitcoinD Request throttling params, per client
    /// See Server.cpp, generic_async_to_bitcoind for how these are used.
    struct BdReqThrottleParams {
        int hi = defaultBDReqHi,             ///< hi - hi water mark (threshold), PAUSE client processing
            lo = defaultBDReqLo,             ///< lo - lo water mark (threashold), RESUME client  processing
            decay = defaultBDReqDecayPerSec; ///< decay - how much to decay from the bitcoind request counter, per second
        bool isValid() const noexcept;
    };
    // Atomic version of above. We could't use C++ atomic here because GCC 7.3.x lacks support for std::atomic<struct>.
    class AtomicBdReqThrottleParams : protected BdReqThrottleParams
    {
        mutable std::shared_mutex rwlock;
    public:
        inline BdReqThrottleParams load() const {
            std::shared_lock guard(rwlock);
            return *this;
        }
        inline void store(const BdReqThrottleParams &p) {
            std::unique_lock guard(rwlock);
            std::tie(hi, lo, decay) = std::tuple(p.hi, p.lo, p.decay);
        }
    };
    /// Comes from a triplet in config, if specified e.g.: "bitcoind_throttle = 50, 20, 10"
    AtomicBdReqThrottleParams bdReqThrottleParams;

    int64_t maxSubsPerIP = 50000; // testing.. 50k subs per IP ought to be plenty.
    int64_t maxSubsGlobally = 10000000; // testing.. 10 million subs max globally.
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
/// they are all saved (QMultiHash is used to store name/value pairs).  However, the simple .value() style functions
/// will return an arbitrary value of the same name.
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

    /// Returns all the values matching name or an empty list if no values matching name exist.
    QStringList values(const QString &name, Qt::CaseSensitivity = Qt::CaseInsensitive) const;

    /// Remove all entries for `name` (if any) from the internal hash table of name/value pairs and returns the number
    /// of items matched & removed.  Complexity: O(N) for CaseInsensitive, O(M) for CaseSensitive (where M is the
    /// number of items having exactly the same name).
    int remove(const QString &name, Qt::CaseSensitivity = Qt::CaseInsensitive);

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
    QMultiHash<QString, QString> all() const { return map; }

    bool isEmpty() const { return map.isEmpty(); }
    void clear() { map.clear(); }

private:
    QMultiHash<QString, QString> map; ///< name/value pairs read/parsed
};
