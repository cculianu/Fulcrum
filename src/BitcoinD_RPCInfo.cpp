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

#include "BitcoinD_RPCInfo.h"
#include "Common.h"
#include "Util.h"

#include <QByteArray>
#include <QFile>

#include <cctype> // for std::isspace
#include <tuple>  // for std::tie

void BitcoinD_RPCInfo::setCookieFile(const QString &file)
{
    if (file.isEmpty()) throw BadArgs("BitcoinD cookie file cannot be the empty string");
    user.clear(), pass.clear();
    cookieFile = file;
}

void BitcoinD_RPCInfo::setStaticUserPass(const QString &u, const QString &p)
{
    cookieFile.clear();
    std::tie(user, pass) = std::tie(u, p);
}

QPair<QString, QString> BitcoinD_RPCInfo::getUserPass() const
{
    QPair<QString, QString> ret;

    if (!hasCookieFile()) {
        // static user/pass (e.g. rpcuser= rpcpassword= was specified in conf file)
        std::tie(ret.first, ret.second) = std::tie(user, pass);
        return ret;
    }

    // otherwise, user specified a cookie file -- read the cookie file..

    QFile f(cookieFile);
    if (!f.open(QIODevice::ReadOnly)) {
        Warning() << "Unable to open cookie file '" << cookieFile << "': " << f.errorString();
        return ret;
    }

    QByteArray line = f.readLine();
    f.close();
    // trim trailing whitespace, newlines, etc
    while (!line.isEmpty() && (std::isspace(char(line.back())) || char(line.back()) == '\0')) {
        line.resize(line.size() - 1);
    }

    const int colon = line.indexOf(':');
    if (colon < 0) {
        Warning() << "Cookie file '" << cookieFile << "' "
                  << "does not appear to be a valid bitcoind cookie file (missing ':' character)";
        return ret;
    }

    // extract user:pass
    ret.first = QString::fromUtf8(line.left(colon));
    ret.second = QString::fromUtf8(line.mid(colon+1));

    return ret;
}
