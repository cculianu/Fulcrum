//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include <QCoreApplication>
#include <QTimer>

#include <cstdlib>

#include "Common.h"
#include "Logger.h"

namespace {
    void loggerCommon(int level, const QString &)
    {
        if (level == Logger::Fatal) {
            if (qApp && !QCoreApplication::startingUp())
                QTimer::singleShot(0, qApp, []{qApp->exit(1);});
            else
                std::exit(1);
        }
    }
}

Logger::Logger(QObject *parent) : QObject(parent)
{
    connect(this, &Logger::log, this, [this](int level, const QString &line){
        // we do it in a closure because in this c'tor gotLine isn't defined yet (pure virtual)
        gotLine(level, line);
    });
}

Logger::~Logger() {}

#include <iostream>
#include <stdio.h>
#ifdef Q_OS_UNIX
#  include <unistd.h>
#  include <syslog.h>
#endif
ConsoleLogger::ConsoleLogger(QObject *p, bool stdOut)
    : Logger(p), stdOut(stdOut)
{}

void ConsoleLogger::gotLine(int level, const QString &l) {
    (stdOut ? std::cout : std::cerr)
            << l.toUtf8().constData()
            << std::endl << std::flush;
    loggerCommon(level, l);
}

bool ConsoleLogger::isaTTY() const {
#ifdef Q_OS_WIN
    return false; // console control chars don't reliably work on windows. disable color always
#else
    int fd = fileno(stdOut ? stdout : stderr);
    return isatty(fd);
#endif
}

#ifdef Q_OS_UNIX
/* static */ bool SysLogger::opened = false;
SysLogger::SysLogger(QObject *parent)
    : ConsoleLogger (parent)
{
    if (!opened) {
        openlog(APPNAME, LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
        setlogmask(LOG_UPTO(LOG_DEBUG));
        opened = true;
    }
}
void SysLogger::gotLine(int level, const QString &l)
{
    if (!opened) {
        ConsoleLogger::gotLine(level, l);
        return;
    }
    int ulevel = LOG_NOTICE;
    switch (level) {
    case Warning: ulevel = LOG_WARNING; break;
    case Fatal:
    case Critical: ulevel = LOG_CRIT; break;
    case Debug: ulevel = LOG_DEBUG; break;
    }
    syslog(ulevel, "%s", l.toUtf8().constData());
    loggerCommon(level, l);
}
#endif
