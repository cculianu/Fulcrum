//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Common.h"
#include "Logger.h"

#include <QCoreApplication>
#include <QTimer>

#include <cstdio>
#include <cstdlib>

#ifdef Q_OS_UNIX
#  include <stdio.h>   // fileno
#  include <syslog.h>
#  include <unistd.h>  // isatty, etc
#elif defined(Q_OS_WIN)
#  define WIN32_LEAN_AND_MEAN 1
#  include <stdio.h>   // _fileno
#  include <io.h>      // _isatty
#  include <windows.h> // win32api
#endif

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

ConsoleLogger::ConsoleLogger(QObject *p, bool stdOut_)
    : Logger(p), stdOut(stdOut_), isATty(calcIsATty(stdOut_))
{}

/* static */
bool ConsoleLogger::calcIsATty(bool stdOut)
{
#ifdef Q_OS_WIN
    const int fd = _fileno(stdOut ? stdout : stderr);
    if (fd >= 0 && _isatty(fd)) {
        HANDLE h = GetStdHandle(stdOut ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE); // handle h should not be CloseHandle'd
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode{};
            if (GetConsoleMode(h, &mode) && SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */)) {
                return true;
            }
        }
    }
#else
    const int fd = fileno(stdOut ? stdout : stderr);
    if (fd >= 0) return isatty(fd);
#endif
    return false;
}

void ConsoleLogger::gotLine(int level, const QString &l)
{
    auto * const strm = stdOut ? stdout : stderr;
    const auto bytes = l.toUtf8();
    std::fwrite(bytes.constData(), 1, bytes.size(), strm);
    std::fwrite("\n", 1, 1, strm);
    std::fflush(strm);
    loggerCommon(level, l);
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
