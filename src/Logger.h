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
#pragma once

#include <QObject>
#include <QString>

/** Abstract base class for a line-based logger */
class Logger : public QObject
{
    Q_OBJECT
public:
    explicit Logger(QObject *parent = nullptr);
    virtual ~Logger();

    enum Level {
        Info = 0, Warning, Critical, Fatal, Debug
    };

    /// returns true if the logger is logging to a tty (and thus supports ANSI color codes, etc)
    virtual bool isaTTY() const { return false; }

signals:
    void log(int level, const QString & line); ///< call this or emit it to log a line

public slots:
    virtual void gotLine(int level, const QString &) = 0;
};

class ConsoleLogger : public Logger
{
public:
    explicit ConsoleLogger(QObject *parent = nullptr, bool stdOut = true);

    bool isaTTY() const override;

public:
    void gotLine(int level, const QString &) override;
private:
    bool stdOut = true;
};

/// On Windows this just prints to stdout. On Unix, calls syslog()
class SysLogger : public ConsoleLogger
{
#ifdef Q_OS_UNIX
public:
    SysLogger(QObject *parent = nullptr);
    void gotLine(int level, const QString &) override;
    bool isaTTY() const override { return !opened && ConsoleLogger::isaTTY(); }
private:
    static bool opened;
#else
public:
    using ConsoleLogger::ConsoleLogger;
#endif
};
