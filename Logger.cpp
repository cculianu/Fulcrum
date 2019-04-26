#include "Logger.h"

Logger::Logger(QObject *parent) : QObject(parent)
{
    connect(this, &Logger::log, this, [this](const QString &line){
        // we do it in a closure because in this c'tor gotLine isn't defined yet (pure virtual)
        gotLine(line);
    });
}

Logger::~Logger() {}

#include <iostream>
#include <stdio.h>
#ifndef Q_OS_WIN
#  include <unistd.h>
#endif
ConsoleLogger::ConsoleLogger(QObject *p, bool stdOut)
    : Logger(p), stdOut(stdOut)
{}

void ConsoleLogger::gotLine(const QString &l) {
    (stdOut ? std::cout : std::cerr)
            << l.toUtf8().constData()
            << std::endl << std::flush;
}

bool ConsoleLogger::isaTTY() const {
#ifdef Q_OS_WIN
    return false; // console control chars don't reliably work on windows. disable color always
#else
    int fd = fileno(stdOut ? stdout : stderr);
    return isatty(fd);
#endif
}
