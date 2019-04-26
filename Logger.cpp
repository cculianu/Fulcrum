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
#ifdef Q_OS_WIN
#  include <io.h>
#  define ISATTY _isatty
#  define FILENO _fileno
#else
#  include <unistd.h>
#  define ISATTY isatty
#  define FILENO fileno
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
    return false;
#else
    int fd = FILENO(stdOut ? stdout : stderr);
    return ISATTY(fd);
#endif
}
