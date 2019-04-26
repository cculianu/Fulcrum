#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <QString>

class Exception : public std::runtime_error
{
public:
    Exception(const QString & what = "Error") : std::runtime_error(what.toUtf8()) {}
    virtual ~Exception();
};

class BadArgs : public Exception
{
public:
    BadArgs(const QString & what = "Bad Arguments") : Exception(what) {}
    ~BadArgs();
};

#define APPNAME "ShuffleUpServer"
#define VERSION "1.0"
#ifdef QT_DEBUG
#  define VERSION_EXTRA "(Debug)"
#else
#  define VERSION_EXTRA "(Release)"
#endif
#endif // EXCEPTIONS_H
