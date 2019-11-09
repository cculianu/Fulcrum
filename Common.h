#ifndef COMMON_H
#define COMMON_H

#include <exception>
#include <QString>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wpadded"
#endif

class Exception : public std::runtime_error
{
public:
    Exception(const QString & what = "Error") : std::runtime_error(what.toUtf8()) {}
    ~Exception(); ///< for vtable
};

class InternalError : public Exception
{
public:
    using Exception::Exception;
};

class BadArgs : public Exception
{
public:
    using Exception::Exception;
};

#define APPNAME "Fulcrum"
#define VERSION "1.0"
#ifdef QT_DEBUG
#  define VERSION_EXTRA "(Debug)"
#else
#  define VERSION_EXTRA "(Release)"
#endif
#endif // COMMON_H
