#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <QString>

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

#define APPNAME "ShuffleUpServer"
#define VERSION "1.0"
#ifdef QT_DEBUG
#  define VERSION_EXTRA "(Debug)"
#else
#  define VERSION_EXTRA "(Release)"
#endif
#endif // EXCEPTIONS_H
