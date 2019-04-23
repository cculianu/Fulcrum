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

#define APPNAME "ShuffleUpServer"
#define VERSION "1.0"

#endif // EXCEPTIONS_H
