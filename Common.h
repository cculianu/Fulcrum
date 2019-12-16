#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <exception>
#include <QString>

#ifdef __clang__
// turn off the dreaded "warning: class padded with xx bytes, etc" since we aren't writing wire protocols using structs..
#pragma clang diagnostic ignored "-Wpadded"
#endif

/// All of the custom exceptions we define in this app inherit from this base.
struct Exception : public std::runtime_error
{
    Exception(const QString & what = "Error") : std::runtime_error(what.toUtf8()) {}
    ~Exception() override; ///< for vtable
};

struct InternalError : public Exception { using Exception::Exception; };
struct BadArgs : public Exception { using Exception::Exception; };

#define APPNAME "Fulcrum"
#define VERSION "1.0"
#ifdef QT_DEBUG
#  define VERSION_EXTRA "(Debug)"
inline constexpr bool isReleaseBuild() { return false; }
#else
#  define VERSION_EXTRA "(Release)"
inline constexpr bool isReleaseBuild() { return true; }
#endif
#endif // COMMON_H
