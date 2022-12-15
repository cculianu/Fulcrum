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

#include <QString>

#include <cstdint>
#include <exception>

#ifdef __clang__
// turn off the dreaded "warning: class padded with xx bytes, etc" since we aren't writing wire protocols using structs..
#pragma clang diagnostic ignored "-Wpadded"
#endif

/// All of the custom exceptions we define in this app inherit from this base.
struct Exception : std::runtime_error
{
    Exception(const QString & what = "Error") : std::runtime_error(what.toUtf8()) {}
    ~Exception() override; ///< for vtable
};

struct InternalError : Exception { using Exception::Exception; ~InternalError() override; };
struct BadArgs : Exception { using Exception::Exception; ~BadArgs() override; };

#define APPNAME "Fulcrum"
#define VERSION "1.9.0"
#ifdef QT_DEBUG
inline constexpr bool isReleaseBuild() { return false; }
#else
inline constexpr bool isReleaseBuild() { return true; }
#endif
#ifdef GIT_COMMIT
#  ifdef QT_DEBUG
#    define VERSION_EXTRA "(Debug " GIT_COMMIT ")"
#  else
#    define VERSION_EXTRA "(Release " GIT_COMMIT ")"
#  endif
#else
#  ifdef QT_DEBUG
#    define VERSION_EXTRA "(Debug)"
#  else
#    define VERSION_EXTRA "(Release)"
#  endif
#endif

#if (QT_VERSION < QT_VERSION_CHECK(5, 12, 5)) || (QT_VERSION == QT_VERSION_CHECK(5, 13, 0))
#error Fulcrum requires Qt 5.12.5 (or later) or Qt 5.13.1 (or later) to be successfully built without errors.  Please use Qt 5.12.5+ or Qt 5.13.1+ to build this codebase.
#endif
