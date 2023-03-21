/*
Json - A lightweight JSON parser and serializer for Qt.
Copyright (c) 2020-2023 Calin A. Culianu <calin.culianu@gmail.com>

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#pragma once

#include "Common.h"

#include <QtGlobal> // for qsizetype (and other typedefs)
#include <QByteArray>
#include <QString>
#include <QVariant>

#include <optional>
#include <stdexcept>
#include <vector>

/// A namespace for a custom JSON parser and serializer that doesn't
/// suffer from the 128MB limit and heap fragmentation that Qt 5.14.x
/// and below suffer from, and has none of the bugs that Qt 5.15.0 has.
/// See:
///     https://bugreports.qt.io/browse/QTBUG-47629
///     https://bugreports.qt.io/browse/QTBUG-84610
///
/// If using the ParserBackend::SimdJson backend, this is also *much*
/// faster than any of the Qt parsers for parsing. For serialization it
/// is also faster than Qt in all cases.
namespace Json {
    /// Generic error (this exact type usually is thrown if ParseOption is violated)
    /*struct Error : public std::runtime_error {
        using std::runtime_error::runtime_error;
        Error(const QString &msg) : std::runtime_error(msg.toUtf8().constData()) {}
        ~Error() override;
    };*/
    /// This is the only thing modified from the library implementation -- in order to
    /// fit the exception hierarchy for this lib into our codebase's "Exception" tree.
    /// There is a static_assert in RPC.cpp to check for this.
    struct Error : Exception {
        using Exception::Exception;
        Error(const QString &msg) : Exception(msg) {}
        ~Error() override;
    };

    /// More specific Json error -- usually if trying to parse malformed JSON text.
    struct ParseError : Error { using Error::Error; ~ParseError() override; };

    /// Thrown by the parseUtf8 and parseFile functions if the parser SimdJson was selected but it is unavailable.
    struct ParserUnavailable : Error { using Error::Error; ~ParserUnavailable() override; };

    /// Thrown by serialize and toUff8 if the JSON object is nested too deeply (>1024 deep)
    struct NestingLimitExceeded : Error { using Error::Error; ~NestingLimitExceeded() override; };

    enum class ParseOption {
        RequireObject,     ///< Reject any JSON that is not embeded in a JSON object { ... }
        RequireArray,      ///< Reject any JSON that is not embeded in a JSON array [ ... ]
        AcceptAnyValue     ///< Do not require a root-level container: accept any JSON value that is valid e.g. "str", null, true, etc
    };

    enum class ParserBackend {
        Default,          ///< The default parser (implemented in Json_Parser.cpp), always available
        SimdJson,         ///< Much faster experimental parser, only available on aarch64 and x86-64
        FastestAvailable  ///< If SimdJson is available, use that, if not, use Default.
    };

    /// If ParseOption is not satisfied, throws Error. May also throw Error on invalid JSON. May throw
    /// ParserUnavailable. Additionally, may throw a std::exception too on low-level error (bad_alloc, etc).
    extern QVariant parseUtf8(const QByteArray &json, ParseOption = ParseOption::AcceptAnyValue,
                              ParserBackend = ParserBackend::Default);
    /// Convenience method -- loads all data from file and calls parseUtf8 on it.
    extern QVariant parseFile(const QString &file, ParseOption = ParseOption::AcceptAnyValue,
                              ParserBackend = ParserBackend::Default);

    enum class SerOption { NoBareNull, BareNullOk };
    /// Serialization, may throw Error, may throw std::exception on low-level error (bad_alloc, etc).
    /// Will throw also if given an empty QVariant{}, unless BareNullOk is specified.
    /// May throw NestingLimitExceeded if the supplied QVariant has a recursive nesting depth larger than 1024.
    /// If compact = true, the generated JSON will have no whitespace between tokens.
    /// If compact = false, the generated JSON will have newlines and 4-spaces as indentation per indentation level.
    extern QByteArray toUtf8(const QVariant &, bool compact = false, SerOption = SerOption::BareNullOk);

    /// Low-level function -- like toUtf8() but lets you control the indentation level, etc.
    /// prettyIndent = 0 - compact (no whitespace), otherwise it will be the amount to indent at each level
    /// May throw Error or std::exception, or return an empty QByteArray on error.
    /// May throw NestingLimitExceeded if the supplied QVariant has a recursive nesting depth larger than 1024.
    extern QByteArray serialize(const QVariant &v, unsigned prettyIndent = 0, unsigned indentLevel = 0);

    /// Returns a rough estimate of the amount of memory a particular JSON-compatible QVariant
    /// consumes.  This is a Fulcrum extension (which may end up ported to the main lib -Calin).
    /// Note that if the QVariant contains types we don't support for serialization, they will
    /// be costed as simply sizeof(QVariant).
    /// May throw NestingLimitExceeded if the supplied QVariant has a recursive nesting depth larger than 1024.
    extern qsizetype estimateMemoryFootprint(const QVariant &);

    // --
    // -- Below are extra utility and other functions for querying the simdjson impl, checking the locale, etc.
    // --

    /// Query if a certain parser backend is available
    extern bool isParserAvailable(ParserBackend); // implemented in Json_Parser.cpp

    /// Information about the SimdJson backend
    namespace SimdJson {
        /// Information on the simdjson backend
        struct Info {
            struct Implementation {
                QString name, description;
                bool supported{};                        ///< true if supported on this processor
            };
            std::vector<Implementation> implementations; ///< list of available implementations
            Implementation active;                       ///< the currently active implementation
        };
        /// If isParserAvailable(ParserBackend::SimdJson), will return a valid optional with information on the simdjson
        /// backend.  Otherwise will return an empty optional.
        extern std::optional<const Info> getInfo(); // implemented in Json_Parser.cpp
        /// If isParserAvailable(ParserBackend::SimdJson), will return a version string e.g. "0.6.0", or the empty
        /// string otherwise.
        extern QString versionString();
    }

    /// Call this to check and/or force LC_NUMERIC to use decimal points otherwise parsing/serializing may produce
    /// invalid numeric values (we require "." for the decimal point character).
    ///
    /// @param `autoFix` if true, we force the locale if it was incorrect. If false, we do not.
    /// @returns `true` if the locale was ok, `false` if it wasn't (will have been auto-fixed if `autoFix==true`)
    bool checkLocale(bool autoFix = true);

    /// Defaults to true. Set this to false to not check & auto-set the numeric locale on each call to serialize()
    /// and/or parse*(). Checking the locale on each call takes ~1-10 us at most, but if you want to not waste those
    /// cycles, this flag is offered for advanced users of this library.
    extern bool autoFixLocale;


    // ---
    // --- detail
    // ---

    /// Internal namespace -- not intended for public use, but if you must you can call into it.
    namespace detail {
        /// Parser.  Implemented in Json_Parser.cpp.
        ///
        /// @param vout - out param.  Results are placed here
        /// @param json - The json to parse.  It need not be wrapped in an object or an array. Even simple json items
        ///               may be parsed.
        /// @param backend - The backend to use.  May throw `ParserUnavailable` if backend is SimdJson and it is not
        ///                  available.
        /// @returns true on success, false on parse error.
        extern bool parse(QVariant &out, const QByteArray &json, ParserBackend backend);
    }
}
