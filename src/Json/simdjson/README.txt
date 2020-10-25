The simdjson library is optionally compiled-in to Json_Parser.cpp on
x86-64 and aarch64 platforms.  All other platforms do not include
simdjson (and ParserBackend::SimdJson will not be available).
