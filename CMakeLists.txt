cmake_minimum_required(VERSION 3.19)

project(Fulcrum 
        VERSION 1.10.0
        DESCRIPTION "A fast & nimble SPV Server for BCH, BTC, and LTC"
        HOMEPAGE_URL "https://fulcrumserver.org"
	LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
  message(STATUS "Using ccache: ${CCACHE}")
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

option(ENABLE_REDUCE_EXPORTS "Reduce the amount of exported symbols" OFF)
option(ENABLE_TESTS "Enabled compiled-in tests and benchmarks" $<IF:$<CONFIG:Debug>,ON,OFF>)

# Qt lib
find_package(Qt6 6.6.0 COMPONENTS Core Networking REQUIRED)

# Rocksdb lib
find_package(RocksDB 9.0.0 REQUIRED)

# Jemalloc
find_package(jemalloc)

# ZeroMQ
find_package(ZeroMQ)


add_executable(Fulcrum resources.qrc)
add_subdirectory(src)

# Compile options
include(CheckCompilerFlag)
include(CheckLinkerFlag)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
target_compile_options(Fulcrum PRIVATE -Wall -Wno-unused-parameter)
if(ENABLE_TESTS)
    target_compile_definitions(Fulcrum PRIVATE ENABLE_TESTS)
    target_sources(Fulcrum PRIVATE
        src/tests/ByteView_tests.cpp
        resources/testdata/testdata.qrc
    )
endif()
if(ENABLE_REDUCE_EXPORTS)
  # Default visibility is set by CMAKE_<LANG>_VISIBILITY_PRESET, but this
  # doesn't tell if the visibility set is effective.
  # Check if the flag -fvisibility=hidden is supported, as using the hidden
  # visibility is a requirement to reduce exports.
  check_compiler_flag(CXX -fvisibility=hidden HAS_CXX_FVISIBILITY)
  if(NOT HAS_CXX_FVISIBILITY)
    message(FATAL_ERROR "Cannot set default symbol visibility. Use -DENABLE_REDUCE_EXPORTS=OFF.")
  endif()
  target_compile_options(Fulcrum PRIVATE -fvisibility=hidden)

  check_linker_flag(CXX -Wl,--exclude-libs,ALL HAS_EXCLUDE_LIBS_LINKER_FLAG)
  if (HAS_EXCLUDE_LIBS_LINKER_FLAG)
      # Also hide symbols from static libraries
      target_link_options(Fulcrum PRIVATE -Wl,--exclude-libs,ALL)
  endif()
endif()
# /Compile options

if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
    message("Detected big endian platform")
    target_compile_definitions(Fulcrum PRIVATE WORDS_BIGENDIAN)
endif()

target_link_libraries(Fulcrum Qt6::Core Qt6::Network jemalloc::jemalloc RocksDB::rocksdb libzmq-static)

# TODO: Set some of the CLZL and other stuff Fulcrum.pro sets for us
