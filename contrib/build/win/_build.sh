#!/bin/bash

# This runs inside the Docker image

set -e  # Exit on error

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Please pass Fulcrum and rocksdb dirnames as the two args"
    exit 1
fi

PACKAGE="$1"
ROCKSDB_PACKAGE="$2"
TARGET_BINARY=Fulcrum.exe

top=/work
cd "$top" || fail "Could not cd $top"
. "$top/$PACKAGE/contrib/build/common/common.sh" || (echo "Cannot source common.h" && exit 1)

info "Running CMake for RocksDB ..."
cd "$ROCKSDB_PACKAGE" && mkdir build/ && cd build || fail "Could not change to build dir"
/opt/mxe/usr/x86_64-pc-linux-gnu/bin/cmake  .. -DCMAKE_C_COMPILER=x86_64-w64-mingw32.static-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32.static-g++ -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_HOST_SYSTEM_NAME=Linux -G"Unix Makefiles" -DWITH_GFLAGS=0 -DWITH_JNI=0  \
    -DCMAKE_BUILD_TYPE=Release -DUSE_RTTI=1 -DPORTABLE=1 \
|| fail "Could not run CMake"

info "Building RocksDB ..."
#make -j`nproc` VERBOSE=1 rocksdb || fail "Could not build RocksDB"  # Uncomment this for verbose compile
make -j`nproc` rocksdb || fail "Could not build RocksDB"

info "Stripping librocksdb.a ..."
x86_64-w64-mingw32.static-strip -g librocksdb.a || fail "Could not strip librocksdb.a"

info "Copying librocksdb.a to Fulcrum directory ..."
cp -fpva librocksdb.a "$top"/"$PACKAGE"/staticlibs/rocksdb/bin/win64 || fail "Could not copy librocksdb.a"
printok "RocksDB built and moved to Fulcrum staticlibs directory"

cd "$top"/"$PACKAGE" || fail "Could not chdir to Fulcrum dir"

info "Building Fulcrum ..."
qmake || fail "Could not run qmake"
make -j`nproc`  || fail "Could not run make"

ls -al "$TARGET_BINARY" || fail "$TARGET_BINARY not found"
printok "$TARGET_BINARY built"

info "Copying to top level ..."
cp -fpva "$TARGET_BINARY" "$top/." || fail "Could not copy $TARGET_BINARY"
cd "$top" || fail "Could not cd to $top"

printok "Inner _build.sh finished"
