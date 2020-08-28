#!/bin/bash

# This runs inside the Docker image

set -e  # Exit on error

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Please pass Fulcrum, rocksdb, and jemalloc dirnames as the three args"
    exit 1
fi

PACKAGE="$1"
ROCKSDB_PACKAGE="$2"
JEMALLOC_PACKAGE="$3"
TARGET_BINARY=Fulcrum

top=/work
cd "$top" || fail "Could not cd $top"
. "$top/$PACKAGE/contrib/build/common/common.sh" || (echo "Cannot source common.h" && exit 1)

info "Running configure for jemalloc ..."
cd "$JEMALLOC_PACKAGE" || fail "Could not change dir to $JEMALLOC_PACKAGE"
./autogen.sh -with-jemalloc-prefix= --disable-shared --enable-static \
    || fail "Configure of jemalloc failed"

info "Building jemalloc ..."
make -j`nproc` || fail "Could not build jemalloc"
make install || fail "Could not install jemalloc"
JEMALLOC_LIBDIR=$(jemalloc-config --libdir)
[ -n "$JEMALLOC_LIBDIR" ] || fail "Could not determine JEMALLOC_LIBDIR"
for a in "$JEMALLOC_LIBDIR"/libjemalloc*; do
    bn=`basename $a`
    info "Stripping $bn ..."
    strip -g "$a" || fail "Failed to strip $a"
done
printok "jemalloc static library built and installed in $JEMALLOC_LIBDIR"

info "Building RocksDB ..."
cd "$top/$ROCKSDB_PACKAGE" || fail "Could not cd tp $ROCKSDB_PACKAGE"
USE_RTTI=1 PORTABLE=1 DISABLE_JEMALLOC=1 make static_lib -j`nproc` V=1 \
    || fail "Could not build RocksDB"

info "Stripping librocksdb.a ..."
strip -g librocksdb.a || fail "Could not strip librocksdb.a"

info "Copying librocksdb.a to Fulcrum directory ..."
cp -fpva librocksdb.a "$top"/"$PACKAGE"/staticlibs/rocksdb/bin/linux || fail "Could not copy librocksdb.a"
printok "RocksDB built and moved to Fulcrum staticlibs directory"

cd "$top"/"$PACKAGE" || fail "Could not chdir to Fulcrum dir"

info "Building Fulcrum ..."
mkdir build && cd build || fail "Could not create/change-to build/"
qmake ../Fulcrum.pro "CONFIG-=debug" "CONFIG+=release" "LIBS+=-L${JEMALLOC_LIBDIR} -ljemalloc" \
    || fail "Could not run qmake"
make -j`nproc` || fail "Could not run make"

ls -al "$TARGET_BINARY" || fail "$TARGET_BINARY not found"
printok "$TARGET_BINARY built"

info "Copying to top level ..."
mkdir -p "$top/built" || fail "Could not create build products directory"
cp -fpva "$TARGET_BINARY" "$top/built/." || fail "Could not copy $TARGET_BINARY"
cd "$top" || fail "Could not cd to $top"

printok "Inner _build.sh finished"
