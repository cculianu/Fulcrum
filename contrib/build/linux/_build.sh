#!/bin/bash

# This runs inside the Docker image

set -e  # Exit on error

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
    echo "Please pass Fulcrum, rocksdb, jemalloc, and miniupnpc dirnames as the four args"
    exit 1
fi

PACKAGE="$1"
ROCKSDB_PACKAGE="$2"
JEMALLOC_PACKAGE="$3"
MINIUPNPC_PACKAGE="$4"
TARGET_BINARY=Fulcrum

top=/work
cd "$top" || fail "Could not cd $top"
. "$top/$PACKAGE/contrib/build/common/common.sh" || (echo "Cannot source common.h" && exit 1)

# miniupnpc
info "Building miniupnpc ..."
git config --global --add safe.directory "$top"/"$MINIUPNPC_PACKAGE"  # Needed for some versions of git to not complain
pushd "$top/$MINIUPNPC_PACKAGE" || fail "Coult not change dir to $MINIUPNPC_PACKAGE"
INSTALLPREFIX=/tmp make -j`nproc` || fail "Could not build miniupnpc"
INSTALLPREFIX=/tmp make install || fail "Could not install miniupnpc"
rm -vf /tmp/lib/libminiupnpc*.so*
for a in /tmp/lib/libminiupnpc*.a; do
    bn=`basename $a`
    info "Stripping $bn ..."
    strip -g "$a" || fail "Failed to strip $a"
done
popd > /dev/null
printok "miniupnpc built and installed in /tmp"
# /miniupnpc

# libzmq
pushd /tmp
LIBZMQ_COMMIT=622fc6dde99ee172ebaa9c8628d85a7a1995a21d  # v4.3.5 release
info "Cloning libzmq ..."
git clone https://github.com/zeromq/libzmq.git || fail "Could not clone libzmq"
cd libzmq && git checkout ${LIBZMQ_COMMIT} && cd .. || fail "Coult not checkout commit hash: ${LIBZMQ_COMMIT}"
mkdir -p zmqbuild && cd zmqbuild || fail "Could not create directory zmqbuild"
info "Building libzmq @ ${LIBZMQ_COMMIT} ..."
cmake ../libzmq -DBUILD_TESTS=OFF -DWITH_DOC=OFF -DWITH_LIBSODIUM=OFF  -DWITH_PERF_TOOL=OFF || fail "cmake failed"
make -j`nproc` || fail "build libzmq failed"
mkdir -p /tmp/lib && cp -fpva lib/libzmq.a /tmp/lib || fail "failed to copy libzmq.a to /tmp/lib"
info "Stripping libzmq.a ..."
strip -g /tmp/lib/libzmq.a  || fail "failed to strip libzmq.a"
info "Copying headers to /tmp/include ..."
mkdir -p /tmp/include && cp -fpvra ../libzmq/include/* /tmp/include/. || fail "failed to copy headers"
popd > /dev/null
printok "libzmq built and installed in /tmp"
# /libzmq

# jemalloc
info "Running configure for jemalloc ..."
git config --global --add safe.directory "$top"/"$JEMALLOC_PACKAGE"  # Needed for some versions of git to not complain
cd "$top/$JEMALLOC_PACKAGE" || fail "Could not change dir to $JEMALLOC_PACKAGE"
./autogen.sh --with-jemalloc-prefix= --disable-shared --enable-static \
    || fail "Configure of jemalloc failed"

info "Building jemalloc ..."
make -j`nproc` || fail "Could not build jemalloc"
make install || fail "Could not install jemalloc"
JEMALLOC_LIBDIR=$(jemalloc-config --libdir)
[ -n "$JEMALLOC_LIBDIR" ] || fail "Could not determine JEMALLOC_LIBDIR"
JEMALLOC_INCDIR=$(jemalloc-config --includedir)
[ -n "$JEMALLOC_INCDIR" ] || fail "Could not determine JEMALLOC_INCDIR"
for a in "$JEMALLOC_LIBDIR"/libjemalloc*; do
    bn=`basename $a`
    info "Stripping $bn ..."
    strip -g "$a" || fail "Failed to strip $a"
done
printok "jemalloc static library built and installed in $JEMALLOC_LIBDIR"
# /jemalloc

# RocksDB
info "Building RocksDB ..."
git config --global --add safe.directory "$top"/"$ROCKSDB_PACKAGE"  # Needed for some versions of git to not complain
cd "$top/$ROCKSDB_PACKAGE" || fail "Could not cd tp $ROCKSDB_PACKAGE"
USE_RTTI=1 PORTABLE=1 DEBUG_LEVEL=0 make static_lib -j`nproc` V=1 \
    || fail "Could not build RocksDB"

info "Stripping librocksdb.a ..."
strip -g librocksdb.a || fail "Could not strip librocksdb.a"

info "Copying librocksdb.a to Fulcrum directory ..."
ROCKSDB_LIBDIR="$top"/"$PACKAGE"/staticlibs/rocksdb/bin/custom_linux  # prevents -dirty git commit hash
ROCKSDB_INCDIR="$top"/"$PACKAGE"/staticlibs/rocksdb/include
mkdir -p "${ROCKSDB_LIBDIR}" || fail "Could not create directory ${ROCKSDB_LIBDIR}"
cp -fpva librocksdb.a "${ROCKSDB_LIBDIR}" || fail "Could not copy librocksdb.a"
printok "RocksDB built and moved to Fulcrum staticlibs directory"
# /RocksDB

cd "$top"/"$PACKAGE" || fail "Could not chdir to Fulcrum dir"

# This is used by the Dockerfile for the regular Linux build for now to "force" linking to static libssl
if [ -n "$FORCE_STATIC_SSL" ]; then
    info "Moving dynamic OpenSSL libs out of the way ..."
    SSL_LDIR=$(pkg-config --variable=libdir libssl)
    [ -n "${SSL_LDIR}" ] || fail "Could not determine library directory for OpenSSL"
    mkdir -p /tmp/ssl_dynlibs || fail "Could not make the tmp dir for the openssl dynamic libs"
    mv -vf "${SSL_LDIR}"/libcrypto*.so* "${SSL_LDIR}"/libssl*.so* /tmp/ssl_dynlibs/. || fail "Could not move libs"
fi

info "Building Fulcrum ..."
git config --global --add safe.directory "$top"/"$PACKAGE"  # Needed for some versions of git to not complain
mkdir build && cd build || fail "Could not create/change-to build/"
if [ -n "${LDFLAGS}" ]; then
    # For things like -static-libstdc++, etc
    extra_libs="LIBS+=${LDFLAGS}"
else
    extra_libs=""
fi
qmake ../Fulcrum.pro "CONFIG-=debug" \
                     "CONFIG+=release" \
                     "${extra_libs}" \
                     "LIBS+=-L${ROCKSDB_LIBDIR} -lrocksdb" \
                     "LIBS+=-lz -lbz2" \
                     "INCLUDEPATH+=${ROCKSDB_INCDIR}" \
                     "LIBS+=-L${JEMALLOC_LIBDIR} -ljemalloc" \
                     "INCLUDEPATH+=${JEMALLOC_INCDIR}" \
                     "LIBS+=-L/tmp/lib -lzmq -lminiupnpc" \
                     "INCLUDEPATH+=/tmp/include" \
    || fail "Could not run qmake"
make -j`nproc` || fail "Could not run make"

# Undo the "damage" from the above move of openssl libs
if [ -n "$FORCE_STATIC_SSL" ] && [ -n "$SSL_LDIR" ]; then
    info "Moving dynamic OpenSSL libs back ..."
    mv -vf /tmp/ssl_dynlibs/* "${SSL_LDIR}"/.
    rm -vfr /tmp/ssl_dynlibs
fi

ls -al "$TARGET_BINARY" || fail "$TARGET_BINARY not found"
printok "$TARGET_BINARY built"

info "Copying to top level ..."
mkdir -p "$top/built" || fail "Could not create build products directory"
cp -fpva "$TARGET_BINARY" "$top/built/." || fail "Could not copy $TARGET_BINARY"
cd "$top" || fail "Could not cd to $top"

printok "Inner _build.sh finished"
