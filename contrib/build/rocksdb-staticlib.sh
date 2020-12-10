#!/bin/bash

set -e  # Exit on error

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

pushd "$here" > /dev/null
here=`pwd`
popd > /dev/null
topdir="$here"/../..

. "$here"/common/common.sh # functions we use below (fail, et al)

bin_dir="staticlibs/rocksdb/bin"
plat_dir=""
strip_arg="-g"
case `uname` in
    Darwin)
        plat_dir="osx"
        strip_arg="-S"
        ;;
    Linux)
        plat_dir="linux"
        arch=`uname -m`
        if [ "${arch}" = "aarch64" ]; then
            info "aarch64 platform"
            # put it in a subdir linux/aarch64
            plat_dir="${plat_dir}/aarch64"
        elif [ "${arch}" = "x86_64" ]; then
            info "x86_64 platform"
        else
            fail "Unsupported arch: ${arch}"
        fi
        ;;
    *)
        fail "This shell script does not support this platform."
esac

info "We will build librocksdb.a and place it in: ${bin_dir}/${plat_dir} ..."

dest_dir="${topdir}/${bin_dir}/${plat_dir}"

workdir="${topdir}/contrib/work"
mkdir -p "${workdir}"
cd "${workdir}"
if [ -e "rocksdb" ]; then
    rm -fr rocksdb
fi

ROCKSDB_REPO=${ROCKSDB_REPO:-https://github.com/facebook/rocksdb.git}

# we use the linux commit-hash and patch even if on Darwin (it works ok)
rocksdb_commit=$(cat "$topdir"/contrib/build/linux/rocksdb-commit-hash) \
    || fail "Could not find the proper rocksdb commit hash."

info "Cloning repo ..."
git clone "$ROCKSDB_REPO" rocksdb || fail "Failed to clone rocksdb"
cd rocksdb
git checkout "$rocksdb_commit" || fail "Failed to checkout the requisite rocksdb commit: $rocksdb_commit"
if [ -e "$topdir"/contrib/build/linux/rocksdb.patch ]; then
    patch -p1 < "$topdir"/contrib/build/linux/rocksdb.patch || fail "Failed to patch rocksdb"
fi

info "Building librocksdb.a ..."
USE_RTTI=1 PORTABLE=1 DEBUG_LEVEL=0 make static_lib -j4 V=1 || fail "Failed to build librocksdb.a"

info "Stripping librocksdb.a ..."
[ -e librocksdb.a ] || fail "Expected build product librocksdb.a missing!"
strip "${strip_arg}" librocksdb.a

info "Copying librocksdb.a to ${bin_dir}/${plat_dir} ..."
mkdir -p "${dest_dir}"  # Just in case it doesn't exist (aarch64)
cp -fpva librocksdb.a "${dest_dir}" || fail "Failed to copy lib to destination"

# Clean up
info "Cleaning up ..."
cd "${topdir}"
rm -fr "${workdir}"

info "librocksdb.a has been compiled and placed in the staticlibs/ directory where Fulcrum.pro can find it."
info "You may now run qmake against Fulcrum.pro"
