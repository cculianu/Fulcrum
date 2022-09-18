#!/bin/bash

set -e  # Exit on error

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

. "$here"/common/common.sh # functions we use below (fail, et al)

if [ -z "$1" ]; then
    info "Please specify a build platform as the first argument, one of: windows linux linux_ub22 linux_ub16 (or short versions: win lin newlin oldlin)"
    exit 1
fi
plat="$1"

if [ -z "$2" ]; then
    info "Please pass a tag, a branch, or a commit hash to this script as the second argument, e.g. \"master\", \"v1.0.6\", etc ..."
    exit 1
fi
tag="$2"

suffix=""
case "$plat" in
    "windows_qt6"|"win_qt6")
        plat=win  # normalize to 'win'
        docker_img_name="fulcrum-builder/qt620beta3:windows"
        docker_cont_name="fulcrum_cont_qt_6_2_0beta3_windows_$$"
        suffix="_qt6"
        ;;
    "windows"|"win")
        plat=win  # normalize to 'win'
        docker_img_name="fulcrum-builder/qt:windows"
        docker_cont_name="fulcrum_cont_qt_windows_$$"
        ;;
    "linux"|"lin")
        plat=linux
        docker_img_name="fulcrum-builder/qt:linux"
        docker_cont_name="fulcrum_cont_qt_linux_$$"
        ;;
    "linux_ub22"|"newlinux"|"newlin"|"lin_ub22")
        plat=linux
        docker_img_name="fulcrum-builder/qt:linux_ub22"
        docker_cont_name="fulcrum_cont_qt_linux_ub22_$$"
        suffix="_ub22"
        ;;
    "linux_ub16"|"oldlinux"|"oldlin"|"lin_ub16")
        plat=linux
        docker_img_name="fulcrum-builder/qt:linux_ub16"
        docker_cont_name="fulcrum_cont_qt_linux_ub16_$$"
        suffix="_ub16"
        ;;
    *)
        fail "Unknown platform \"$plat\". Please specify one of: windows linux linux_ub22 linux_ub16"
        ;;
esac

osxfs_option=""
if [ `uname` == "Darwin" ]; then
    osxfs_option=":delegated"
fi


dockerfile=Dockerfile${suffix}
cd "$here"/"$plat"
workdir=`pwd`/work${suffix}
outdir=`pwd`/../../../dist/${plat}${suffix}
rm -fr "$workdir"
mkdir -p "$workdir"
pushd "$workdir" 1> /dev/null

# Checkout Fulcrum @ $tag
info "Checking out $PACKAGE: $GIT_REPO [$tag] ..."
git clone -b "$tag" "$GIT_REPO" "$PACKAGE" || fail "Could not clone repository for [$tag]"
cd "$PACKAGE"
pkgdir=`pwd`

rocksdb_commit=$(cat contrib/build/${plat}/rocksdb-commit-hash) \
    || fail "Could not find the proper rocksdb commit hash in [$tag]."

jemalloc_commit=$(cat contrib/build/${plat}/jemalloc-commit-hash) \
    || fail "Could not find the proper jemalloc commit hash in [$tag]."


cd ..

# Checkout jemalloc @ $tag
JEMALLOC_REPO=${JEMALLOC_REPO:-https://github.com/jemalloc/jemalloc.git}
JEMALLOC_PACKAGE=$(basename $JEMALLOC_REPO .git)
info "Checking out $JEMALLOC_PACKAGE: $JEMALLOC_REPO [$jemalloc_commit] ..."
git clone "$JEMALLOC_REPO" "$JEMALLOC_PACKAGE" || fail "Failed to clone $JEMALLOC_PACKAGE"
cd "$JEMALLOC_PACKAGE"
jemallocdir=`pwd`
git checkout "$jemalloc_commit" || fail "Failed to checkout $JEMALLOC_PACKAGE [$jemalloc_commit]"
pp=$(ls "$pkgdir"/contrib/build/${plat}/jemalloc*.patch 2> /dev/null || true)
if [ -n "$pp" ]; then
    info "Applying patches ..."
    let i=0 || true
    for a in $pp; do
        info "Applying ${a} ..."
        patch -p1 < "$a" || fail "Could not apply patch: $a"
        let i++ || true
    done
    printok "${i} patch(es) applied"
fi

cd ..  # back up, proceed to rocksdb checkout

# Checkout rocksdb @ $tag
ROCKSDB_REPO=${ROCKSDB_REPO:-https://github.com/facebook/rocksdb.git}
ROCKSDB_PACKAGE=$(basename $ROCKSDB_REPO .git)
info "Checking out $ROCKSDB_PACKAGE: $ROCKSDB_REPO [$rocksdb_commit] ..."
git clone "$ROCKSDB_REPO" "$ROCKSDB_PACKAGE" || fail "Failed to clone $ROCKSDB_PACKAGE"
cd "$ROCKSDB_PACKAGE"
rocksdir=`pwd`
git checkout "$rocksdb_commit" || fail "Failed to checkout $ROCKSDB_PACKAGE [$rocksdb_commit]"
pp=$(ls "$pkgdir"/contrib/build/${plat}/rocksdb*.patch 2> /dev/null || true)
if [ -n "$pp" ]; then
    info "Applying patches ..."
    let i=0 || true
    for a in $pp; do
        info "Applying ${a} ..."
        patch -p1 < "$a" || fail "Could not apply patch: $a"
        let i++ || true
    done
    printok "${i} patch(es) applied"
fi

popd 1> /dev/null

# Make Docker image using the commit's Dockerfile
cd "${workdir}/${PACKAGE}/contrib/build/${plat}" || fail "Could not chdir to Dockerfile directory"
[ -e "$dockerfile" ] || fail "Could not find $dockerfile in $(pwd)"
info "Creating docker image: $docker_img_name ..."
docker build -t "$docker_img_name" - < "$dockerfile" \
  || fail "Could not build docker image. Check that docker is installed and that you can run docker without sudo on this system."
printok "Docker image created: $docker_img_name"

# Run _build.sh from the specified commit inside Docker image, with $workdir (usually ./work) mapped to /work
cd "$workdir/.." || fail "Could not chdir"
info "Building inside docker container: $docker_cont_name ($docker_img_name) ..."
docker run --rm -it -v "$workdir":/work${osxfs_option} \
    --name "$docker_cont_name" \
    "$docker_img_name" /work/"$PACKAGE"/contrib/build/${plat}/_build.sh "$PACKAGE" "$ROCKSDB_PACKAGE" "$JEMALLOC_PACKAGE" "$DEBUG_BUILD"

(mkdir -p "$outdir" && cp -fpva "$workdir"/built/* "$outdir"/. && rm -fr "$workdir") \
    || fail "Could not clean up and move build products"

cd ../../../ || fail "Could not chdir to the top level"
info "SHA256SUM:"
$SHA256_PROG dist/${plat}${suffix}/* || fail "Could not generate sha256sum"

printok "Build product(s) have been placed in dist/${plat}${suffix}/ at the top level"
exit 0
