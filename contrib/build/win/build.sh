#!/bin/bash

set -e  # Exit on error

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

. "$here"/../common/common.sh # functions we use below (fail, et al)

if [ -z "$1" ]; then
    info "Please pass a tag, a branch, or a commit hash to this script, e.g. \"master\", \"v1.0.6\", etc ..."
    exit 1
fi
tag="$1"

cd "$here"
workdir=`pwd`/work
rm -fr "$workdir"
mkdir -p "$workdir"
pushd "$workdir"

# Checkout Fulcrum @ $tag
info "Checking out $PACKAGE: $GIT_REPO [$tag] ..."
git clone -b "$tag" "$GIT_REPO" "$PACKAGE" || fail "Could not clone repository for [$tag]"
cd "$PACKAGE"
pkgdir=`pwd`

rocksdb_commit=$(cat contrib/build/win/rocksdb-commit-hash) \
    || fail "Could not find the proper rocksdb commit hash in [$tag]. Please manually checkout [$tag] use its own build scripts."

cd ..

# Checkout rocksdb @ $tag
ROCKSDB_REPO=${ROCKSDB_REPO:-https://github.com/facebook/rocksdb.git}
ROCKSDB_PACKAGE=$(basename $ROCKSDB_REPO .git)
info "Checking out $ROCKSDB_PACKAGE: $ROCKSDB_REPO [$rocksdb_commit] ..."
git clone "$ROCKSDB_REPO" "$ROCKSDB_PACKAGE" || fail "Failed to clone $ROCKSDB_PACKAGE"
cd "$ROCKSDB_PACKAGE"
rocksdir=`pwd`
git checkout "$rocksdb_commit" || fail "Failed to checkout $ROCKSDB_PACKAGE [$rocksdb_commit]"
pp=$(ls "$pkgdir"/contrib/build/win/rocksdb*.patch 2> /dev/null || true)
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

popd

# Make Docker image
docker_img_name="fulcrum-builder/qt:windows"
docker_cont_name="fulcrum_cont_qt_windows"
info "Creating docker image: $docker_img_name ..."
docker build -t "$docker_img_name" . \
  || fail "Could not build docker image. Check that docker is installed and that you can run docker without sudo on this system."
printok "Docker image created: $docker_img_name"

# Run _build.sh from the specified commit inside Docker image, with ./work mapped to /work
cd "$workdir/.." || fail "Could not chdir"
info "Building inside docker container: $docker_cont_name ($docker_img_name) ..."
docker run --rm -it -v "$workdir":/work \
    --name "$docker_cont_name" \
    "$docker_img_name" ./work/"$PACKAGE"/contrib/build/win/_build.sh "$PACKAGE" "$ROCKSDB_PACKAGE"

(mkdir -p ../../../dist/win && cp -fpva "$workdir"/Fulcrum.exe ../../../dist/win/. && rm -fr work) \
    || fail "Could not clean up and move Fulcrum.exe"

cd ../../../ || fail "Could not chdir to the top level"
info "SHA256SUM:"
$SHA256_PROG dist/win/Fulcrum.exe || fail "Could not generate sha256sum"

printok "Fulcrum.exe has been placed in dist/win/ at the top level"
exit 0
