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
TARGET_ADMIN_SCRIPT=FulcrumAdmin

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
mkdir -p "$top/built" || fail "Could not create build products directory"
cp -fpva "$TARGET_BINARY" "$top/built/." || fail "Could not copy $TARGET_BINARY"
cd "$top" || fail "Could not cd to $top"

function build_AdminScript {
    info "Preparing to build ${TARGET_ADMIN_SCRIPT}.exe ..."
    pushd "$top" 1> /dev/null || fail "Could not chdir to $top"
    rm -fr tmp || true
    mkdir tmp || fail "Cannot mkdir tmp"
    cd tmp || fail "Cannot chdir tmp"
    export WINEPREFIX=$HOME/wine64
    export WINEDEBUG=-all
	#ARCH=win32
    #PYTHON_VERSION=3.6.8
	#WINE=wine
	ARCH=amd64
    PYTHON_VERSION=3.8.2
	WINE=wine64
    PYHOME=c:/python$PYTHON_VERSION
    PYTHON="$WINE $PYHOME/python.exe -OO -B"
    info "Starting Wine ..."
    $WINE 'wineboot' || fail "Cannot start Wine ..."
    info "Installing Python $PYTHON_VERSION (within Wine) ..."
    for msifile in core dev exe lib pip tools; do
        info "Downloading Python component: ${msifile} ..."
        wget "https://www.python.org/ftp/python/$PYTHON_VERSION/${ARCH}/${msifile}.msi"
        info "Installing Python component: ${msifile} ..."
        $WINE msiexec /i "${msifile}.msi" /qn TARGETDIR=$PYHOME || fail "Failed to install Python component: ${msifile}"
    done
    pver=$($PYTHON --version) || fail "Could not verify version"
    printok "Python reports version: $pver"
    unset pver
    info "Updating Python $PYTHON_VERSION ..."
    $PYTHON -m pip install --upgrade pip || fail "Failed to update Python"
    info "Installing PyInstaller ..."
    $PYTHON -m pip install --upgrade pyinstaller || fail "Failed to install PyInstaller"
    info "Building ${TARGET_ADMIN_SCRIPT}.exe (with PyInstaller) ..."
    cp -fpva "$top/$PACKAGE/${TARGET_ADMIN_SCRIPT}" . || fail "Failed to copy script"
    cp -fpva "$top/$PACKAGE/contrib/build/win/${TARGET_ADMIN_SCRIPT}.spec" . || fail "Failed to copy .spec file"
    # TODO: Add an icon here, -i option
    $PYTHON -m PyInstaller --clean ${TARGET_ADMIN_SCRIPT}.spec \
        || fail "Failed to build ${TARGET_ADMIN_SCRIPT}.exe"
    info "Copying to top level ..."
    mkdir -p "$top/built" || true
    cp -fpva dist/${TARGET_ADMIN_SCRIPT}.exe "$top/built/." || fail "Could not copy to top level"
    printok "${TARGET_ADMIN_SCRIPT}.exe built"
    cd "$top" && rm -fr tmp
    popd 1> /dev/null
	# Be tidy and clean up variables we created above
	unset WINEPREFIX WINEDEBUG ARCH PYTHON_VERSION WINE PYHOME PYTHON
}
build_AdminScript || fail "Could not build ${TARGET_ADMIN_SCRIPT}.exe"


printok "Inner _build.sh finished"
