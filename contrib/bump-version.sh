#!/bin/sh

SED=sed

# On macOS "sed" won't work, because it's some strange BSD version
# so must insist on gsed or die.
if [ `uname` == "Darwin" ]; then
    if (which gsed > /dev/null); then
        SED=gsed
    else
	echo "Please install gsed on macOS to use this script."
	exit 1
    fi
fi

version="$1"
if [ -z "$version" ]; then
    echo "Usage: $0 <new version>"
    exit 1
fi

$SED -i "/^#define VERSION .*/c\#define VERSION \"$version\"" src/Common.h
$SED -i "/^Version: .*/c\Version: $version" contrib/rpm/fulcrum.spec
