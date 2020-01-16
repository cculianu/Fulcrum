#!/bin/sh

version="$1"
if [ -z "$version" ]; then
    echo "Usage: $0 <new version>"
    exit 1
fi

sed -i "/^#define VERSION .*/c\#define VERSION \"$version\"" src/Common.h
sed -i "/^Version: .*/c\Version: $version" contrib/rpm/fulcrum.spec
