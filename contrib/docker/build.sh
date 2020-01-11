#!/bin/sh

set -e

if [ -z "$1" ] ; then
    echo "Usage: $0 <image tag>"
    exit 1
fi

IMAGE_TAG="$1"

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
. "$here"/../base.sh

docker build --build-arg MAKEFLAGS=$WORKER_COUNT -t "$IMAGE_TAG" -f contrib/docker/Dockerfile "$here"/../..
