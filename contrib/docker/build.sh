#!/bin/sh

set -e

if [ -z "$1" ] ; then
    echo "Usage: $0 <image tag>"
    exit 1
fi

IMAGE_TAG="$1"

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
. "$here"/../base.sh

docker buildx build --build-arg MAKEFLAGS="-j $WORKER_COUNT" -t "$IMAGE_TAG" -f Dockerfile \
    --platform linux/arm64/v8,linux/amd64 --push "$here"/../..
