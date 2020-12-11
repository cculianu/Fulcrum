#!/bin/sh

set -e

if [ -z "$CPU_COUNT" ] ; then
    # CPU_COUNT is not set, try to detect the core count
    case $(uname) in
        Linux)
            export CPU_COUNT=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
            ;;
        Darwin)
            export CPU_COUNT=$(sysctl -n hw.ncpu)
            ;;
    esac
fi
# If CPU_COUNT is still unset, default to 4
export CPU_COUNT="${CPU_COUNT:-4}"
# Use one more worker than core count
export WORKER_COUNT=$(($CPU_COUNT+1))
