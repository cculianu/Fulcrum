#!/usr/bin/env bash

# Set BUILD_DEBUG=1 to enable additional build output
if [ "${BUILD_DEBUG:-0}" -ne 0 ] ; then
    set -x # Enable shell command logging
fi

# Set a fixed umask as this leaks into the docker container
umask 0022

# First, some functions that build scripts may use for pretty printing
if [ -t 1 ] ; then
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    LIGHTCYAN='\033[1;36m'
    LIGHTRED='\033[1;31m'
    NC='\033[0m' # No Color

    MSG_INFO="\r💬 ${LIGHTCYAN}"
    MSG_ERROR="\r❌  ${LIGHTRED}ERROR:${NC}"
    MSG_WARNING="\r⚠️  ${YELLOW}WARNING:${NC}"
    MSG_OK="\r👍  ${GREEN}OK:${NC}"
else
    RED=''
    BLUE=''
    YELLOW=''
    GREEN=''
    LIGHTCYAN=''
    LIGHTRED=''
    NC='' # No Color

    MSG_INFO="INFO:"
    MSG_ERROR="ERROR:"
    MSG_WARNING="WARNING:"
    MSG_OK="OK:"
fi

function info {
    printf "${MSG_INFO}  ${1}${NC}\n"
}
function fail {
    printf "${MSG_ERROR}  ${1}${NC}\n" >&2

    if [ -r /.dockerenv ] ; then
        if [ -t 1 ] ; then
            if [ "${BUILD_DEBUG:-0}" -ne 0 ] ; then
                bash || true
            fi
        fi
    fi

    exit 1
}
function warn {
    printf "${MSG_WARNING}  ${1}${NC}\n"
}
function printok {
    printf "${MSG_OK}  ${1}${NC}\n"
}

function verify_hash {
    local file=$1 expected_hash=$2
    sha_prog=`which sha256sum || which gsha256sum`
    if [ -z "$sha_prog" ]; then
        fail "Please install sha256sum or gsha256sum"
    fi
    if [ ! -e "$file" ]; then
        fail "Cannot verify hash for $file -- not found!"
    fi
    bn=`basename $file`
    actual_hash=$($sha_prog $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        printok "'$bn' hash verified"
        return 0
    else
        warn "Hash verify failed, removing '$file' as a safety measure"
        rm "$file"
        fail "$file $actual_hash (unexpected hash)"
    fi
}

# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
function verify_signature {
    local file=$1 keyring=$2 out=
    bn=`basename $file .asc`
    info "Verifying PGP signature for $bn ..."
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) \
            && echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        printok "$bn signature verified"
        return 0
    else
        fail "$out"
    fi
}

function download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
        if [ -n "$(which wget)" ]; then
            wget -O $file_name "$url" || fail "Failed to download $file_name"
        else
            curl -L "$url" > $file_name || fail "Failed to download $file_name"
        fi
    fi

}

# https://github.com/travis-ci/travis-build/blob/master/lib/travis/build/templates/header.sh
function retry() {
  local result=0
  local count=1
  while [ $count -le 3 ]; do
    [ $result -ne 0 ] && {
      echo -e "\nThe command \"$@\" failed. Retrying, $count of 3.\n" >&2
    }
    ! { "$@"; result=$?; }
    [ $result -eq 0 ] && break
    count=$(($count + 1))
    sleep 1
  done

  [ $count -gt 3 ] && {
    echo -e "\nThe command \"$@\" failed 3 times.\n" >&2
  }

  return $result
}

function gcc_with_triplet()
{
    TRIPLET="$1"
    CMD="$2"
    shift 2
    if [ -n "$TRIPLET" ] ; then
        "$TRIPLET-$CMD" "$@"
    else
        "$CMD" "$@"
    fi
}

function gcc_host()
{
    gcc_with_triplet "$GCC_TRIPLET_HOST" "$@"
}

function gcc_build()
{
    gcc_with_triplet "$GCC_TRIPLET_BUILD" "$@"
}

function host_strip()
{
    if [ "$GCC_STRIP_BINARIES" -ne "0" ] ; then
        case "$BUILD_TYPE" in
            linux|wine)
                gcc_host strip "$@"
                ;;
            darwin)
                # TODO: Strip on macOS?
                ;;
        esac
    fi
}

# From: https://stackoverflow.com/a/4024263
# By kanaka (https://stackoverflow.com/users/471795/)
function verlte()
{
    [  "$1" = "`echo -e "$1\n$2" | $SORT_PROG -V | head -n1`" ]
}

function verlt()
{
    [ "$1" = "$2" ] && return 1 || verlte $1 $2
}

if ((_COMMON_SH_SOURCED==1)) ; then
    # common.sh has been sourced already, no need to source it again
    return 0
fi

which git > /dev/null || fail "Git is required to proceed"

DEFAULT_GIT_REPO=https://github.com/cculianu/Fulcrum.git
if [ -z "$GIT_REPO" ] ; then
    # If no override from env is present, use default. Support for overrides
    # for the GIT_REPO has been added to allows contributors to test containers
    # that are on local filesystem (while devving) or are their own github forks
    GIT_REPO="$DEFAULT_GIT_REPO"
fi
if [ "$GIT_REPO" != "$DEFAULT_GIT_REPO" ]; then
    # We check if it's default because we unconditionally propagate $GIT_REPO
    # in env to _build.sh inside the docker container, and we don't want to
    # print this message if it turns out to just be the default.
    info "Picked up override from env: GIT_REPO=${GIT_REPO}"
fi
GIT_DIR_NAME=`basename $GIT_REPO .git`
PACKAGE=${PACKAGE:-Fulcrum}  # Modify this if you like


SHA256_PROG=`which sha256sum || which gsha256sum`
if [ -z "$SHA256_PROG" ]; then
    fail "Please install sha256sum or gsha256sum"
fi

SORT_PROG=`which gsort || which sort`
if [ -z "$SORT_PROG" ]; then
    fail "Please install sort or gsort"
fi

MKTEMP_PROG=`which mktemp`
if [ -z "$MKTEMP_PROG" ]; then
  fail "mktemp command is missing"
fi

# This variable is set to avoid sourcing base.sh multiple times
export _COMMON_SH_SOURCED=1
