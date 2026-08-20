#!/usr/bin/env bash
#
# Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
# Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see LICENSE.txt).  If not, see
# <https://www.gnu.org/licenses/>.
#
# ------------------------------------------------------------------------------
# Integration test for the bitcoind_tls_* and ssl_verify_clients options (mTLS).
#
# No bitcoind is required: the remote daemon is impersonated by `openssl
# s_server` and inbound Electrum clients by `openssl s_client`.  A throwaway CA
# plus server & client certificates are minted into a temp dir which is removed
# on exit.
#
# Usage:  contrib/mtls-test/run.sh [/path/to/Fulcrum]
#
# If the Fulcrum binary is not given, $FULCRUM is used, else `Fulcrum` from
# $PATH.  Override the ports with $DAEMON_PORT / $TCP_PORT / $SSL_PORT if the
# defaults collide with something on your machine.
# ------------------------------------------------------------------------------
set -u -o pipefail

FULCRUM=${1:-${FULCRUM:-Fulcrum}}
DAEMON_PORT=${DAEMON_PORT:-19332}   # the fake "bitcoind" that openssl s_server provides
TCP_PORT=${TCP_PORT:-59001}         # Fulcrum's plain TCP Electrum port (unused, but Fulcrum wants a port)
SSL_PORT=${SSL_PORT:-59002}         # Fulcrum's SSL Electrum port (used by the inbound tests)
SETTLE_SECS=${SETTLE_SECS:-6}       # how long to let Fulcrum run before reading its log

if ! command -v "$FULCRUM" >/dev/null 2>&1 && [ ! -x "$FULCRUM" ]; then
    echo "Cannot find the Fulcrum binary '$FULCRUM'. Pass its path as the first argument." >&2
    exit 2
fi
command -v openssl >/dev/null || { echo "openssl not found in \$PATH" >&2; exit 2; }

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/fulcrum-mtls-test.XXXXXX")
cleanup() {
    # shellcheck disable=SC2046  # deliberate word splitting of the pid list
    kill $(jobs -p) 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT
cd "$WORKDIR"

NPASS=0 NFAIL=0
pass() { NPASS=$((NPASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { NFAIL=$((NFAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

# ------------------------------------------------------------------------------
# Mint a throwaway CA, a server cert (for the fake daemon and for Fulcrum's own
# SSL port) and a client cert (for Fulcrum to present, and for s_client to use).
# A second, unrelated CA gives us the "wrong CA" negative case, and a spare EC
# key gives us the "key does not match cert" negative case.
# ------------------------------------------------------------------------------
gen_certs() {
    local subj_alt
    subj_alt=$(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n')

    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca-cert.pem \
        -days 1 -subj "/CN=Fulcrum mTLS Test CA"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout other-ca-key.pem -out other-ca-cert.pem \
        -days 1 -subj "/CN=Fulcrum mTLS Test CA (unrelated)"

    openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj "/CN=localhost"
    openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
        -out server-cert.pem -days 1 -extfile <(echo "$subj_alt")

    openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client.csr -subj "/CN=fulcrum-client"
    openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
        -out client-cert.pem -days 1

    openssl ecparam -genkey -name prime256v1 -noout -out mismatch-key.pem
}

# ------------------------------------------------------------------------------
# Write a fulcrum.conf out of the common preamble plus the given extra lines.
# ------------------------------------------------------------------------------
write_conf() {
    rm -rf datadir && mkdir -p datadir
    {
        echo "datadir = $WORKDIR/datadir"
        echo "bitcoind = localhost:$DAEMON_PORT"
        echo "rpcuser = user"
        echo "rpcpassword = pass"
        echo "tcp = 127.0.0.1:$TCP_PORT"
        echo "debug = true"
        echo "peering = false"
        printf '%s\n' "$@"
    } > fulcrum.conf
}

# Run Fulcrum with the current fulcrum.conf until it settles, then kill it.
# The log lands in fulcrum.log.  $1, if given, is a command run while Fulcrum
# is up (used by the inbound tests to poke the SSL port).
run_fulcrum() {
    "$FULCRUM" fulcrum.conf > fulcrum.log 2>&1 &
    local fpid=$!
    sleep "$SETTLE_SECS"
    [ $# -gt 0 ] && eval "$1"
    kill "$fpid" 2>/dev/null
    wait "$fpid" 2>/dev/null
    return 0
}

# Assert that Fulcrum refused to start, with $2 appearing in its complaint.
expect_startup_error() {
    local label=$1 needle=$2
    local out
    out=$("$FULCRUM" fulcrum.conf 2>&1 | head -3)
    if ! grep -q "Use the -h option" <<< "$out"; then
        fail "$label (Fulcrum started, but should have refused to)"
    elif ! grep -qF -- "$needle" <<< "$out"; then
        fail "$label (wrong error: $(head -1 <<< "$out"))"
    else
        pass "$label"
    fi
}

# Assert that Fulcrum accepted the config and got as far as starting up.
expect_startup_ok() {
    local label=$1
    if "$FULCRUM" fulcrum.conf 2>&1 | head -3 | grep -q "Use the -h option"; then
        fail "$label (Fulcrum refused to start)"
    else
        pass "$label"
    fi
}

grep_log() { grep -qE "$1" fulcrum.log; }

# ==============================================================================
echo "Generating throwaway CA and certificates in $WORKDIR ..."
gen_certs > openssl.log 2>&1 || { echo "Certificate generation failed:"; cat openssl.log; exit 2; }
CA=$WORKDIR/ca-cert.pem
OTHER_CA=$WORKDIR/other-ca-cert.pem
CLIENT_CERT=$WORKDIR/client-cert.pem
CLIENT_KEY=$WORKDIR/client-key.pem

# ==============================================================================
echo
echo "=== 1. Option validation (no daemon involved) ==="

write_conf "bitcoind_tls_verify = true"
expect_startup_error "bitcoind_tls_verify without bitcoind_tls" "require that bitcoind_tls"
write_conf "bitcoind_tls_ca = $CA"
expect_startup_error "bitcoind_tls_ca without bitcoind_tls" "require that bitcoind_tls"
write_conf "bitcoind_tls_hostname = localhost"
expect_startup_error "bitcoind_tls_hostname without bitcoind_tls" "require that bitcoind_tls"
write_conf "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_error "bitcoind_tls_cert/key without bitcoind_tls" "require that bitcoind_tls"

write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $CLIENT_CERT"
expect_startup_error "bitcoind_tls_cert without bitcoind_tls_key" "must both be specified"
write_conf "bitcoind_tls = true" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_error "bitcoind_tls_key without bitcoind_tls_cert" "must both be specified"
write_conf "bitcoind_tls = true" "bitcoind_tls_ca = $CA"
expect_startup_error "bitcoind_tls_ca without bitcoind_tls_verify" "bitcoind_tls_verify"
write_conf "bitcoind_tls = true" "bitcoind_tls_hostname = localhost"
expect_startup_error "bitcoind_tls_hostname without bitcoind_tls_verify" "bitcoind_tls_verify"

write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $WORKDIR/enoent.pem" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_error "unreadable bitcoind_tls_cert" "cert file not found"
write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $WORKDIR/enoent.pem"
expect_startup_error "unreadable bitcoind_tls_key" "key file not found"
write_conf "bitcoind_tls = true" "bitcoind_tls_verify = true" "bitcoind_tls_ca = $WORKDIR/enoent.pem"
expect_startup_error "unreadable bitcoind_tls_ca" "CA file not found"
write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $WORKDIR/ca-key.pem" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_error "bitcoind_tls_cert is not a certificate" "Unable to read a certificate"
write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CA"
expect_startup_error "bitcoind_tls_key is not a private key" "Unable to read a private key"
write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $WORKDIR/mismatch-key.pem"
expect_startup_error "bitcoind_tls_key does not match cert" "does not match cert"

write_conf
expect_startup_ok "no TLS options at all"
write_conf "bitcoind_tls = true"
expect_startup_ok "bitcoind_tls alone (legacy)"
write_conf "bitcoind_tls = true" "bitcoind_tls_verify = true"
expect_startup_ok "bitcoind_tls_verify against the system CA store"
write_conf "bitcoind_tls = true" "bitcoind_tls_verify = true" "bitcoind_tls_ca = $CA"
expect_startup_ok "bitcoind_tls_verify with an explicit CA"
write_conf "bitcoind_tls = true" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_ok "client certificate without verification"
write_conf "bitcoind_tls = true" "bitcoind_tls_verify = true" "bitcoind_tls_ca = $CA" \
           "bitcoind_tls_hostname = localhost" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
expect_startup_ok "full mTLS configuration"

# ==============================================================================
echo
echo "=== 2. Outbound mTLS to the daemon (openssl s_server stands in) ==="

# $1 = extra s_server args, rest = extra fulcrum.conf lines
start_daemon_and_run() {
    local sargs=$1; shift
    # shellcheck disable=SC2086  # deliberate word splitting of $sargs
    openssl s_server -accept "$DAEMON_PORT" -cert server-cert.pem -key server-key.pem \
        -CAfile ca-cert.pem $sargs -www -quiet > s_server.log 2>&1 &
    local spid=$!
    sleep 1
    write_conf "$@"
    run_fulcrum
    kill "$spid" 2>/dev/null
    wait "$spid" 2>/dev/null
    return 0
}

start_daemon_and_run "-Verify 1" "bitcoind_tls = true" "bitcoind_tls_verify = true" \
    "bitcoind_tls_ca = $CA" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
if grep_log "SSL error verifying bitcoind"; then
    fail "full mTLS handshake succeeds (Fulcrum reported an SSL error)"
elif ! grep_log "on_connected"; then
    fail "full mTLS handshake succeeds (Fulcrum never got an encrypted connection)"
elif ! grep -q "CN *= *fulcrum-client" s_server.log; then
    fail "full mTLS handshake succeeds (the daemon never saw our client certificate)"
else
    pass "full mTLS handshake succeeds and presents the client certificate"
fi

start_daemon_and_run "-Verify 1" "bitcoind_tls = true" "bitcoind_tls_verify = true" \
    "bitcoind_tls_ca = $OTHER_CA" "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
if grep_log "SSL error verifying bitcoind.*(self-signed|untrusted|issuer)"; then
    pass "wrong bitcoind_tls_ca is rejected"
else
    fail "wrong bitcoind_tls_ca is rejected (no verification error logged)"
fi

start_daemon_and_run "-Verify 1" "bitcoind_tls = true" "bitcoind_tls_verify = true" "bitcoind_tls_ca = $CA" \
    "bitcoind_tls_hostname = not-the-right-host.invalid" \
    "bitcoind_tls_cert = $CLIENT_CERT" "bitcoind_tls_key = $CLIENT_KEY"
if grep_log "SSL error verifying bitcoind.*host name did not match"; then
    pass "wrong bitcoind_tls_hostname is rejected"
else
    fail "wrong bitcoind_tls_hostname is rejected (no host name error logged)"
fi

start_daemon_and_run "-Verify 1" "bitcoind_tls = true" "bitcoind_tls_verify = true" "bitcoind_tls_ca = $CA"
# Note: with TLS 1.3 the daemon's "certificate required" alert arrives *after* the handshake completes,
# so Fulcrum sees an encrypted connection first and only then a read error. Either way the connection dies.
if grep_log "certificate required|alert|handshake"; then
    pass "daemon requiring a client cert rejects us when we have none configured"
else
    fail "daemon requiring a client cert rejects us when we have none configured (connection was not refused)"
fi

# Regression guard: the historical bitcoind_tls behavior must still ignore every certificate problem.
start_daemon_and_run "" "bitcoind_tls = true"
if grep_log "SSL error verifying bitcoind"; then
    fail "bitcoind_tls alone still ignores certificate errors (it did not)"
elif ! grep_log "on_connected"; then
    fail "bitcoind_tls alone still ignores certificate errors (no encrypted connection)"
else
    pass "bitcoind_tls alone still ignores certificate errors (legacy behavior preserved)"
fi

# ==============================================================================
echo
echo "=== 3. Inbound client certificates on Fulcrum's own SSL port ==="

if ! "$FULCRUM" --help 2>&1 | grep -q "ssl-verify-clients"; then
    echo "  SKIP  this build has no --ssl-verify-clients option (phase 2 not present)"
else
    inbound_conf() {
        write_conf "ssl = 127.0.0.1:$SSL_PORT" "cert = $WORKDIR/server-cert.pem" \
                   "key = $WORKDIR/server-key.pem" "$@"
    }

    # An `openssl s_client` handshake against Fulcrum's SSL port. $1 = extra s_client args.
    probe_ssl_port() {
        openssl s_client -connect "127.0.0.1:$SSL_PORT" -CAfile "$CA" -servername localhost \
            -verify_return_error $1 </dev/null > s_client.log 2>&1
        echo $? > s_client.rc
    }

    inbound_conf "ssl_verify_clients = true"
    expect_startup_error "ssl_verify_clients without ssl_client_ca" "ssl_client_ca"

    inbound_conf "ssl_client_ca = $CA"
    expect_startup_error "ssl_client_ca without ssl_verify_clients" "ssl_verify_clients"

    inbound_conf "ssl_verify_clients = true" "ssl_client_ca = $CA"
    run_fulcrum "probe_ssl_port \"-cert $CLIENT_CERT -key $CLIENT_KEY\""
    if [ "$(cat s_client.rc)" = 0 ] && grep -q "Verify return code: 0" s_client.log; then
        pass "client presenting a valid certificate completes the handshake"
    else
        fail "client presenting a valid certificate completes the handshake (s_client rc=$(cat s_client.rc))"
    fi

    inbound_conf "ssl_verify_clients = true" "ssl_client_ca = $CA"
    run_fulcrum "probe_ssl_port \"\""
    if [ "$(cat s_client.rc)" != 0 ] || grep_log "no client certificate|SSL error"; then
        pass "client presenting no certificate is dropped"
    else
        fail "client presenting no certificate is dropped (it was accepted)"
    fi

    inbound_conf "ssl_verify_clients = true" "ssl_client_ca = $OTHER_CA"
    run_fulcrum "probe_ssl_port \"-cert $CLIENT_CERT -key $CLIENT_KEY\""
    if [ "$(cat s_client.rc)" != 0 ] || grep_log "SSL error"; then
        pass "client certificate from an untrusted CA is dropped"
    else
        fail "client certificate from an untrusted CA is dropped (it was accepted)"
    fi

    # Regression guard: without ssl_verify_clients, a certificate-less client is still fine.
    inbound_conf
    run_fulcrum "probe_ssl_port \"\""
    if [ "$(cat s_client.rc)" = 0 ]; then
        pass "SSL port still accepts certificate-less clients by default"
    else
        fail "SSL port still accepts certificate-less clients by default (rc=$(cat s_client.rc))"
    fi
fi

# ==============================================================================
echo
echo "$NPASS passed, $NFAIL failed"
[ "$NFAIL" -eq 0 ]
