# Mutual TLS (mTLS) in Fulcrum

Fulcrum has two independent TLS surfaces:

| Direction | Who Fulcrum is | Enabled by |
|---|---|---|
| **Outbound** — Fulcrum → bitcoind JSON-RPC | TLS client | `bitcoind_tls` |
| **Inbound** — Electrum clients → Fulcrum | TLS server | `ssl` / `wss` + `cert` / `key` |

Historically neither surface authenticated the other end. `bitcoind_tls` encrypted
the connection to the daemon but accepted any certificate at all and presented
none of its own, and the `ssl`/`wss` ports presented a server certificate but
never asked clients for one.

The options below add that authentication. **All of them default to off, and with
all of them unset Fulcrum behaves exactly as it did before.**

## Outbound: authenticating the daemon, and ourselves to it

| Option | Default | Meaning |
|---|---|---|
| `bitcoind_tls_verify` | `false` | Verify the certificate the daemon presents. |
| `bitcoind_tls_ca` | (system CA store) | PEM file of CA cert(s) to trust for that verification. |
| `bitcoind_tls_hostname` | (host from `bitcoind`) | Name required in the daemon's cert (CN or SAN). |
| `bitcoind_tls_cert` | (none) | PEM client cert (single cert, or leaf-first chain) to present. |
| `bitcoind_tls_key` | (none) | PEM **unencrypted** private key for `bitcoind_tls_cert`. |

All five require `bitcoind_tls = true`. `bitcoind_tls_ca` and
`bitcoind_tls_hostname` additionally require `bitcoind_tls_verify = true`, and
`bitcoind_tls_cert`/`bitcoind_tls_key` must be given together. Each option also
exists as a CLI arg, e.g. `--bitcoind-tls-verify`.

Note that `bitcoind_tls_verify` and `bitcoind_tls_cert` are orthogonal: the
former authenticates the daemon to Fulcrum, the latter authenticates Fulcrum to
the daemon. A full mTLS setup uses both.

If verification fails, Fulcrum logs the specific reason and then retries every 5
seconds, the same as for any other failure to reach the daemon:

```
<BitcoinD.1> SSL error verifying bitcoind at bitcoind.example.com: The root certificate of the
             certificate chain is self-signed, and untrusted (certificate: Example Corp Root CA)
```

## Quick start

Bitcoin Core does not speak TLS itself, so the usual arrangement is an nginx (or
stunnel, or haproxy) reverse proxy in front of it that terminates TLS, verifies
Fulcrum's client certificate, and forwards plain HTTP to bitcoind on localhost.

### 1. Mint a CA and two certificates

```sh
# A private CA. Keep ca-key.pem somewhere safe -- it can mint new clients.
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
    -keyout ca-key.pem -out ca-cert.pem -subj "/CN=My Bitcoin Infra CA"

# The server certificate, for the proxy in front of bitcoind. The SAN must
# contain the name (or IP) that Fulcrum will use in its `bitcoind=` setting.
openssl req -newkey rsa:2048 -nodes \
    -keyout bitcoind-key.pem -out bitcoind.csr -subj "/CN=bitcoind.example.com"
openssl x509 -req -in bitcoind.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out bitcoind-cert.pem -days 825 \
    -extfile <(echo "subjectAltName=DNS:bitcoind.example.com")

# The client certificate, for Fulcrum.
openssl req -newkey rsa:2048 -nodes \
    -keyout fulcrum-key.pem -out fulcrum.csr -subj "/CN=fulcrum"
openssl x509 -req -in fulcrum.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out fulcrum-cert.pem -days 825
```

Fulcrum needs `ca-cert.pem`, `fulcrum-cert.pem` and `fulcrum-key.pem`; the proxy
needs `ca-cert.pem`, `bitcoind-cert.pem` and `bitcoind-key.pem`. Neither needs
`ca-key.pem`. Make sure the key files are readable only by the user the
respective daemon runs as (`chmod 600`).

### 2. Terminate TLS in front of bitcoind

```nginx
server {
    listen 8332 ssl;
    server_name bitcoind.example.com;

    ssl_certificate     /etc/nginx/tls/bitcoind-cert.pem;
    ssl_certificate_key /etc/nginx/tls/bitcoind-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Require and verify a client certificate signed by our CA.
    ssl_client_certificate /etc/nginx/tls/ca-cert.pem;
    ssl_verify_client      on;

    location / {
        # bitcoind itself, listening plain-HTTP on loopback only
        proxy_pass http://127.0.0.1:8331;
    }
}
```

Point bitcoind at loopback to match, e.g. `rpcbind=127.0.0.1` and
`rpcport=8331` in `bitcoin.conf`.

### 3. Configure Fulcrum

```ini
bitcoind = bitcoind.example.com:8332
rpccookie = /path/to/bitcoind/.cookie

bitcoind_tls = true
bitcoind_tls_verify = true
bitcoind_tls_ca = /etc/fulcrum/tls/ca-cert.pem
# only needed if `bitcoind=` names a host that the server cert does not
#bitcoind_tls_hostname = bitcoind.example.com
bitcoind_tls_cert = /etc/fulcrum/tls/fulcrum-cert.pem
bitcoind_tls_key = /etc/fulcrum/tls/fulcrum-key.pem
```

Start Fulcrum with `debug = true` the first time; it echoes back what it loaded:

```
(Debug) config: bitcoind_tls = true
(Debug) config: bitcoind_tls_verify = true
(Debug) config: bitcoind_tls_ca = /etc/fulcrum/tls/ca-cert.pem (1 certificate(s))
(Debug) config: bitcoind_tls_cert = /etc/fulcrum/tls/fulcrum-cert.pem (1 certificate(s)), \
                bitcoind_tls_key = /etc/fulcrum/tls/fulcrum-key.pem
```

## Testing without a node

`contrib/mtls-test/run.sh` exercises all of the above against `openssl s_server`
standing in for the daemon — no bitcoind required. It mints its own throwaway
CA and certificates into a temp dir and checks both the accept and the reject
paths, including that the legacy `bitcoind_tls`-only behavior is unchanged:

```sh
contrib/mtls-test/run.sh /path/to/Fulcrum
```

## Limitations

* Private keys must be unencrypted. Passphrase-protected keys are not supported.
* Certificate files are read once, at startup. Replacing the files on disk
  requires a restart to take effect. (The `cert`/`key` files for the *inbound*
  SSL ports *are* hot-reloaded — see `SSLCertMonitor` — but the
  `bitcoind_tls_*` files are not.)
* Qt cannot definitively check that a private key belongs to a certificate, so
  Fulcrum compares only key algorithm and length at startup. A subtler mismatch
  shows up as a TLS handshake failure on the first connection attempt.
* No CRL or OCSP revocation checking is performed.
