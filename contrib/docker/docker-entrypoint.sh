#!/bin/sh

if [ ! -e "$SSL_CERTFILE" ] || [ ! -e "$SSL_KEYFILE" ] ; then
  openssl req -newkey rsa:2048 -sha256 -nodes -x509 -days 365 -subj "/O=Fulcrum" -keyout "$SSL_KEYFILE" -out "$SSL_CERTFILE"
fi

if [ "$1" = "Fulcrum" ] ; then
  set -- "$@" -D "$DATA_DIR" -c "$SSL_CERTFILE" -k "$SSL_KEYFILE"
fi

exec "$@"
