FROM debian:13.1 AS builder

LABEL maintainer="Axel Gembe <derago@gmail.com>"

ARG MAKEFLAGS
ENV LC_ALL="C.UTF-8"

RUN apt update -y && \
    apt install -y \
        openssl git build-essential pkg-config zlib1g-dev libbz2-dev libjemalloc-dev libzmq3-dev libminiupnpc-dev \
        qt6-base-dev qmake6

WORKDIR /src

COPY . .

RUN qmake6 -makefile PREFIX=/usr Fulcrum.pro && \
    make $MAKEFLAGS install

FROM debian:13.1-slim

RUN apt update && \
    apt install -y openssl libqt6network6 zlib1g libbz2-1.0 libjemalloc2 libzmq5 python3 libminiupnpc18 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /src/Fulcrum /usr/bin/Fulcrum
COPY --from=builder /src/FulcrumAdmin /usr/bin/FulcrumAdmin

VOLUME ["/data"]
ENV LC_ALL="C.UTF-8"
ENV DATA_DIR=/data

ENV SSL_CERTFILE=${DATA_DIR}/fulcrum.crt
ENV SSL_KEYFILE=${DATA_DIR}/fulcrum.key

EXPOSE 50001 50002

COPY contrib/docker/docker-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["Fulcrum"]
