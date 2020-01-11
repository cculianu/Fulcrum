FROM ubuntu:bionic
LABEL maintainer="Axel Gembe <derago@gmail.com>"

ARG MAKEFLAGS

RUN apt-get update -y && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:beineri/opt-qt-5.13.2-bionic && \
    apt-get update -y && \
    apt-get install -y qt513base openssl && \
    apt-get install -y git build-essential zlib1g-dev libbz2-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /src

RUN cd /src && \
    /opt/qt513/bin/qmake -makefile Fulcrum.pro && \
    make $MAKEFLAGS install

RUN rm -rf /src && \
    apt-get remove -y git build-essential zlib1g-dev libbz2-dev && \
    apt-get autoremove -y

ENV PATH=/opt/Fulcrum/bin:$PATH

VOLUME ["/data"]
ENV DATA_DIR /data

ENV SSL_CERTFILE ${DATA_DIR}/fulcrum.crt
ENV SSL_KEYFILE ${DATA_DIR}/fulcrum.key

EXPOSE 50001 50002

COPY contrib/docker/docker-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["Fulcrum"]
