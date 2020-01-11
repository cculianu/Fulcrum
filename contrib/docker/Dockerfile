FROM ubuntu:bionic
LABEL maintainer="Axel Gembe <derago@gmail.com>"

RUN apt-get update -y && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:beineri/opt-qt-5.13.2-bionic && \
    apt-get update -y && \
    apt-get install -y qt513base openssl && \
    apt-get install -y git build-essential zlib1g-dev libbz2-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    mkdir Fulcrum && cd Fulcrum && git init && \
    git remote add origin https://github.com/cculianu/Fulcrum.git && \
    git fetch --depth 1 origin master && \
    git checkout -b pinned FETCH_HEAD && \
    /opt/qt513/bin/qmake -makefile Fulcrum.pro && \
    make install && \
    apt-get remove -y git build-essential zlib1g-dev libbz2-dev && \
    apt-get autoremove -y && \
    rm -rf Fulcrum

ENV PATH=/opt/Fulcrum/bin:$PATH

VOLUME ["/data"]
ENV DATA_DIR /data

ENV SSL_CERTFILE ${DATA_DIR}/fulcrum.crt
ENV SSL_KEYFILE ${DATA_DIR}/fulcrum.key

EXPOSE 50001 50002

COPY docker-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["Fulcrum"]
