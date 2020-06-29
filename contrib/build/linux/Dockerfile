# Taken from https://github.com/fffaraz/docker-qt
# Example usage:
#   $ docker build --force-rm -t fulcrum-builder/qt:linux .
#   $ docker run --rm -it -v $(pwd):/work fulcrum-builder/qt:linux
FROM ubuntu:bionic
LABEL maintainer="Calin Culianu <calin.culianu@gmail.com>"
ENTRYPOINT ["/bin/bash"]

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    apt -qy update && \
    apt -qy upgrade && \
    apt -qy install build-essential cmake gdb git iputils-ping nano perl python valgrind wget && \
    apt -qy install libbz2-dev zlib1g-dev libssl-dev libnss3-dev libxslt-dev libxml2-dev  && \
    apt -qy autoremove && \
    apt -qy autoclean

RUN \
    mkdir -p /opt && \
    cd /opt && \
    echo "💬  \033[1;36mDownloading Qt sources ...\033[0m" && \
    wget -q http://download.qt.io/official_releases/qt/5.14/5.14.2/single/qt-everywhere-src-5.14.2.tar.xz && \
    echo "💬  \033[1;36mExtracting archive ...\033[0m" && \
    tar xf qt-everywhere-src-5.14.2.tar.xz && \
    rm qt-everywhere-src-5.14.2.tar.xz && \
    cd qt-everywhere-src-5.14.2 && \
    echo "💬  \033[1;36mConfiguring Qt ...\033[0m" && \
    ./configure -opensource -confirm-license -release -static -nomake tests -nomake examples -no-compile-examples \
        -prefix /opt/local/qt -no-gui -no-sse2 -ssl -no-shared -c++std c++17 -no-widgets -no-dbus -no-cups -no-freetype -no-fontconfig -no-gif \
        -no-ico -no-libpng -no-libjpeg -strip -no-opengl -no-sqlite -no-glib -no-iconv -optimize-size -no-harfbuzz -no-sql-sqlite -no-sql-mysql \
        -qpa 'linuxfb' -no-accessibility -nomake tools -no-linuxfb -no-xcb -no-feature-sqlmodel -no-feature-itemmodeltester \
        -no-feature-sessionmanager -no-feature-vnc -no-icu \
        -qt-pcre -qt-zlib -no-tiff -no-webp -no-gstreamer -no-libinput && \
    echo "" && echo "💬  \033[1;36mCompiling Qt ...\033[0m" && \
    make -j $(nproc) && \
    echo "" && echo "💬  \033[1;36mInstalling Qt ...\033[0m" && \
    make install && \
    cd /opt && \
    echo "" && echo "💬  \033[1;36mCleaning up ...\033[0m" && \
    rm -rf qt-everywhere-src-5.14.2 && \
    echo "" && echo "👍  \033[1;32mGCC Version:\033[0m" && \
    gcc --version && \
    echo "👍  \033[1;32mQt Version:\033[0m" && \
    /opt/local/qt/bin/qmake --version

ENV PATH="${PATH}:/opt/local/qt/bin"
