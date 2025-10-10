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
    apt -qy install build-essential cmake gdb git iputils-ping nano perl python valgrind wget autoconf && \
    apt -qy install libbz2-dev zlib1g-dev libssl-dev libnss3-dev libxslt-dev libxml2-dev  && \
    apt -qy autoremove && \
    apt -qy autoclean

RUN \
    apt -qy install software-properties-common && \
    add-apt-repository -y ppa:ubuntu-toolchain-r/test && \
    apt -qy update && \
    apt -qy install gcc-13 g++-13 cpp-13 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 131 \
                        --slave /usr/bin/g++ g++ /usr/bin/g++-13 \
                        --slave /usr/bin/gcov gcov /usr/bin/gcov-13 && \
    apt -qy autoremove && \
    apt -qy autoclean

# Ensure we statically link libstdc++ otherwise produced binaries won't be compatible with stock systems
ENV LDFLAGS="-static-libstdc++"

RUN \
    mkdir -p /opt/local/qt && \
    cd /opt && \
    echo "💬  \033[1;36mDownloading Qt sources ...\033[0m" && \
    wget -q https://download.qt.io/archive/qt/5.15/5.15.17/single/qt-everywhere-opensource-src-5.15.17.tar.xz && \
    echo "💬  \033[1;36mExtracting archive ...\033[0m" && \
    tar -xf qt-everywhere-opensource-src-5.15.17.tar.xz && \
    rm qt-everywhere-opensource-src-5.15.17.tar.xz && \
    cd qt-everywhere-src-5.15.17 && \
    echo "💬  \033[1;36mConfiguring Qt ...\033[0m" && \
    ./configure -opensource -confirm-license -release -static -nomake tests -nomake examples -no-compile-examples \
        -prefix /opt/local/qt -no-gui -no-sse2 -no-sse3 -no-ssse3 -no-sse4.1 -no-sse4.2 -no-avx -no-avx2 -no-avx512 \
        -openssl-linked -no-shared -c++std c++17 -no-widgets -no-dbus -no-cups -no-freetype -no-fontconfig -no-gif \
        -no-ico -no-libpng -no-libjpeg -strip -no-opengl -no-sqlite -no-glib -no-iconv -no-harfbuzz -no-sql-sqlite \
        -no-sql-mysql -qpa 'linuxfb' -no-feature-accessibility -nomake tools -no-linuxfb -no-xcb -no-feature-sqlmodel \
        -no-feature-itemmodeltester -no-feature-sessionmanager -no-feature-vnc -no-icu -skip qtconnectivity -qt-pcre \
        -qt-zlib -no-tiff -no-webp  -no-libinput -skip qtwebengine -skip qt3d -skip qtlocation -skip qtquick3d \
        -no-feature-action -no-feature-animation  -no-feature-big_codecs   -no-feature-clipboard -no-feature-codecs \
        -no-feature-cups -no-feature-cursor  -no-feature-desktopservices -no-feature-draganddrop \
        -no-feature-jalalicalendar -no-feature-movie -no-feature-pdf -no-feature-picture -no-feature-valgrind \
        -skip multimedia -skip serialbus -skip tools -skip gamepad -skip serialport -skip sensors -skip quickcontrols2 \
        -skip speech && \
    echo "" && echo "💬  \033[1;36mCompiling Qt ...\033[0m" && \
    make -j $(nproc) && \
    echo "" && echo "💬  \033[1;36mInstalling Qt ...\033[0m" && \
    make install && \
    cd /opt && \
    echo "" && echo "💬  \033[1;36mCleaning up ...\033[0m" && \
    rm -rf qt-everywhere-src-5.15.17 && \
    echo "" && echo "👍  \033[1;32mGCC Version:\033[0m" && \
    gcc --version && \
    echo "👍  \033[1;32mQt Version:\033[0m" && \
    /opt/local/qt/bin/qmake --version

ENV PATH="${PATH}:/opt/local/qt/bin"
ENV FORCE_STATIC_SSL=1
