# Taken from https://github.com/fffaraz/docker-qt
# Example usage:
#   $ docker build --force-rm -t fulcrum-builder/qt:windows .
#   $ docker run --rm -it -v $(pwd):/work fulcrum-builder/qt:windows
FROM ubuntu:bionic
LABEL maintainer="Calin Culianu <calin.culianu@gmail.com>"
ENTRYPOINT ["/bin/bash"]

RUN \
apt -y update && \
apt -y upgrade && \
apt -y install build-essential iputils-ping nano \
    autoconf automake autopoint bash bison bzip2 flex gettext \
    git g++ gperf intltool libffi-dev libgdk-pixbuf2.0-dev \
    libtool-bin libltdl-dev libssl-dev libxml-parser-perl lzip make \
    openssl p7zip-full patch perl pkg-config python ruby scons \
    sed unzip wget xz-utils \
    g++-multilib libc6-dev-i386 && \
apt -y autoremove && \
apt -y autoclean && \
apt -y clean

RUN \
    cd /opt && \
    echo "💬  \033[1;36mCloning MXE repository ...\033[0m" && \
    git clone https://github.com/mxe/mxe.git && cd mxe && git checkout fc6f4f5fb134ed65b6a2ed87b40a24233bb742bd && cd .. && \
    echo "💬  \033[1;36mBuilding dependencies for static linking ...\033[0m" && \
    cd /opt/mxe && \
    echo 'override MXE_PLUGIN_DIRS += plugins/gcc11' >> settings.mk && \
    NPROC=$(($(nproc))) && \
    make --jobs=$NPROC JOBS=$NPROC MXE_TARGETS='x86_64-w64-mingw32.static' qtbase && \
    ln -s /opt/mxe/usr/bin/x86_64-w64-mingw32.static-qmake-qt5 /usr/bin/qmake

RUN \
    echo "💬  \033[1;36mInstalling LibZMQ ...\033[0m" && \
    cd /opt/mxe && \
    NPROC=$(($(nproc))) && \
    make --jobs=$NPROC JOBS=$NPROC MXE_TARGETS='x86_64-w64-mingw32.static' libzmq

# This bit taken from Electron Cash's Windows build Dockerfile -- requires
# Ubuntu bionic (which is 18.04 LTS). If we decide to upgrade the base Ubuntu
# tag at the top of this file, then this will just need slight modification.
RUN \
    apt -y update && \
    apt -y upgrade && \
    apt install -qy software-properties-common && \
    echo "💬  \033[1;36mInstalling Wine ...\033[0m" && \
    wget -nc https://dl.winehq.org/wine-builds/Release.key && \
        echo "c51bcb8cc4a12abfbd7c7660eaf90f49674d15e222c262f27e6c96429111b822 Release.key" | sha256sum -c - && \
        apt-key add Release.key && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 winehq.key" | sha256sum -c - && \
        apt-key add winehq.key && \
    rm -f winehq.key Release.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        wine-stable-amd64:amd64=4.0.3~bionic \
        wine-stable-i386:i386=4.0.3~bionic \
        wine-stable:amd64=4.0.3~bionic \
        winehq-stable:amd64=4.0.3~bionic

# Just print versions of everything at the end
RUN \
    echo "" && echo "👍  \033[1;32mGCC Version:\033[0m" && \
    /opt/mxe/usr/bin/x86_64-w64-mingw32.static-gcc --version && \
    echo "👍  \033[1;32mQt Version:\033[0m" && \
    qmake --version && \
    echo && echo "👍  \033[1;32mWine Version:\033[0m" && \
    wine --version && echo

ENV PATH="${PATH}:/opt/mxe/usr/bin"
