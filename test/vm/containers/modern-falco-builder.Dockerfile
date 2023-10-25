FROM centos:7

RUN yum -y install centos-release-scl; \
    yum -y install devtoolset-9-gcc \
    devtoolset-9-gcc-c++; \
    source scl_source enable devtoolset-9; \
    yum -y install git \
    wget \
    make \
    m4 \
    rpm-build \
    which \
    libcurl-devel \
    perl-IPC-Cmd

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.27.6/cmake-3.27.6-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.27.6-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.27.6-linux-$(uname -m)/

RUN source scl_source enable devtoolset-9;
RUN cp -f /opt/rh/devtoolset-9/root/usr/bin/gcc /usr/bin/gcc; cp -f /opt/rh/devtoolset-9/root/usr/bin/g++ /usr/bin/g++;

ENTRYPOINT ["/bin/bash", "-c"]