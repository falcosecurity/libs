FROM centos:7

# fix broken mirrors
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo; \
    sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo; \
    sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

RUN yum -y install centos-release-scl

# fix broken mirrors (again)
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo; \
    sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo; \
    sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

RUN [ $(uname -m) == 'aarch64' ] && sed -i 's/vault.centos.org\/centos/vault.centos.org\/altarch/g' /etc/yum.repos.d/CentOS-SCLo-scl*.repo

RUN yum -y install devtoolset-9-gcc \
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