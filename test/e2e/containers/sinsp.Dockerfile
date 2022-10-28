FROM debian:buster

ENV HOST_ROOT /host

RUN apt-get update && \
    apt-get install -y \
    libcurl4 \
    libgrpc++1 \
    jq \
    libjsoncpp1 \
    openssl \
    libb64-0d \
    libre2-5 \
    liblua5.1-0 \
    libtbb2

COPY /sinsp-example /usr/local/bin/sinsp-example
COPY /probe.o /driver/probe.o
COPY /scap.ko /driver/scap.ko

ENTRYPOINT [ "sinsp-example", "-j", "-a" ]
