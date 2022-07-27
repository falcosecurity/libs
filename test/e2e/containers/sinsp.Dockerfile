FROM debian:buster

RUN apt-get update && \
    apt-get install -y \
    libcurl4 \
    libgrpc++1 \
    jq \
    libjsoncpp1 \
    openssl \
    libb64-0d \
    libtbb2

COPY /libsinsp/examples/sinsp-example /usr/local/bin/sinsp-example
COPY /driver/bpf/probe.o /driver/probe.o
COPY /driver/scap.ko /driver/scap.ko

ENTRYPOINT [ "sinsp-example", "-j", "-a" ]
