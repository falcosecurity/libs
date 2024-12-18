FROM debian:buster

ENV HOST_ROOT /host

RUN apt-get update && \
    apt-get install -y \
    jq \
    libjsoncpp1 \
    libre2-5 \
    libtbb2

COPY /sinsp-example /usr/local/bin/sinsp-example
COPY /probe.o /driver/probe.o
COPY /scap.ko /driver/scap.ko
COPY /libcontainer.so /plugins/libcontainer.so

ENTRYPOINT [ "sinsp-example", "-j", "-a", "-p", "/plugins/libcontainer.so" ]
