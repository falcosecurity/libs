
FROM runner-image AS runner

ENV HOST_ROOT /host
ENV HOME /root

# As a docker context you need to pass the `build` directory
COPY /libscap/examples/01-open/scap-open /usr/bin/scap-open
COPY /driver/bpf/probe.o /driver/probe.o
COPY /driver/scap.ko /driver/scap.ko

CMD ["/usr/bin/scap-open", "--modern_bpf"]
