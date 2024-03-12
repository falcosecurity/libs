FROM busybox
RUN cp /bin/true /bin/ut-health-check
HEALTHCHECK --interval=0.5s CMD ["/bin/ut-health-check"]
