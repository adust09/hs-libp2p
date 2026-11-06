FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

RUN apk add --no-cache \
    iproute2 \
    iptables

COPY interop/hole-punch/router/run.sh /usr/local/bin/run-hole-punch-router
RUN chmod +x /usr/local/bin/run-hole-punch-router

ENTRYPOINT ["/usr/local/bin/run-hole-punch-router"]
