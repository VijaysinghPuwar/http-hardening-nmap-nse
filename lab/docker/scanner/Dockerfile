FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts python3 \
 && python3 -m venv /opt/hhc

COPY reporter /tmp/reporter
RUN /opt/hhc/bin/pip install --no-cache-dir /tmp/reporter && rm -rf /tmp/reporter

COPY http-hardening-check.nse /opt/hhc/http-hardening-check.nse
COPY policies /opt/hhc/policies
COPY lab/docker/scanner/scan.sh /opt/hhc/scan.sh

ENV PATH="/opt/hhc/bin:${PATH}"
WORKDIR /out
ENTRYPOINT ["/bin/sh", "/opt/hhc/scan.sh"]
