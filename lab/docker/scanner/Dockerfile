FROM alpine:3.20

# The base image tag is pinned; apk versions are not, because Alpine drops old
# package versions from its index and that would break the lab build.
# hadolint ignore=DL3018
RUN apk add --no-cache nmap nmap-scripts python3 \
 && python3 -m venv /opt/hhc

COPY reporter /tmp/reporter
RUN /opt/hhc/bin/pip install --no-cache-dir /tmp/reporter && rm -rf /tmp/reporter

COPY http-hardening-check.nse /opt/hhc/http-hardening-check.nse
COPY policies /opt/hhc/policies
COPY lab/docker/scanner/scan.sh /opt/hhc/scan.sh

ENV PATH="/opt/hhc/bin:${PATH}"
WORKDIR /out
# Never root by default. docker-compose.yml overrides this with the invoking
# user's ids so the reports in ./out are owned by them; a connect scan (-sT)
# needs no privileges either way.
USER 1000:1000
ENTRYPOINT ["/bin/sh", "/opt/hhc/scan.sh"]
