FROM alpine:3.21

LABEL org.opencontainers.image.title="php2shell-guard" \
      org.opencontainers.image.description="Read-only runtime, SAPI, stale-worker, config, and IaC auditor for PHP2Shell & Node2Shell" \
      org.opencontainers.image.source="https://github.com/malikad778/php2shell-guard" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache nodejs bash

WORKDIR /opt/php2shell-guard
COPY . /opt/php2shell-guard
RUN chmod +x /opt/php2shell-guard/bin/audit.sh /opt/php2shell-guard/bin/php2shell-guard.mjs /opt/php2shell-guard/bin/php2shell-guard

ENTRYPOINT ["/opt/php2shell-guard/bin/audit.sh"]
CMD ["scan"]
