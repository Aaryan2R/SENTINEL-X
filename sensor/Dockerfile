# SENTINEL-X Sensor Image
# Zeek metadata extraction — runs with NO network (INV-5, ADR-012)
#
# Build: docker build -t sentinel-sensor ./sensor
# Runtime: network_mode: none, read_only: true, cap_add: [NET_RAW, NET_ADMIN]

# ── Stage 1: Install Zeek and packages (with network) ──
FROM zeek/zeek:9.0.0 AS builder

# Install zkg packages at build time (INV-4: no network at runtime)
# The runtime sensor has no network, so all packages must be baked in
COPY zeek/packages.txt /tmp/packages.txt
RUN zkg autoconfig && \
    while IFS= read -r pkg || [ -n "$pkg" ]; do \
        [ -z "$pkg" ] || [ "${pkg#\#}" != "$pkg" ] && continue; \
        zkg install --force "$pkg"; \
    done < /tmp/packages.txt

# ── Stage 2: Runtime sensor (minimal, no network) ──
FROM zeek/zeek:9.0.0

# Copy installed packages from builder
COPY --from=builder /usr/local/zeek/lib/zeek/plugins/ /usr/local/zeek/lib/zeek/plugins/
COPY --from=builder /usr/local/zeek/share/zeek/site/packages/ /usr/local/zeek/share/zeek/site/packages/

# Copy custom Zeek configuration
COPY zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek

# Create log directory
RUN mkdir -p /var/log/zeek && \
    chown zeek:zeek /var/log/zeek

# Drop to non-root user (SEC-5)
USER zeek

# Zeek writes logs to this volume
VOLUME ["/var/log/zeek"]

# Default: run Zeek on the capture interface
# The interface is attached by the setup script after container starts
ENTRYPOINT ["zeek"]
CMD ["-i", "eth0", "local.zeek"]
