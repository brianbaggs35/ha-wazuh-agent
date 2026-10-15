# Wazuh agent for Home Assistant.
#
# Debian (not Alpine) on purpose: Wazuh publishes its agent as a glibc .deb
# (amd64 and arm64) and does not support musl. The Home Assistant Debian base
# image brings s6-overlay and bashio, so the app plugs into the
# Supervisor like any other app.
#
# Pinned by digest (multi-arch index: linux/amd64 + linux/arm64). Dependabot
# keeps the digest current; do not replace it with a floating tag.
FROM ghcr.io/home-assistant/base-debian:trixie@sha256:a7f262f331e2a4f4e3e02173da932a8d8c26f3d5758a5f59903d46de1f728e5b

# The agent version. Wazuh requires the MANAGER to be the same version or
# newer than the agent, so check your manager before bumping this. The
# scheduled "Wazuh version watch" workflow opens a PR when a newer stable
# agent is published; the version is only ever set here.
ARG WAZUH_VERSION=4.14.9
ARG WAZUH_PKG_REVISION=1

# Fingerprint of the Wazuh package signing key (primary key of
# https://packages.wazuh.com/key/GPG-KEY-WAZUH). The build fails if the key
# served by packages.wazuh.com ever differs from this one.
ARG WAZUH_GPG_FINGERPRINT=0DCFCA5547B19D2A6099506096B3EE5F29111145

ARG BUILD_VERSION=dev
ARG BUILD_DATE=unknown
ARG BUILD_REVISION=unknown
ARG TARGETARCH

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN set -eux; \
    # Fixed IDs for the account the agent daemons drop to. The agent's state lives on the app's
    # persistent /data volume and survives image updates, so these numbers must not depend on
    # what the package installer happens to pick: a different ID after a rebuild would leave the
    # persisted files unreadable. (The package re-uses the account if it already exists.)
    groupadd --system --gid 1450 wazuh; \
    useradd --system --uid 1450 --gid wazuh --home-dir /var/ossec \
        --shell /sbin/nologin --no-create-home wazuh; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    # HTTPS only, even across redirects.
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.key; \
    fingerprint="$(gpg --show-keys --with-colons /tmp/wazuh.key | awk -F: '/^fpr:/ {print $10; exit}')"; \
    if [ "${fingerprint}" != "${WAZUH_GPG_FINGERPRINT}" ]; then \
        echo "Wazuh signing key fingerprint mismatch: got ${fingerprint}, expected ${WAZUH_GPG_FINGERPRINT}" >&2; \
        exit 1; \
    fi; \
    gpg --dearmor < /tmp/wazuh.key > /usr/share/keyrings/wazuh.gpg; \
    chmod 644 /usr/share/keyrings/wazuh.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_VERSION}-${WAZUH_PKG_REVISION}"; \
    apt-mark manual curl ca-certificates jq procps; \
    apt-get purge -y --auto-remove gnupg; \
    rm -rf /var/lib/apt/lists/* /tmp/wazuh.key /root/.gnupg; \
    # The agent was installed by the package at /var/ossec. Keep that pristine copy aside: at
    # start-up it is copied to /data/ossec (the app's persistent volume) and /var/ossec becomes a
    # symlink to it. A symlink rather than a bind mount because the daemons chroot() into
    # /var/ossec and an app container has no CAP_SYS_ADMIN to mount anything.
    mv /var/ossec /var/ossec.dist; \
    ln -s /data/ossec /var/ossec; \
    # The base image's tempio (a Go templating tool) is not used: the configuration is rendered
    # with jq. Removing it keeps the image to what the agent needs, and drops a binary that was
    # built with an older Go toolchain than the vulnerability scans accept.
    rm -f /usr/bin/tempio

COPY rootfs /

RUN chmod 0755 \
    /usr/local/bin/wazuh-ha-render \
    /usr/local/bin/wazuh-ha-healthcheck \
    /etc/s6-overlay/s6-rc.d/init-wazuh/run \
    /etc/s6-overlay/s6-rc.d/wazuh-agent/run \
    /etc/s6-overlay/s6-rc.d/wazuh-agent/finish

# s6: give the agent time to stop its daemons cleanly (they flush their
# databases on SIGTERM); the Supervisor's own stop timeout is set to match.
ENV S6_SERVICES_GRACETIME=25000

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/wazuh-ha-healthcheck"]

LABEL \
    io.hass.type="app" \
    io.hass.name="Wazuh Agent" \
    io.hass.description="Wazuh security agent for Home Assistant OS" \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.arch="${TARGETARCH}" \
    org.opencontainers.image.title="Wazuh Agent for Home Assistant" \
    org.opencontainers.image.description="Wazuh ${WAZUH_VERSION} agent packaged as a Home Assistant app" \
    org.opencontainers.image.source="https://github.com/brianbaggs35/ha-wazuh-agent" \
    org.opencontainers.image.licenses="MIT AND GPL-2.0-only" \
    org.opencontainers.image.version="${BUILD_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${BUILD_REVISION}" \
    com.wazuh.agent.version="${WAZUH_VERSION}"
