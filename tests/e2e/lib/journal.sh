#!/usr/bin/env bash
# Helpers that fake the Home Assistant OS host journal for tests.
#
# A real journald appends to one active file (system.journal). Writing each batch
# of entries to a *new* file looks like a rotation to Wazuh, which then discards
# anything older than the rotation, so the writer here is a long-running
# systemd-journal-remote that keeps one file open and appends to it.
#
#   journal_writer_start NAME VOLUME MACHINE_ID   start the writer; the journal lives in VOLUME
#   journal_emit NAME IDENT PRIORITY MESSAGE      append one entry
#   journal_writer_stop NAME
#
# VOLUME is mounted read-only at /var/log/journal in the app container, exactly as
# the Supervisor does for an app that sets "journald: true".

JOURNAL_WRITER_IMAGE="${JOURNAL_WRITER_IMAGE:-debian:trixie-slim}"

journal_writer_start() {
    local name="$1" volume="$2" mid="$3"
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker volume create "${volume}" > /dev/null
    docker run -d --name "${name}" -v "${volume}:/out" "${JOURNAL_WRITER_IMAGE}" sleep infinity > /dev/null
    docker exec "${name}" bash -c "
        set -e
        apt-get update -qq > /dev/null
        apt-get install -y -qq systemd-journal-remote > /dev/null 2>&1
        echo '${mid}' > /etc/machine-id
        mkdir -p '/out/${mid}'
        : > /tmp/feed.log
    "
    docker exec -d "${name}" bash -c "
        tail -f -n0 /tmp/feed.log \
            | /usr/lib/systemd/systemd-journal-remote -o '/out/${mid}/system.journal' - > /tmp/journal-remote.log 2>&1
    "
    # The journal file only exists once the first entry is written.
    journal_emit "${name}" "journal-writer" 6 "journal writer started" "${mid}"
    local _
    for _ in $(seq 1 30); do
        docker exec "${name}" test -s "/out/${mid}/system.journal" && return 0
        sleep 1
    done
    echo "journal writer ${name}: the journal file was never created" >&2
    return 1
}

journal_emit() {
    local name="$1" ident="$2" prio="$3" message="$4" mid="${5:-}"
    [[ -n "${mid}" ]] || mid="$(docker exec "${name}" cat /etc/machine-id)"
    docker exec -i "${name}" bash -c "cat >> /tmp/feed.log" << EOF
__REALTIME_TIMESTAMP=$(date +%s%6N)
_BOOT_ID=0123456789abcdef0123456789abcdef
_MACHINE_ID=${mid}
_HOSTNAME=homeassistant
PRIORITY=${prio}
SYSLOG_IDENTIFIER=${ident}
_TRANSPORT=${JOURNAL_TRANSPORT:-syslog}
_PID=222
MESSAGE=${message}

EOF
}

journal_writer_stop() {
    docker rm -f "$1" > /dev/null 2>&1 || true
}
