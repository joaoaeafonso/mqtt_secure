#!/usr/bin/env bash
# Entrypoint of the lab image (docker/Dockerfile, target `lab`).
#
#   live | matrix | scenarios | attacks | campaign [args]   loadgen.py subcommands
#   agent sensors|attacker [args]                          join the controller $MSEC_CONTROLLER
#   analyze | microbench [args]                            tools/analysis/<name>.py
#   demo                                                   the narrated C++ gateway demo
#   anything else                                          run as is (bash, python, ...)
#
# It starts as root only to hand the mounted directories to the `lab` user
# (Docker creates missing host directories as root), then drops privileges for
# good. Mosquitto must not run as root: it would switch to the `mosquitto` user
# and could no longer read the lab's 0600 certificates, passwords and ACL.
set -euo pipefail

if [[ $(id -u) -eq 0 ]]; then
    for dir in /mnt/build /app/results ${MSEC_JOIN_DIR:-}; do
        mkdir -p "$dir"
        if [[ $(stat -c %u "$dir") -eq 0 ]]; then
            chown lab:lab "$dir"
        fi
    done
    export HOME=/home/lab USER=lab LOGNAME=lab
    exec setpriv --reuid=lab --regid=lab --init-groups -- "$0" "$@"
fi

cd /app
mkdir -p /mnt/build/loadtest /mnt/build/analysis
py=/opt/venv/bin/python
loadgen=tools/loadgen/loadgen.py

# Agents need the join token and the controller certificate's fingerprint.
# Publish exactly those two values, never the state directory: it holds the CA key.
publish_join() {
    [[ -n ${MSEC_JOIN_DIR:-} ]] || return 0
    "$py" - "$MSEC_JOIN_DIR" <<'EOF'
import os, sys
from pathlib import Path
sys.path.insert(0, "tools/loadgen")
from cluster import ControllerIdentity
from loadgen import DEFAULT_STATE

identity = ControllerIdentity(DEFAULT_STATE)  # creates the CA and token on first use
os.umask(0o077)
join = Path(sys.argv[1])
(join / "token").write_text(identity.token + "\n")
(join / "fingerprint").write_text(identity.fingerprint + "\n")
EOF
}

cmd=${1:-live}
[[ $# -gt 0 ]] && shift
case $cmd in
    live)
        # The dashboard must listen on the container's interface for the port
        # mapping; compose.yaml publishes it on the host's 127.0.0.1 only.
        publish_join
        exec "$py" "$loadgen" live --http-host 0.0.0.0 "$@" ;;
    matrix | scenarios | attacks | campaign)
        publish_join
        exec "$py" "$loadgen" "$cmd" "$@" ;;
    agent)
        role=${1:?usage: agent sensors|attacker [args]}
        shift
        join=${MSEC_JOIN_DIR:-/join}
        until [[ -s $join/token && -s $join/fingerprint ]]; do
            echo "waiting for the controller's join data in $join" >&2
            sleep 2
        done
        exec "$py" "$loadgen" agent --controller "${MSEC_CONTROLLER:-lab}" \
            --token "$(<"$join/token")" --fingerprint "$(<"$join/fingerprint")" \
            --role "$role" "$@" ;;
    analyze | microbench)
        exec "$py" "tools/analysis/$cmd.py" "$@" ;;
    demo)
        exec build/bench/apps/gateway/msec_gateway_demo "$@" ;;
    *)
        exec "$cmd" "$@" ;;
esac
