#!/usr/bin/env bash
# Starts the three agents of the Pi campaign on this (load) machine and keeps
# them up: two sensor agents and one attacker. They retry until the controller
# is reachable and rejoin by themselves between the campaign's steps.
#
#   tools/loadgen/start_agents.sh PI_IP TOKEN FINGERPRINT
#
# (tools/loadgen/pi_campaign.sh prints this exact line.) Ctrl+C stops all
# three. While they run, this machine is kept from suspending (systemd-inhibit),
# so it can be left alone for the evening. Logs: build/agents/<role>-<n>.log
set -uo pipefail

if [[ $# -ne 3 ]]; then
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
PI_IP=$1 TOKEN=$2 FINGERPRINT=$3

REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO" || exit 1
PY=tools/loadgen/.venv/bin/python
mkdir -p build/agents

run_agents() {
    local pids=() n=0 role
    trap 'kill "${pids[@]}" 2>/dev/null; wait; exit 0' INT TERM
    for role in sensors sensors attacker; do
        n=$((n + 1))
        "$PY" tools/loadgen/loadgen.py agent --controller "$PI_IP:8089" --token "$TOKEN" \
            --fingerprint "$FINGERPRINT" --role "$role" \
            >> "build/agents/$role-$n.log" 2>&1 &
        pids+=($!)
        echo "agent $n ($role): pid $!, log build/agents/$role-$n.log"
    done
    echo "$(git rev-parse --short HEAD): agents up; Ctrl+C stops them."
    wait
    echo "an agent exited: see build/agents/*.log"
}

if command -v systemd-inhibit > /dev/null; then
    export -f run_agents
    export PI_IP TOKEN FINGERPRINT PY
    exec systemd-inhibit --what=sleep:idle --who=mqtt-secure --why="campaign agents running" \
        bash -c run_agents
fi
run_agents
