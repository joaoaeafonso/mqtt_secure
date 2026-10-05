#!/usr/bin/env bash
# Start the live load lab: builds what is missing, then opens the dashboard.
#
#   ./run.sh                              # 100 sensors, dashboard at http://127.0.0.1:8088/
#   ./run.sh --set load.sensors=500       # extra arguments go to `loadgen.py live`
#   ./run.sh --set payload.protection=encrypt --set transport.mode=tls
#
# Ctrl-C stops everything (broker, gateway, sensors, attacker).
set -euo pipefail

cd "$(dirname "$0")"

venv=tools/loadgen/.venv
gateway=build/bench/apps/load_gateway/msec_load_gateway

need() { command -v "$1" >/dev/null 2>&1 || PATH="$PATH:/usr/sbin" command -v "$1" >/dev/null 2>&1 \
    || { echo "missing '$1': $2" >&2; exit 1; }; }
need cmake     "install CMake >= 3.25"
need ninja     "install Ninja (ninja-build)"
need python3   "install Python >= 3.11"
need mosquitto "install Mosquitto (mosquitto, mosquitto-clients)"
need mosquitto_passwd "install Mosquitto (mosquitto)"

if [[ ! -f build/bench/CMakeCache.txt ]]; then
    echo "· configuring (bench preset)"
    cmake --preset bench
fi
echo "· building"
cmake --build --preset bench --target msec_load_gateway
[[ -x $gateway ]] || { echo "build did not produce $gateway" >&2; exit 1; }

if [[ ! -x $venv/bin/python ]]; then
    echo "· creating Python venv"
    python3 -m venv "$venv"
fi
if ! "$venv/bin/python" -c 'import paho.mqtt, cryptography' 2>/dev/null; then
    echo "· installing Python requirements"
    "$venv/bin/pip" install -q -r tools/loadgen/requirements.txt
fi

exec "$venv/bin/python" tools/loadgen/loadgen.py live \
    --config tools/loadgen/lab.example.toml \
    --set load.sensors=100 \
    --open \
    "$@"
