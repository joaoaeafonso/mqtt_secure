#!/usr/bin/env bash
# The whole Pi evaluation of docs/raspberry-pi.md §6–§8, unattended:
#
#   7a  cost campaign + saturation sweep          (≈ 2.5 h)
#   7b  attack matrix × 3, merged into attacks.csv (≈ 1.2 h)
#   6   microbenchmarks                           (≈ 15–20 min, no agents)
#   7c  scenarios with agents
#   8   analysis
#
# Usage (on the Pi, from anywhere, ideally inside tmux):
#   tools/loadgen/pi_campaign.sh NAME PI_IP            run it
#   tools/loadgen/pi_campaign.sh NAME PI_IP --check    preflight + agent command only
#
# Start the agents on the load machine BEFORE or AFTER (tools/loadgen/start_agents.sh
# with the line this prints): they retry until the controller is up and rejoin
# by themselves between steps, so nothing here needs a human.
#
# Preflight refuses to start on: a dirty tree, an existing results/NAME, a
# governor other than performance, NTP on, Docker running. SKIP_PREFLIGHT=1
# skips it (tests only). For a quick dry run of the chain, override:
#   CAMPAIGN_ARGS  (default: the report's campaign)  ATTACK_REPS (3)
#   MICROBENCH_ARGS (--repetitions 10)               SKIP_MICROBENCH=1
#   ATTACK_ARGS, SCENARIO_ARGS (extra options, e.g. --levels K0,K9 / --only ...)
set -uo pipefail

if [[ $# -lt 2 ]]; then
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
NAME=$1
PI_IP=$2
CHECK_ONLY=${3:-}

REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO" || exit 1
PY=tools/loadgen/.venv/bin/python
OUT=results/$NAME
LOG=build/campaign-$NAME.log
AGENTS=(--set broker.host=0.0.0.0 --set "broker.advertise=$PI_IP"
        --set cluster.sensor_agents=2 --set cluster.attacker_agents=1)
DEFAULT_CAMPAIGN="--repetitions 10 --seed 20261201 --settle 3 --duration 30 --connect-test 5
  --saturate 10,20,50,100,125,150,200,300,400,500,600,700,800,1000,1200,1600"
read -r -a CAMPAIGN <<< "${CAMPAIGN_ARGS:-$DEFAULT_CAMPAIGN}"
read -r -a MICROBENCH <<< "${MICROBENCH_ARGS:---repetitions 10}"
ATTACK_REPS=${ATTACK_REPS:-3}
read -r -a ATTACK_EXTRA <<< "${ATTACK_ARGS:-}"
read -r -a SCENARIO_EXTRA <<< "${SCENARIO_ARGS:-}"

# ------------------------------------------------------------- preflight ---
problems=()
if [[ ${SKIP_PREFLIGHT:-0} != 1 ]]; then
    [[ -z $(git status --porcelain --untracked-files=no) ]] \
        || problems+=("the working tree has uncommitted changes (the manifest would say dirty)")
    [[ -e $OUT ]] && problems+=("$OUT already exists (raw data is never overwritten: pick a new NAME)")
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [[ $(cat "$g") == performance ]] || {
            problems+=("governor is not performance: echo performance | sudo tee $g ...")
            break; }
    done
    [[ $(timedatectl show -p NTP --value 2>/dev/null) == no ]] \
        || problems+=("NTP is on: sync first, then 'sudo timedatectl set-ntp false' (here AND on the desktop)")
    systemctl is-active --quiet docker 2>/dev/null \
        && problems+=("Docker is running: sudo systemctl stop docker.socket docker")
    [[ -x $PY ]] || problems+=("no venv at $PY")
    [[ -x build/bench/apps/load_gateway/msec_load_gateway || -d build/bench ]] \
        || problems+=("no bench build: cmake --preset bench && cmake --build --preset bench")
fi
throttled=$(vcgencmd get_throttled 2>/dev/null || echo "throttled=?")

echo "commit:    $(git rev-parse --short HEAD) ($(git log -1 --format=%s))"
echo "campaign:  $OUT     log: $LOG"
echo "pi:        $PI_IP   $throttled"
echo
echo "Agents (on the load machine, from the repository root; once, before or after this):"
"$PY" - "$PI_IP" <<'EOF'
import sys
from pathlib import Path
sys.path.insert(0, "tools/loadgen")
from cluster import ControllerIdentity
from loadgen import DEFAULT_STATE
identity = ControllerIdentity(DEFAULT_STATE)
print(f"  tools/loadgen/start_agents.sh {sys.argv[1]} {identity.token} {identity.fingerprint}")
EOF
echo
if ((${#problems[@]})); then
    echo "Not starting:"
    printf '  - %s\n' "${problems[@]}"
    exit 1
fi
[[ $CHECK_ONLY == --check ]] && { echo "Preflight OK (--check: not starting)."; exit 0; }

# ------------------------------------------------------------------ steps ---
mkdir -p build
exec > >(tee -a "$LOG") 2>&1
failed=()
step() {  # step NAME COMMAND...: runs, times and records it; never aborts the chain
    local name=$1; shift
    echo; echo "=== $(date '+%F %T') $name"
    local t0=$SECONDS
    if "$@"; then
        echo "=== $name: OK ($(( (SECONDS - t0) / 60 )) min)"
    else
        echo "=== $name: FAILED (exit $?, $(( (SECONDS - t0) / 60 )) min)"
        failed+=("$name")
        return 1
    fi
}
merge_attacks() {
    "$PY" - "$OUT" <<'EOF'
import csv, glob, sys
rows = []
for rep, path in enumerate(sorted(glob.glob(f"{sys.argv[1]}/attacks-*.csv")), 1):
    rows += [{"repetition": rep, **r} for r in csv.DictReader(open(path, newline=""))]
if not rows:
    sys.exit("no attack rows to merge")
with open(f"{sys.argv[1]}/attacks.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)), restval="")
    w.writeheader(); w.writerows(rows)
print(len(rows), "rows")
EOF
}

echo "=== $(date '+%F %T') start: $NAME at $(git rev-parse HEAD)"
if ! step "7a cost campaign + saturation" \
        "$PY" tools/loadgen/loadgen.py campaign "${AGENTS[@]}" "${CAMPAIGN[@]}" --out "$OUT"; then
    # Without the cost runs the rest has nothing to attach to: stop here.
    [[ -d $OUT ]] || { echo "no campaign directory: stopping"; exit 1; }
fi
for ((i = 1; i <= ATTACK_REPS; i++)); do
    step "7b attacks $i/$ATTACK_REPS" \
        "$PY" tools/loadgen/loadgen.py attacks "${AGENTS[@]}" "${ATTACK_EXTRA[@]}" --out "$OUT/attacks-$i.csv"
done
step "7b merge attacks" merge_attacks
if [[ ${SKIP_MICROBENCH:-0} != 1 ]]; then
    step "6 microbenchmarks" "$PY" tools/analysis/microbench.py --out "$OUT/microbench" "${MICROBENCH[@]}"
fi
step "7c scenarios" "$PY" tools/loadgen/loadgen.py scenarios "${AGENTS[@]}" "${SCENARIO_EXTRA[@]}" --out "$OUT/scenarios"
step "8 analysis" "$PY" tools/analysis/analyze.py "$OUT"

echo
echo "=== $(date '+%F %T') done: $OUT"
if ((${#failed[@]})); then
    echo "FAILED steps:"; printf '  - %s\n' "${failed[@]}"
fi
echo "Next: the §8 checklist (build/analysis/$NAME/), copy $OUT off the Pi, NTP and Docker back on."
((${#failed[@]} == 0))
