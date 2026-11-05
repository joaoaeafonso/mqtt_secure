"""What a campaign records about where and how it ran (report §7: reproducible
artefact): the code (git commit, dirty or not, binary hash), the platform
(CPU model, memory, kernel, OS), the software (OpenSSL, Mosquitto, compiler,
Python), and per run the thermal state, since a Raspberry Pi throttles when hot.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def _run(*cmd: str, cwd: Path | None = None) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=cwd,
                             check=False)
        return (out.stdout or out.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip("\x00\n ")
    except OSError:
        return ""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return ""
    return h.hexdigest()


def cpu_model() -> str:
    model = _read("/proc/device-tree/model")  # Raspberry Pi: "Raspberry Pi 5 Model B Rev 1.0"
    cpuinfo = _read("/proc/cpuinfo")
    for key in ("model name", "Model", "Hardware"):
        m = re.search(rf"^{key}\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
        if m:
            return f"{model} / {m.group(1)}" if model and model not in m.group(1) else m.group(1)
    return model or platform.processor()


def mem_total_kb() -> int:
    m = re.search(r"MemTotal:\s+(\d+)", _read("/proc/meminfo"))
    return int(m.group(1)) if m else 0


def os_release() -> str:
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', _read("/etc/os-release"), re.MULTILINE)
    return m.group(1) if m else platform.platform()


def compiler(gateway_binary: Path) -> str:
    """From the CMake cache of the build the gateway came from."""
    for parent in gateway_binary.resolve().parents:
        cache = parent / "CMakeCache.txt"
        if cache.exists():
            text = cache.read_text(errors="replace")
            cxx = re.search(r"^CMAKE_CXX_COMPILER:\w+=(.+)$", text, re.MULTILINE)
            build = re.search(r"^CMAKE_BUILD_TYPE:\w+=(.*)$", text, re.MULTILINE)
            version = _run(cxx.group(1), "--version").splitlines()[:1] if cxx else []
            return f"{version[0] if version else '?'} ({build.group(1) if build else '?'})"
    return ""


def git_state(repo: Path) -> dict:
    status = _run("git", "status", "--porcelain", "--untracked-files=no", cwd=repo)
    return {"commit": _run("git", "rev-parse", "HEAD", cwd=repo),
            "dirty": bool(status), "describe": _run("git", "describe", "--always", "--dirty",
                                                    cwd=repo)}


def collect(repo: Path, gateway_binary: Path) -> dict:
    mosquitto = _run("mosquitto", "-h").splitlines()[:1]
    return {
        "git": git_state(repo),
        "gateway_binary": str(gateway_binary),
        "gateway_sha256": sha256(gateway_binary),
        "platform": {"cpu": cpu_model(), "cpus": os.cpu_count(), "mem_total_kb": mem_total_kb(),
                     "kernel": platform.release(), "machine": platform.machine(),
                     "os": os_release(), "hostname": platform.node(),
                     "governor": _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")},
        "software": {"openssl": _run("openssl", "version"),
                     "mosquitto": mosquitto[0] if mosquitto else "",
                     "compiler": compiler(gateway_binary),
                     "python": sys.version.split()[0]},
        "env": {k: os.environ[k] for k in ("OPENSSL_armcap", "OPENSSL_ia32cap")
                if k in os.environ},
    }


def thermal() -> dict:
    """Temperature (°C) and frequency (MHz) now; on a Pi also the throttling flags."""
    temp = _read("/sys/class/thermal/thermal_zone0/temp")
    freq = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
    out = {"temp_c": round(int(temp) / 1000, 1) if temp.isdigit() else "",
           "freq_mhz": round(int(freq) / 1000) if freq.isdigit() else ""}
    if shutil.which("vcgencmd"):
        out["throttled"] = _run("vcgencmd", "get_throttled").partition("=")[2]
    return out
