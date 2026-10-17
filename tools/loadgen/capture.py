"""Packet capture of a lab run, ready for Wireshark (`loadgen.py ... --capture`).

    dumpcap  records the broker port (and the agent control port) to .pcapng
    keylog   every TLS endpoint logs its secrets to <capture>.keys (keylog.py)
    finish   editcap embeds those secrets in the pcapng (a Decryption Secrets
             Block), so the file opens already decrypted on any machine, and
             adds a packet comment at the first frame after every lab event
             ("transport.mode: plain → tls", "scenario replay-window", ...)

Open the result with the dissector (tools/wireshark/msec.lua) installed and
filter on `frame.comment` to jump from one configuration change to the next.

Capturing needs permission: on Debian/Ubuntu, `sudo dpkg-reconfigure
wireshark-common` (allow non-root) and `sudo usermod -aG wireshark $USER`,
then log in again.
"""

from __future__ import annotations

import bisect
import shutil
import struct
import subprocess
import threading
import time
from pathlib import Path

import keylog

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def find_tool(name: str) -> str | None:
    return shutil.which(name) or (f"/usr/bin/{name}" if Path(f"/usr/bin/{name}").exists() else None)


def frame_times(path: Path) -> list[float]:
    """Timestamps (Unix seconds) of every packet in a pcapng file, in order.

    Minimal reader: Enhanced/Simple Packet Blocks, per-interface if_tsresol."""
    times: list[float] = []
    resolution: list[float] = []
    data = path.read_bytes()
    pos, endian = 0, "<"
    while pos + 12 <= len(data):
        block_type, length = struct.unpack_from(endian + "II", data, pos)
        if block_type == 0x0A0D0D0A:  # section header: byte order magic decides endianness
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            block_type, length = struct.unpack_from(endian + "II", data, pos)
            resolution = []
        elif block_type == 1:  # interface description: look for if_tsresol (option 9)
            res, opt = 1e-6, pos + 16
            while opt + 4 <= pos + length - 4:
                code, size = struct.unpack_from(endian + "HH", data, opt)
                if code == 0:
                    break
                if code == 9:
                    v = data[opt + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opt += 4 + (size + 3) // 4 * 4
            resolution.append(res)
        elif block_type == 6:  # enhanced packet
            iface, high, low = struct.unpack_from(endian + "III", data, pos + 8)
            res = resolution[iface] if iface < len(resolution) else 1e-6
            times.append(((high << 32) | low) * res)
        elif block_type == 3:  # simple packet: no timestamp
            times.append(times[-1] if times else 0.0)
        if length < 12:
            break
        pos += length
    return times


class Capture:
    def __init__(self, path: Path, interface: str, ports: list[int], log=print,
                 keys: Path | None = None) -> None:
        self.path = path.resolve()
        self.interface = interface
        self.ports = ports
        self.log = log
        self.keys = keylog.activate(keys or self.path.with_suffix(".keys"))
        self.events: list[tuple[float, str]] = []
        self._lock = threading.Lock()
        self.proc: subprocess.Popen | None = None

    @staticmethod
    def interface_for(config: dict) -> str:
        """Loopback when everything runs here, otherwise every interface."""
        remote = config["cluster"]["sensor_agents"] or config["cluster"]["attacker_agents"]
        return "lo" if config["broker"]["host"] in LOOPBACK and not remote else "any"

    def start(self) -> None:
        dumpcap = find_tool("dumpcap")
        if dumpcap is None:
            raise RuntimeError("--capture needs dumpcap (apt install wireshark-common or tshark)")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        bpf = " or ".join(f"tcp port {p}" for p in self.ports)
        self.proc = subprocess.Popen([dumpcap, "-i", self.interface, "-f", bpf, "-w", str(self.path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        output = []
        while time.monotonic() < deadline:
            line = self.proc.stderr.readline()
            if not line:
                break
            output.append(line)
            if line.startswith("File:"):
                threading.Thread(target=self._drain, daemon=True).start()
                self.log(f"capturing {bpf} on {self.interface} → {self.path}")
                return
        self.proc.kill()
        raise RuntimeError("dumpcap could not start capturing:\n" + "".join(output) +
                           "\nAllow non-root capture: sudo dpkg-reconfigure wireshark-common; "
                           "sudo usermod -aG wireshark $USER; then log in again")

    def _drain(self) -> None:
        for _ in self.proc.stderr:
            pass

    def mark(self, text: str) -> None:
        with self._lock:
            self.events.append((time.time(), text))

    def stop(self) -> None:
        if self.proc is None:
            return
        time.sleep(0.5)  # let the last packets reach the file
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None
        self._finish()

    def _finish(self) -> None:
        events_file = self.path.with_suffix(".events.tsv")
        with self._lock:
            events = list(self.events)
        events_file.write_text("".join(f"{t:.6f}\t{text}\n" for t, text in events),
                               encoding="utf-8")
        editcap = find_tool("editcap")
        if editcap is None or not self.path.exists():
            self.log(f"capture: {self.path} (editcap not found: secrets and comments not embedded;"
                     f" TLS secrets are in {self.keys})")
            return
        args = [editcap]
        if self.keys.exists() and self.keys.stat().st_size:
            args += ["--inject-secrets", f"tls,{self.keys}"]
        times = frame_times(self.path)
        comments: dict[int, list[str]] = {}
        for t, text in events:
            index = bisect.bisect_left(times, t)  # dumpcap writes packets in time order
            if index < len(times):
                comments.setdefault(index + 1, []).append(text)
        for frame, texts in sorted(comments.items()):
            args += ["-a", f"{frame}:lab: {' | '.join(texts)}"]
        if len(args) == 1:
            return
        tmp = self.path.with_suffix(".tmp.pcapng")
        result = subprocess.run([*args, str(self.path), str(tmp)], capture_output=True, text=True)
        if result.returncode != 0:
            self.log(f"capture: editcap failed ({result.stderr.strip()}); raw capture kept")
            tmp.unlink(missing_ok=True)
            return
        tmp.replace(self.path)
        self.log(f"capture: {self.path} ({len(times)} packets, {len(comments)} event comments, "
                 f"TLS secrets embedded); events in {events_file}")
