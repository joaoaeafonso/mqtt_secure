"""Synthetic packet captures for the Wireshark tooling (no root, no live capture).

    TcpConnection   one TCP connection: handshake, data both ways, FIN
    Capture         collects frames from several connections, writes .pcap
    mqtt_*          minimal MQTT 3.1.1 packet encoders
    Recorder        a TCP relay that records the exact bytes of a real
                    connection (e.g. TLS to mosquitto) for replay into a capture

Used by tests/test_wireshark.py and by `python pcapgen.py sample OUT.pcap`,
which writes a capture of the lab's typical traffic (every protection mode,
an eavesdropper, a replay, a forgery, a malformed envelope) built from the
shared test vectors, handy for trying the dissector.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from pathlib import Path

LINKTYPE_ETHERNET = 1
SEGMENT = 1400  # split payloads like a real TCP stream, so reassembly gets exercised


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip(addr: str) -> bytes:
    return socket.inet_aton(addr)


class Capture:
    def __init__(self, start: float | None = None) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.clock = start if start is not None else time.time()

    def tick(self, dt: float = 0.001) -> float:
        self.clock += dt
        return self.clock

    def add(self, frame: bytes, at: float | None = None) -> None:
        self.frames.append((at if at is not None else self.tick(), frame))

    def write(self, path: Path) -> Path:
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))
            for t, frame in sorted(self.frames, key=lambda x: x[0]):
                secs = int(t)
                f.write(struct.pack("<IIII", secs, int((t - secs) * 1e9), len(frame), len(frame)))
                f.write(frame)
        return path


class TcpConnection:
    """Client (ip, port) <-> server (ip, port); emits valid TCP frames."""

    def __init__(self, cap: Capture, client: tuple[str, int], server: tuple[str, int]) -> None:
        self.cap, self.client, self.server = cap, client, server
        self.seq = {True: 1000, False: 5000}  # True = client side
        self.handshake()

    def _frame(self, from_client: bool, flags: int, data: bytes = b"") -> bytes:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        seq = self.seq[from_client]
        ack = 0 if flags == 0x02 else self.seq[not from_client]  # a SYN acknowledges nothing
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = _ip(src[0]) + _ip(dst[0]) + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
        tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp + data)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(data), 0, 0x4000, 64, 6, 0,
                         _ip(src[0]), _ip(dst[0]))
        ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
        eth = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"
        return eth + ip + tcp + data

    def handshake(self) -> None:
        self.cap.add(self._frame(True, 0x02))           # SYN
        self.seq[True] += 1
        self.cap.add(self._frame(False, 0x12))          # SYN-ACK
        self.seq[False] += 1
        self.cap.add(self._frame(True, 0x10))           # ACK

    def send(self, from_client: bool, data: bytes) -> None:
        for i in range(0, len(data), SEGMENT):
            chunk = data[i:i + SEGMENT]
            self.cap.add(self._frame(from_client, 0x18, chunk))  # PSH+ACK
            self.seq[from_client] += len(chunk)
        self.cap.add(self._frame(not from_client, 0x10))         # ACK

    def close(self) -> None:
        self.cap.add(self._frame(True, 0x11))
        self.seq[True] += 1
        self.cap.add(self._frame(False, 0x11))
        self.seq[False] += 1
        self.cap.add(self._frame(True, 0x10))


# --------------------------------------------------------------------- MQTT ---

def _remaining_length(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _string(s: str | bytes) -> bytes:
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def mqtt_connect(client_id: str, username: str | None = None, password: str | None = None) -> bytes:
    flags = 0x02 | (0x80 if username else 0) | (0x40 if password else 0)
    body = _string("MQTT") + bytes((4, flags)) + struct.pack("!H", 30) + _string(client_id)
    if username:
        body += _string(username)
    if password:
        body += _string(password)
    return b"\x10" + _remaining_length(len(body)) + body


def mqtt_connack(code: int = 0) -> bytes:
    return bytes((0x20, 2, 0, code))


def mqtt_subscribe(packet_id: int, topic: str, qos: int = 0) -> bytes:
    body = struct.pack("!H", packet_id) + _string(topic) + bytes((qos,))
    return b"\x82" + _remaining_length(len(body)) + body


def mqtt_suback(packet_id: int, code: int = 0) -> bytes:
    return b"\x90\x03" + struct.pack("!H", packet_id) + bytes((code,))


def mqtt_publish(topic: str, payload: bytes) -> bytes:
    body = _string(topic) + payload
    return b"\x30" + _remaining_length(len(body)) + body


# ------------------------------------------------------------------ recorder ---

class Recorder:
    """TCP relay on 127.0.0.1:<port> -> target; records (from_client, bytes) in order."""

    def __init__(self, target: tuple[str, int]) -> None:
        self.target = target
        self.chunks: list[tuple[bool, bytes]] = []
        self._lock = threading.Lock()
        self._server = socket.create_server(("127.0.0.1", 0))
        self.port = self._server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        client, _ = self._server.accept()
        upstream = socket.create_connection(self.target)
        threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True).start()
        self._pump(upstream, client, False)

    def _pump(self, src: socket.socket, dst: socket.socket, from_client: bool) -> None:
        try:
            while data := src.recv(65536):
                with self._lock:
                    self.chunks.append((from_client, data))
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def replay_into(self, conn: TcpConnection) -> None:
        with self._lock:
            chunks = list(self.chunks)
        for from_client, data in chunks:
            conn.send(from_client, data)

    def close(self) -> None:
        self._server.close()


# -------------------------------------------------------------------- sample ---

def sample(out: Path, vectors: Path, broker_port: int = 18830) -> Path:
    """Typical lab traffic in plain MQTT, built from the shared envelope vectors."""
    envs = {}
    for line in vectors.read_text().splitlines():
        f = line.split()
        if len(f) == 6 and not line.startswith("#"):
            envs[f[0]] = (f[3], bytes.fromhex(f[5]))
    cap = Capture(start=1_700_000_000.5)
    broker = ("127.0.0.1", broker_port)
    gateway = TcpConnection(cap, ("127.0.0.1", 41000), broker)
    gateway.send(True, mqtt_connect("gateway", "gateway"))
    gateway.send(False, mqtt_connack())
    gateway.send(True, mqtt_subscribe(1, "+/sensors/#"))
    gateway.send(False, mqtt_suback(1))
    mallory = TcpConnection(cap, ("127.0.0.1", 41001), broker)
    mallory.send(True, mqtt_connect("mallory-1", "mallory"))
    mallory.send(False, mqtt_connack())
    mallory.send(True, mqtt_subscribe(1, "#"))
    mallory.send(False, mqtt_suback(1))
    sensor = TcpConnection(cap, ("127.0.0.1", 41002), broker)
    sensor.send(True, mqtt_connect("sensor-7", "sensor-7"))
    sensor.send(False, mqtt_connack())
    for name in ("encrypt_short", "auth_only", "sign"):
        topic, env = envs[name]
        sensor.send(True, mqtt_publish(topic, env))              # sensor -> broker
        gateway.send(False, mqtt_publish(topic, env))            # broker -> gateway
        mallory.send(False, mqtt_publish(topic, env))            # broker -> eavesdropper
    topic, env = envs["encrypt_short"]
    mallory.send(True, mqtt_publish(topic, env))                 # replay
    forged = struct.pack("!Q", 1_700_000_000_500_000_000) + b"FORGED!!" + bytes(8)
    mallory.send(True, mqtt_publish("open/sensors/sensor-1/temp", forged))
    mallory.send(True, mqtt_publish("open/sensors/sensor-1/temp", b"MS\x02\x01short"))
    for c in (sensor, mallory, gateway):
        c.close()
    return cap.write(out)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "sample":
        sys.exit("usage: pcapgen.py sample OUT.pcap")
    repo = Path(__file__).resolve().parents[2]
    print(sample(Path(sys.argv[2]), repo / "tests" / "vectors" / "envelope_vectors.txt"))
