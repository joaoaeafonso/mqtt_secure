"""An attacker on the gateway's link: a TCP relay between the gateway and the
broker (`attacker.wiretap`, startup only).

Passive, it is a network eavesdropper: it counts the PUBLISH packets it can
parse and how many carry a readable reading (a plaintext send time at offset
0). Under TLS it sees only ciphertext and parses nothing, which is the point.

Active (`attacker.tamper`), it plays a malicious broker towards the gateway:
on every second PUBLISH from the broker it

    alter      flips the last payload byte
    redirect   moves the message to another topic of the same device
               (".../temp" → ".../humidity"), rewriting the packet
    delay      holds it back for `tamper_delay_s` seconds (the rest keeps flowing)
    drop       discards it (suppression: nothing at the receiver can tell)

Only possible on plaintext MQTT: with TLS the relay cannot read or rewrite
packets, so it only counts bytes. A real malicious broker terminates TLS
itself; the relay stands in for it on plain transport.

It also counts the TCP bytes in each direction, so wire bytes per message
can be compared with what the payload, the envelope and MQTT account for.
"""

from __future__ import annotations

import heapq
import itertools
import socket
import threading
import time

TAMPER_MODES = ("none", "alter", "redirect", "delay", "drop")
READABLE_WINDOW_NS = 300 * 1_000_000_000
PUBLISH = 3


def read_varint(data: bytes, pos: int) -> tuple[int, int] | None:
    value, shift = 0, 0
    for i in range(4):
        if pos + i >= len(data):
            return None
        b = data[pos + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos + i + 1
        shift += 7
    raise ValueError("malformed variable byte integer")


def write_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def split_packets(buffer: bytearray) -> list[bytes]:
    """Removes and returns every complete MQTT packet at the front of `buffer`."""
    out = []
    while len(buffer) >= 2:
        parsed = read_varint(buffer, 1)
        if parsed is None:
            break
        length, start = parsed
        if len(buffer) < start + length:
            break
        out.append(bytes(buffer[:start + length]))
        del buffer[:start + length]
    return out


def parse_publish(packet: bytes, v5: bool) -> tuple[str, int, bytes, bytes] | None:
    """(topic, payload offset, bytes between topic and payload, payload) of a PUBLISH."""
    if packet[0] >> 4 != PUBLISH:
        return None
    _, pos = read_varint(packet, 1)
    qos = (packet[0] >> 1) & 3
    tlen = int.from_bytes(packet[pos:pos + 2], "big")
    topic = packet[pos + 2:pos + 2 + tlen].decode("utf-8", "replace")
    middle_start = pos + 2 + tlen
    p = middle_start + (2 if qos else 0)
    if v5:
        plen, p = read_varint(packet, p)
        p += plen
    return topic, p, packet[middle_start:p], packet[p:]


class _Sender:
    """Whole packets to one socket, now or later; delayed packets are sent by
    a scheduler thread, so they do not hold up the packets behind them."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.lock = threading.Lock()
        self.cv = threading.Condition()
        self.heap: list = []
        self.seq = itertools.count()
        self.closed = False
        threading.Thread(target=self._run, daemon=True).start()

    def send(self, packet: bytes) -> None:
        with self.lock:
            self.sock.sendall(packet)

    def later(self, packet: bytes, delay: float) -> None:
        with self.cv:
            heapq.heappush(self.heap, (time.monotonic() + delay, next(self.seq), packet))
            self.cv.notify()

    def close(self) -> None:
        with self.cv:
            self.closed = True
            self.cv.notify()

    def _run(self) -> None:
        while True:
            with self.cv:
                while not self.closed and (not self.heap or self.heap[0][0] > time.monotonic()):
                    self.cv.wait(None if not self.heap else self.heap[0][0] - time.monotonic())
                if self.closed:
                    return
                _, _, packet = heapq.heappop(self.heap)
            try:
                self.send(packet)
            except OSError:
                return


def build_publish(first: int, topic: str, middle: bytes, payload: bytes) -> bytes:
    t = topic.encode()
    body = len(t).to_bytes(2, "big") + t + middle + payload
    return bytes((first,)) + write_varint(len(body)) + body


class Relay:
    def __init__(self, target_host: str, target_port: int, listen_host: str = "127.0.0.1",
                 log=print) -> None:
        self.target = (target_host, target_port)
        self.log = log
        self.tamper = "none"
        self.delay_s = 2.0
        self.lock = threading.Lock()
        self.counters = {"publishes": 0, "readable": 0, "opaque_bytes": 0, "tampered": 0,
                         "to_client_bytes": 0, "to_broker_bytes": 0, "connections": 0}
        self._stop = threading.Event()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((listen_host, 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def configure(self, tamper: str, delay_s: float) -> None:
        if tamper not in TAMPER_MODES:
            raise ValueError(f"tamper must be one of {', '.join(TAMPER_MODES)}")
        self.tamper, self.delay_s = tamper, delay_s

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.counters)

    def _count(self, **inc) -> None:
        with self.lock:
            for k, v in inc.items():
                self.counters[k] += v

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(self.target, timeout=5)
                upstream.settimeout(None)
            except OSError as e:
                self.log(f"relay: cannot reach broker: {e}")
                client.close()
                continue
            for s in (client, upstream):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._count(connections=1)
            session = {"plain": None, "v5": False}
            threading.Thread(target=self._to_broker, args=(client, upstream, session),
                             daemon=True).start()
            threading.Thread(target=self._to_client, args=(upstream, client, session),
                             daemon=True).start()

    @staticmethod
    def _close(*socks: socket.socket) -> None:
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()

    def _to_broker(self, src: socket.socket, dst: socket.socket, session: dict) -> None:
        """Client → broker: forwarded untouched; the first bytes tell TLS from MQTT."""
        try:
            while data := src.recv(65536):
                if session["plain"] is None:
                    # MQTT CONNECT is exactly 0x10; a TLS handshake record starts 0x16.
                    session["plain"] = data[0] == 0x10
                    if session["plain"] and len(data) > 9:
                        # CONNECT: fixed header, varint, u16 len "MQTT", level byte.
                        _, pos = read_varint(data, 1)
                        name_len = int.from_bytes(data[pos:pos + 2], "big")
                        session["v5"] = data[pos + 2 + name_len] == 5
                self._count(to_broker_bytes=len(data))
                dst.sendall(data)
        except OSError:
            pass
        finally:
            self._close(src, dst)

    def _to_client(self, src: socket.socket, dst: socket.socket, session: dict) -> None:
        buffer = bytearray()
        flip = False
        out = _Sender(dst)
        try:
            while data := src.recv(65536):
                self._count(to_client_bytes=len(data))
                if not session["plain"]:
                    self._count(opaque_bytes=len(data))
                    out.send(data)
                    continue
                buffer += data
                for packet in split_packets(buffer):
                    pub = parse_publish(packet, session["v5"])
                    if pub is None:
                        out.send(packet)
                        continue
                    topic, _, middle, payload = pub
                    now = time.time_ns()
                    readable = (len(payload) >= 8 and
                                abs(int.from_bytes(payload[:8], "big") - now) < READABLE_WINDOW_NS)
                    self._count(publishes=1, readable=int(readable))
                    flip = not flip
                    mode = self.tamper if flip else "none"
                    if mode == "drop":
                        self._count(tampered=1)
                        continue
                    if mode == "alter" and payload:
                        payload = payload[:-1] + bytes((payload[-1] ^ 1,))
                        packet = build_publish(packet[0], topic, middle, payload)
                        self._count(tampered=1)
                    elif mode == "redirect" and topic.endswith("/temp"):
                        packet = build_publish(packet[0], topic[:-4] + "humidity", middle, payload)
                        self._count(tampered=1)
                    elif mode == "delay":
                        self._count(tampered=1)
                        out.later(packet, self.delay_s)
                        continue
                    out.send(packet)
        except (OSError, ValueError):
            pass
        finally:
            out.close()
            self._close(src, dst)

    def stop(self) -> None:
        self._stop.set()
        self._close(self.server)
