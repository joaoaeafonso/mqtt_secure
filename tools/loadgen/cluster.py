"""Control plane for running sensors and attackers on other machines.

The controller (the machine with the broker and the gateway) is the lab's
certificate authority and listens for agents on a TLS control port. An agent
joins with

    loadgen.py agent --controller HOST:PORT --token TOKEN --fingerprint SHA256

Trust bootstrap, in this order:
  1. The agent opens TLS and compares the controller certificate's SHA-256
     fingerprint with --fingerprint *before sending anything*, so a machine
     impersonating the controller learns nothing (not even the token).
  2. The agent authenticates with the token (constant-time compare).
  3. For each sensor it is assigned, the agent generates the private key
     locally and sends only a CSR; the controller signs it for exactly the
     identity it assigned. Sensor private keys never leave the agent.
  4. Secrets the controller must know anyway (MQTT passwords, AES payload
     keys, Ed25519 payload signing keys) travel only over this verified
     channel, and only those of the sensors the agent runs (plus the
     gateway's downlink AES key and public key, which every actuator needs).
     The attacker role receives only the public CA.

The controller identity (CA, its certificate and the token) persists in a
state directory, so agents can stay up across many lab runs and reconnect on
their own. Use --new-token to rotate the token.

Wire format: one JSON object per line over the TLS connection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import queue
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pki as pki_module
from sensors import summarize

PROTOCOL_VERSION = 2  # 2: key files carry kinds and owners (aead + Ed25519)
DEFAULT_CONTROL_PORT = 8089
ROLES = ("sensors", "attacker")


# ------------------------------------------------------------------ framing ---

class Channel:
    """Newline-delimited JSON over a (TLS) socket; send() is thread-safe."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._reader = sock.makefile("r", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()

    def send(self, message: dict) -> None:
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode()
        with self._lock:
            self.sock.sendall(data)

    def receive(self) -> dict | None:
        line = self._reader.readline()
        return json.loads(line) if line else None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def primary_address() -> str:
    """The address other machines most likely reach this one on (no packets sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: routing lookup only
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


# ----------------------------------------------------------------- identity ---

class ControllerIdentity:
    """CA + control-channel certificate + join token, kept in a state directory."""

    def __init__(self, state_dir: Path, new_token: bool = False) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        state_dir.chmod(0o700)
        ca_key, ca_crt = state_dir / "ca.key", state_dir / "ca.crt"
        key, crt = state_dir / "controller.key", state_dir / "controller.crt"
        token = state_dir / "token"
        new_ca = not (ca_key.exists() and ca_crt.exists())
        if new_ca:
            self.ca = pki_module.CertificateAuthority.create()
            self.ca.save(ca_key, ca_crt)
        else:
            self.ca = pki_module.CertificateAuthority.load(ca_key, ca_crt)
        if new_ca or not (key.exists() and crt.exists()):
            leaf_key = pki_module.new_key()
            leaf = self.ca.issue("msec-loadtest-controller", leaf_key.public_key(), server=True)
            pki_module.write_private(key, pki_module.key_pem(leaf_key))
            crt.write_bytes(pki_module.cert_pem(leaf))
        if new_token or not token.exists():
            pki_module.write_private(token, secrets.token_urlsafe(24).encode())
        self.key_path, self.cert_path = key, crt
        self.token = token.read_text().strip()
        cert = ssl.PEM_cert_to_DER_cert(crt.read_text())
        self.fingerprint = fingerprint(cert)


# ------------------------------------------------------------------- agents ---

@dataclass
class AgentHandle:
    """The controller's view of one connected agent."""

    agent_id: int
    role: str
    host: str
    processes: int
    channel: Channel
    connected: bool = True
    busy: bool = False
    latest: dict = field(default_factory=dict)
    clock: dict = field(default_factory=dict)
    inbox: queue.Queue = field(default_factory=queue.Queue)

    def send(self, message: dict) -> None:
        if self.connected:
            try:
                self.channel.send(message)
            except OSError:
                self.connected = False

    def expect(self, kind: str, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.connected:
                raise RuntimeError(f"agent {self.host} (#{self.agent_id}): no '{kind}' reply")
            try:
                message = self.inbox.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if message.get("type") == "error":
                raise RuntimeError(f"agent {self.host}: {message.get('message')}")
            if message.get("type") == kind:
                return message

    def describe(self) -> dict:
        return {"id": self.agent_id, "role": self.role, "host": self.host,
                "connected": self.connected, "busy": self.busy, "clock": self.clock,
                "report": self.latest}


class ControlServer:
    def __init__(self, identity: ControllerIdentity, listen: str, port: int, log=print) -> None:
        self.identity = identity
        self.listen, self.port = listen, port
        self.log = log
        self.agents: list[AgentHandle] = []
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._next_id = 1
        self._stop = threading.Event()
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.load_cert_chain(identity.cert_path, identity.key_path)
        self._server = socket.create_server((listen, port), reuse_port=False)

    def start(self) -> None:
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._server.close()
        with self._lock:
            agents = list(self.agents)
        for agent in agents:
            agent.channel.close()

    def join_command(self, advertise: str) -> str:
        return (f"loadgen.py agent --controller {advertise}:{self.port} "
                f"--token {self.identity.token} --fingerprint {self.identity.fingerprint} "
                "--role sensors|attacker")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw, address = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw, address), daemon=True).start()

    def _serve(self, raw: socket.socket, address) -> None:
        try:
            raw.settimeout(10)
            tls = self._context.wrap_socket(raw, server_side=True)
            channel = Channel(tls)
            hello = channel.receive()
            tls.settimeout(None)
        except (OSError, ssl.SSLError, json.JSONDecodeError):
            raw.close()
            return
        problem = None
        if not hello:
            problem = "closed before hello (did the agent reject our fingerprint?)"
        elif hello.get("type") != "hello":
            problem = "expected hello"
        elif not hmac.compare_digest(str(hello.get("token", "")), self.identity.token):
            problem = "invalid token"
        elif hello.get("version") != PROTOCOL_VERSION:
            problem = f"protocol version {hello.get('version')} != {PROTOCOL_VERSION}"
        elif hello.get("role") not in ROLES:
            problem = "unknown role"
        if problem:
            self.log(f"· rejected agent from {address[0]}: {problem}")
            try:
                channel.send({"type": "reject", "reason": problem})
            except OSError:
                pass
            channel.close()
            return

        with self._lock:
            agent = AgentHandle(self._next_id, hello["role"], f"{hello.get('host', '?')} ({address[0]})",
                                int(hello.get("processes", 1)), channel)
            self._next_id += 1
            self.agents.append(agent)
            self._changed.notify_all()
        channel.send({"type": "welcome", "agent_id": agent.agent_id})
        self.log(f"· agent #{agent.agent_id} joined: {agent.role} on {agent.host}")
        try:
            while (message := channel.receive()) is not None:
                kind = message.get("type")
                if kind == "ping":
                    channel.send({"type": "pong", "t0": message["t0"], "t1": time.time_ns()})
                elif kind == "report":
                    agent.latest = message.get("data") or {}
                    agent.clock = message.get("clock") or {}
                else:
                    agent.inbox.put(message)
        except (OSError, ssl.SSLError, json.JSONDecodeError):
            pass
        finally:
            agent.connected = False
            channel.close()
            with self._lock:
                self.agents.remove(agent)
                self._changed.notify_all()
            self.log(f"· agent #{agent.agent_id} ({agent.role} on {agent.host}) disconnected")

    def claim(self, role: str, count: int, timeout: float, stop: threading.Event | None = None,
              announce=None) -> list[AgentHandle]:
        """Waits until `count` idle agents of `role` are connected and reserves them."""
        deadline = time.monotonic() + timeout
        announced = -1
        with self._lock:
            while True:
                idle = [a for a in self.agents if a.role == role and not a.busy and a.connected]
                if len(idle) >= count:
                    for a in idle[:count]:
                        a.busy = True
                    return idle[:count]
                if announce and len(idle) != announced:
                    announced = len(idle)
                    announce(f"waiting for {role} agents: {len(idle)}/{count} connected")
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (stop and stop.is_set()):
                    raise RuntimeError(f"only {len(idle)} of {count} {role} agents joined in time")
                self._changed.wait(timeout=min(remaining, 1.0))

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [a.describe() for a in self.agents]


# ----------------------------------------------- remote groups (lab-facing) ---

def transport_for_agent(transport: dict) -> dict:
    """The agent substitutes its own path to the CA certificate."""
    return {k: v for k, v in transport.items() if k != "ca"}


class RemoteSensors:
    """A slice of the sensor fleet running on an agent; same interface as SensorFleet."""

    def __init__(self, agent: AgentHandle, ids: list[int], ca: pki_module.CertificateAuthority,
                 passwords: dict[str, str], key_lines: list[str], settings: dict,
                 record_issued=None) -> None:
        self.agent, self.ids = agent, ids
        agent.send({"type": "assign", "role": "sensors", "ids": ids})
        csrs = agent.expect("csrs", timeout=120)["csrs"]
        certs = {}
        for sensor_id in ids:
            name = f"sensor-{sensor_id}"
            pem = pki_module.cert_pem(ca.issue_from_csr(csrs[name], expected_cn=name))
            if record_issued:
                record_issued(name, pem)  # kept for revocation (CRL)
            certs[name] = pem.decode()
        agent.send({"type": "provision", "ca": ca.pem.decode(), "certs": certs,
                    "passwords": {f"sensor-{i}": passwords[f"sensor-{i}"] for i in ids},
                    "keys": key_lines,
                    "settings": {**settings, "transport": transport_for_agent(settings["transport"])}})
        agent.expect("started", timeout=60)

    def update(self, **change) -> None:
        if "transport" in change:
            change = {**change, "transport": transport_for_agent(change["transport"])}
        self.agent.send({"type": "update", "change": change})

    def poll(self) -> dict:
        r = self.agent.latest
        if not self.agent.connected or not r:
            return {"sent": r.get("sent", 0), "skipped": r.get("skipped", 0), "up": 0,
                    "total": len(self.ids),
                    "last_error": "agent disconnected" if not self.agent.connected else ""}
        return r

    def stop(self) -> None:
        self.agent.send({"type": "release"})
        try:
            self.agent.expect("released", timeout=15)
        except RuntimeError:
            pass
        self.agent.busy = False


class RemoteAttacker:
    """An attacker running on an agent; same interface as attacker.Attacker."""

    def __init__(self, agent: AgentHandle, ca: pki_module.CertificateAuthority,
                 settings: dict) -> None:
        self.agent = agent
        agent.send({"type": "assign", "role": "attacker"})
        agent.send({"type": "provision", "ca": ca.pem.decode(),
                    "settings": {**settings, "transport": transport_for_agent(settings["transport"])}})
        agent.expect("started", timeout=60)

    update = RemoteSensors.update

    def poll(self) -> dict:
        r = dict(self.agent.latest)
        if not self.agent.connected:
            r.update(connected=False, detail="agent disconnected")
        return r

    def stop(self) -> None:
        RemoteSensors.stop(self)


class FleetGroup:
    """Several sensor groups (local or remote) seen as one fleet."""

    def __init__(self, members: list, names: list[str]) -> None:
        self.members, self.names = members, names

    def update(self, **change) -> None:
        for m in self.members:
            m.update(**change)

    def rotate(self, keys, epoch: int) -> None:
        """Key rotation: each member gets only its own sensors' new keys."""
        for m in self.members:
            m.update(add_keys=pki_module.device_view(keys, m.ids).lines())
            m.update(epoch=epoch)

    def poll(self) -> dict:
        reports = [(name, m.poll()) for name, m in zip(self.names, self.members)]
        out = summarize([r for _, r in reports], sum(r.get("total", 0) for _, r in reports))
        errors = [f"{name}: {r['last_error']}" for name, r in reports if r.get("last_error")]
        out["last_error"] = errors[-1] if errors else ""
        return out

    def stop(self) -> None:
        for m in self.members:
            m.stop()


class AttackerGroup:
    """Several attackers seen as one: counters add up, status summarises."""

    COUNTERS = ("received", "injected", "replayed", "captured")

    def __init__(self, members: list, names: list[str]) -> None:
        self.members, self.names = members, names

    def update(self, **change) -> None:
        for m in self.members:
            m.update(**change)

    def poll(self) -> dict:
        reports = [m.poll() for m in self.members]
        out = {k: sum(r.get(k, 0) for r in reports) for k in self.COUNTERS}
        connected = [r for r in reports if r.get("connected")]
        out["connected"] = bool(connected)
        out["enabled"] = any(r.get("enabled") for r in reports)
        out["identity"] = reports[0].get("identity", "mallory") if reports else "mallory"
        if len(reports) == 1:
            out["detail"] = reports[0].get("detail", "")
        else:
            details = sorted({r.get("detail", "") for r in reports})
            out["detail"] = f"{len(connected)}/{len(reports)} connected — " + "; ".join(details)
        return out

    def stop(self) -> None:
        for m in self.members:
            m.stop()
