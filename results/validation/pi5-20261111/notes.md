# Pi 5 platform notes (not captured by manifest.json)

Recorded 2026-11-11, for report Part 2 §3 (Plataforma) and §9 (ameaças).

- **Board:** Raspberry Pi 5 Model B Rev 1.1 (env.txt).
- **Cooling:** official active cooler (fan sensor present; 0 RPM at 45 °C, the
  Pi 5 starts it at ≈ 50 °C). Pilots peaked at 51–52 °C; `throttled = 0x0` in
  every run.
- **Power supply:** official Raspberry Pi 27 W USB-C.
- **Storage:** NVMe SSD, Samsung MZ9LQ256HBJD, 256 GB (not an SD card).
- **Network:** wired, `eth0` at 1000 Mb/s; Wi-Fi (`wlan0`) down.
  Topology: the Pi and the desktop (load machine) are cabled to one simple
  (unmanaged) Ethernet switch, with nothing else between them: no router hop
  on the measured path.
- **Load machine:** the desktop (one machine for both sensor agents and the
  attacker agent): AMD Ryzen 7 3700X (8 cores), 32 GB, Ubuntu 24.04.5,
  kernel 7.0.0-42; wired, `enp6s0` at 1000 Mb/s, Wi-Fi down.
- **Background services:** Docker (7 containers) was running during the
  smoke test and the three pilots; stopped for the campaign
  (`systemctl stop docker.socket docker`).
- **Clocks:** NTP synced before the campaign, NTP off on the Pi and the desktop
  during it; the agents correct the (constant) drift with a fit over the last
  minute of pings.
- **Application scenario behind R_alvo** (group, 2026-11-11): industrial
  monitoring, one edge gateway per plant area; 1,000 condition/vibration
  sensors at 10 Hz → R_alvo = 10,000 msg/s (telemetry); 100 actuators at up to
  10 commands/s → R_alvo = 1,000 msg/s (commands); L_max = 50 ms.
