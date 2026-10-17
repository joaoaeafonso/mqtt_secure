# Wireshark tooling

| File | What |
|---|---|
| `msec.lua` | dissector for the msec envelope and the lab broker port (MQTT or TLS, auto-detected) |
| `sslkeylog.cpp`, `CMakeLists.txt` | `libmsec_sslkeylog.so`, an `LD_PRELOAD` shim that makes mosquitto and `msec_load_gateway` log TLS secrets to `$SSLKEYLOGFILE` (built by the `bench`, `dev` and `release` presets) |

```bash
ln -sf "$PWD/tools/wireshark/msec.lua" ~/.local/lib/wireshark/plugins/msec.lua
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py live --set load.sensors=3 --capture
```

Full guide: [`docs/network-analysis.md`](../../docs/network-analysis.md).
