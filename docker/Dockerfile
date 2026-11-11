# syntax=docker/dockerfile:1
#
# mqtt-secure in containers: the toolchain CI uses (Ubuntu 24.04), nothing
# installed on the host. Driven by ../compose.yaml.
#
#   base       runtime: Mosquitto, the Python venv, tshark, an unprivileged
#              user `lab` with the host user's IDs (Mosquitto must not run as root)
#   toolchain  base + compiler and -dev packages
#   build      compiles the bench preset (gateway, TLS key-log shim, benchmarks, demo)
#   lab        base + the repository's tools + the build output: the image
#              compose.yaml runs (lab, sensors, attacker)

ARG UBUNTU_VERSION=24.04

# ------------------------------------------------------------------- base ---
FROM ubuntu:${UBUNTU_VERSION} AS base
ARG UID=1000
ARG GID=1000
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

# dumpcap (--capture) gets CAP_NET_RAW only, which Docker grants by default;
# with CAP_NET_ADMIN too (the Debian default) it would refuse to start.
# ubuntu:24.04 ships a user `ubuntu` with UID 1000; `lab` takes the host user's IDs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates libcap2-bin openssl procps \
        mosquitto python3 python3-venv tshark \
        libpaho-mqtt1.3 libpaho-mqttpp3-1 libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && setcap cap_net_raw+eip /usr/bin/dumpcap \
 && if id ubuntu >/dev/null 2>&1; then userdel --remove ubuntu; fi \
 && groupadd --non-unique --gid "$GID" lab \
 && useradd --non-unique --uid "$UID" --gid "$GID" --create-home --shell /bin/bash lab

COPY tools/loadgen/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# -------------------------------------------------------------- toolchain ---
FROM base AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        cmake ninja-build g++ libssl-dev libpaho-mqtt-dev libpaho-mqttpp-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# ------------------------------------------------------------------ build ---
FROM toolchain AS build
# Only what the bench preset compiles, so Python or docs edits do not rebuild C++.
COPY CMakeLists.txt CMakePresets.json ./
COPY cmake cmake
COPY modules modules
COPY apps apps
COPY benchmarks benchmarks
COPY tools/wireshark tools/wireshark
# The build tree lives in a cache mount: a source change recompiles only what
# it touches, and the fetched Google Benchmark is not downloaded again.
RUN --mount=type=cache,id=mqtt-secure-bench,target=/src/build \
    cmake --preset bench \
 && cmake --build --preset bench \
 && mkdir -p /out \
 && cp --parents \
        build/bench/apps/load_gateway/msec_load_gateway \
        build/bench/apps/gateway/msec_gateway_demo \
        build/bench/tools/wireshark/libmsec_sslkeylog.so \
        build/bench/benchmarks/msec_pipeline_benchmarks \
        /out/

# -------------------------------------------------------------------- lab ---
FROM base AS lab
WORKDIR /app
# The repository layout loadgen.py expects: build/bench/... next to tools/.
COPY --from=build /out/ ./
COPY tools tools
COPY tests/vectors tests/vectors
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/msec-entrypoint
# Results go to the host: build/loadtest and build/analysis point into the
# bind-mounted ./build (at /mnt/build); build/bench stays this image's own.
RUN ln -s /mnt/build/loadtest build/loadtest \
 && ln -s /mnt/build/analysis build/analysis \
 && mkdir results && chown lab:lab results
EXPOSE 8088
ENTRYPOINT ["msec-entrypoint"]
CMD ["live", "--config", "tools/loadgen/lab.example.toml", "--set", "load.sensors=100"]
