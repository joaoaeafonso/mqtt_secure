-- Wireshark dissector for mqtt-secure (Lua plugin, Wireshark >= 3.6).
--
-- 1. Decodes the lab broker port (18830 by default) as MQTT or, when the
--    connection is TLS, as TLS carrying MQTT. The lab switches plain/tls/mtls
--    on the same port, so this is decided per TCP stream from its first bytes.
-- 2. Dissects every MQTT PUBLISH payload as an msec envelope v2
--    (docs/protocol/envelope-format.md): magic, version, mode, key id,
--    sequence, timestamp, nonce, ciphertext / payload, tag / signature.
-- 3. Expert info for the report:
--      msec.replay         an envelope (key id + sequence) published to the
--                          broker again: a replay; links to the original frame
--      msec.unprotected    a payload on a sensor/actuator topic that is not
--                          an envelope (protection off, or an injection)
--      msec.forged         the lab attacker's forgery marker ("FORGED!!")
--      msec.malformed      starts with "MS" but violates the format
-- 4. Lab conventions (preference, on by default): key id = epoch * 1e6 +
--    device, the sensor send time in the first 8 plaintext bytes, downlink
--    command ids and targets.
--
-- Install: copy to ~/.local/lib/wireshark/plugins/ (Wireshark >= 4.x) or
-- ~/.config/wireshark/plugins/, or run  wireshark -X lua_script:msec.lua
--
-- Filters:  msec   msec.mode == 3   msec.key_id == 7   msec.replay_of
--           msec.lab.device == 1   _ws.expert.message contains "Replay"

local msec = Proto("msec", "mqtt-secure envelope")

local MODES = { [1] = "encrypt", [2] = "auth_only", [3] = "sign" }
local TAG_SIZE = { [1] = 16, [2] = 16, [3] = 64 }
local NONCE_SIZE = { [1] = 12, [2] = 12, [3] = 0 }
local FIXED_HEADER = 25
local EPOCH_STRIDE = 1000000

local pf = {
    magic       = ProtoField.string("msec.magic", "Magic"),
    version     = ProtoField.uint8("msec.version", "Version"),
    mode        = ProtoField.uint8("msec.mode", "Protection mode", base.DEC, MODES),
    key_id      = ProtoField.uint32("msec.key_id", "Key id"),
    seq         = ProtoField.uint64("msec.seq", "Sequence number"),
    ts_ms       = ProtoField.int64("msec.timestamp_ms", "Timestamp (ms since epoch)"),
    time        = ProtoField.absolute_time("msec.time", "Timestamp", base.UTC),
    nonce_len   = ProtoField.uint8("msec.nonce_len", "Nonce length"),
    nonce       = ProtoField.bytes("msec.nonce", "Nonce"),
    ciphertext  = ProtoField.bytes("msec.ciphertext", "Ciphertext"),
    payload     = ProtoField.bytes("msec.payload", "Payload (readable)"),
    tag         = ProtoField.bytes("msec.tag", "AES-GCM tag"),
    signature   = ProtoField.bytes("msec.signature", "Ed25519 signature"),
    overhead    = ProtoField.uint32("msec.overhead", "Envelope overhead (bytes)"),
    topic       = ProtoField.string("msec.topic", "Bound topic (authenticated, in AAD)"),
    replay_of   = ProtoField.framenum("msec.replay_of", "Replay of frame"),
    published   = ProtoField.framenum("msec.published_in", "Published to the broker in frame"),
    -- lab conventions
    epoch       = ProtoField.uint32("msec.lab.epoch", "Key epoch"),
    device      = ProtoField.uint32("msec.lab.device", "Device"),
    owner       = ProtoField.string("msec.lab.owner", "Key owner"),
    sent        = ProtoField.absolute_time("msec.lab.sent", "Sender's send time", base.UTC),
    cmd_id      = ProtoField.uint64("msec.lab.command_id", "Command id"),
    cmd_text    = ProtoField.string("msec.lab.command", "Command"),
    forged      = ProtoField.string("msec.lab.forged", "Forgery marker"),
}
msec.fields = pf

local ef = {
    replay      = ProtoExpert.new("msec.replay", "Replay: this envelope was already published",
                                  expert.group.SEQUENCE, expert.severity.WARN),
    unprotected = ProtoExpert.new("msec.unprotected", "Unprotected payload (not an msec envelope)",
                                  expert.group.SECURITY, expert.severity.WARN),
    forged      = ProtoExpert.new("msec.forged", "Lab attacker forgery",
                                  expert.group.SECURITY, expert.severity.WARN),
    malformed   = ProtoExpert.new("msec.malformed", "Malformed msec envelope",
                                  expert.group.MALFORMED, expert.severity.ERROR),
    mode        = ProtoExpert.new("msec.mode.info", "Payload protection mode",
                                  expert.group.SECURITY, expert.severity.CHAT),
}
msec.experts = { ef.replay, ef.unprotected, ef.forged, ef.malformed, ef.mode }

msec.prefs.broker_port = Pref.uint("Broker TCP port", 18830,
    "MQTT broker port; decoded as MQTT or TLS+MQTT automatically")
msec.prefs.lab = Pref.bool("Lab conventions", true,
    "Interpret key ids (epoch, device), send times and commands as the load lab writes them")

local f_msg = Field.new("mqtt.msg")
local f_topic = Field.new("mqtt.topic")
local f_stream = Field.new("tcp.stream")

-- Envelopes published to the broker, "keyid/seq/mode" -> first frame. A copy
-- the broker delivers to subscribers is not a replay; a second PUBLISH to the
-- broker with the same key id and sequence is.
local published = {}

function msec.init()
    published = {}
end

local function ns_time(ns)  -- UInt64 nanoseconds -> NSTime
    local secs = ns / 1000000000
    local rem = ns % 1000000000
    return NSTime(secs:tonumber(), rem:tonumber())
end

local function ms_time(ms)  -- number milliseconds -> NSTime
    local secs = math.floor(ms / 1000)
    return NSTime(secs, (ms - secs * 1000) * 1000000)
end

local function owner_of(device)
    return device == 0 and "gateway" or ("sensor-" .. device)
end

-- The readable plaintext the lab writes: send time (u64 ns), then either
-- zero padding (sensors), "FORGED!!" (attacker), or command id + "CMD:<dev>".
local function lab_plaintext(tree, r)
    if not msec.prefs.lab or r:len() < 8 then
        return
    end
    tree:add(pf.sent, r(0, 8), ns_time(r(0, 8):uint64())):set_generated()
    if r:len() >= 16 then
        local marker = r(8, 8):string()
        if marker == "FORGED!!" or marker == "FORGED-C" then
            tree:add(pf.forged, r(8, 8))
            tree:add_proto_expert_info(ef.forged, "Lab attacker forgery marker " .. marker)
        elseif r:len() > 20 and r(16, 4):string() == "CMD:" then
            tree:add(pf.cmd_id, r(8, 8))
            tree:add(pf.cmd_text, r(16))
        end
    end
end

local function is_device_topic(topic)
    return topic ~= nil and (topic:find("/sensors/", 1, true) or topic:find("/actuators/", 1, true))
end

local function dissect_payload(r, pinfo, tree, topic)
    local len = r:len()
    if len < 2 or r(0, 2):uint() ~= 0x4d53 then
        if is_device_topic(topic) then
            local t = tree:add(msec, r, "mqtt-secure: unprotected payload")
            t:add_proto_expert_info(ef.unprotected)
            lab_plaintext(t, r)
            pinfo.cols.info:append(" [unprotected]")
        end
        return
    end

    local t = tree:add(msec, r)
    t:add(pf.magic, r(0, 2))
    if len < FIXED_HEADER then
        t:add_proto_expert_info(ef.malformed, "Envelope truncated (" .. len .. " < 25 bytes)")
        pinfo.cols.info:append(" [msec malformed]")
        return
    end
    local version = r(2, 1):uint()
    local mode = r(3, 1):uint()
    local key_id = r(4, 4):uint()
    local seq = r(8, 8):uint64()
    local ts_ms = r(16, 8):int64():tonumber()
    local nonce_len = r(24, 1):uint()

    t:add(pf.version, r(2, 1))
    t:add(pf.mode, r(3, 1))
    local key_item = t:add(pf.key_id, r(4, 4))
    if msec.prefs.lab then
        local device = key_id % EPOCH_STRIDE
        key_item:add(pf.epoch, r(4, 4), math.floor(key_id / EPOCH_STRIDE)):set_generated()
        key_item:add(pf.device, r(4, 4), device):set_generated()
        key_item:add(pf.owner, r(4, 4), owner_of(device)):set_generated()
    end
    t:add(pf.seq, r(8, 8))
    t:add(pf.ts_ms, r(16, 8))
    t:add(pf.time, r(16, 8), ms_time(ts_ms)):set_generated()
    t:add(pf.nonce_len, r(24, 1))

    local problem
    if version ~= 2 then
        problem = "unsupported version " .. version
    elseif not MODES[mode] then
        problem = "unknown protection mode " .. mode
    elseif seq == UInt64(0) then
        problem = "sequence number 0 is reserved"
    elseif nonce_len > 32 then
        problem = "nonce length " .. nonce_len .. " > 32"
    elseif len <= FIXED_HEADER + nonce_len then
        problem = "envelope has no body"
    elseif nonce_len ~= NONCE_SIZE[mode] then
        problem = "nonce length " .. nonce_len .. " does not match mode " .. MODES[mode]
    elseif len - FIXED_HEADER - nonce_len < TAG_SIZE[mode] then
        problem = "body shorter than the " .. TAG_SIZE[mode] .. "-byte tag/signature"
    end
    if problem then
        t:add_proto_expert_info(ef.malformed, problem)
        pinfo.cols.info:append(" [msec malformed]")
        return
    end

    if nonce_len > 0 then
        t:add(pf.nonce, r(FIXED_HEADER, nonce_len))
    end
    local body_at = FIXED_HEADER + nonce_len
    local tag_size = TAG_SIZE[mode]
    local data_len = len - body_at - tag_size
    if data_len > 0 then
        local data = r(body_at, data_len)
        if mode == 1 then
            t:add(pf.ciphertext, data)
        else
            local p = t:add(pf.payload, data)
            lab_plaintext(p, data)
        end
    end
    t:add(mode == 3 and pf.signature or pf.tag, r(len - tag_size, tag_size))
    t:add(pf.overhead, r, body_at + tag_size):set_generated()
    if topic then
        t:add(pf.topic, topic):set_generated()
    end
    t:add_proto_expert_info(ef.mode, "Protection: " .. MODES[mode])

    local tag = string.format(" [msec %s key=%d seq=%s]", MODES[mode], key_id, tostring(seq))
    local id = key_id .. "/" .. tostring(seq) .. "/" .. mode
    local to_broker = pinfo.dst_port == msec.prefs.broker_port
    local first = published[id]
    if to_broker then
        if not pinfo.visited and first == nil then
            published[id] = pinfo.number
            first = pinfo.number
        end
        if first ~= nil and first ~= pinfo.number then
            t:add(pf.replay_of, first):set_generated()
            t:add_proto_expert_info(ef.replay,
                "Replay: key " .. key_id .. " sequence " .. tostring(seq) ..
                " was first published in frame " .. first)
            tag = tag .. " [REPLAY of #" .. first .. "]"
        end
    elseif first ~= nil then
        t:add(pf.published, first):set_generated()
    end
    pinfo.cols.info:append(tag)
end

-- Post-dissector: runs after MQTT (also MQTT inside decrypted TLS) on every frame.
function msec.dissector(tvb, pinfo, tree)
    local msgs = { f_msg() }
    if #msgs == 0 then
        return
    end
    local topics = { f_topic() }
    for _, m in ipairs(msgs) do
        -- The topic of a PUBLISH precedes its payload: take the nearest one before it.
        local topic
        for _, tfi in ipairs(topics) do
            if tfi.offset < m.offset then
                topic = tostring(tfi.value)
            end
        end
        dissect_payload(m.range, pinfo, tree, topic)
    end
end
register_postdissector(msec)

-- ------------------------------------------------------------ port binding --
-- One port carries plain MQTT or TLS depending on the lab's transport mode,
-- so decide per TCP stream from its first payload: a TLS record starts with
-- content type 0x14..0x17 and major version 3, which no MQTT packet does
-- (0x14..0x17 would be a CONNECT with reserved flags set).

local mqtt_dissector = Dissector.get("mqtt")
local tls_dissector = Dissector.get("tls")
local stream_kind = {}

local msec_port = Proto("msec_port", "mqtt-secure broker port")

function msec_port.init()
    stream_kind = {}
end

function msec_port.dissector(tvb, pinfo, tree)
    local stream = f_stream()
    local key = stream and stream.value or -1
    local kind = stream_kind[key]
    if kind == nil then
        local b0 = tvb:len() > 0 and tvb(0, 1):uint() or 0
        local b1 = tvb:len() > 1 and tvb(1, 1):uint() or 0
        kind = (b0 >= 0x14 and b0 <= 0x17 and b1 == 3) and "tls" or "mqtt"
        stream_kind[key] = kind
    end
    if kind == "tls" then
        return tls_dissector:call(tvb, pinfo, tree)
    end
    return mqtt_dissector:call(tvb, pinfo, tree)
end

local registered_port

local function bind(port)
    local tcp = DissectorTable.get("tcp.port")
    local tls = DissectorTable.get("tls.port")
    if registered_port then
        tcp:remove(registered_port, msec_port)
        tls:remove(registered_port, mqtt_dissector)
    end
    tcp:add(port, msec_port)
    tls:add(port, mqtt_dissector)  -- application data inside TLS on this port is MQTT
    registered_port = port
end

function msec.prefs_changed()
    if registered_port ~= msec.prefs.broker_port then
        bind(msec.prefs.broker_port)
    end
end

bind(msec.prefs.broker_port)
