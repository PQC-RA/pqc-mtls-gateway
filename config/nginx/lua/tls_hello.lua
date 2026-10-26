-- tls_hello.lua: ssl_client_hello_by_lua handler for the mTLS listener.
--
-- A handshake that fails on key exchange or protocol version never becomes an
-- HTTP request, so it leaves no access-log line, and nginx reports it only at
-- `info` level with a generic reason ("no suitable key share"). This hook reads
-- the ClientHello and, when it cannot be served, logs ONE warn-level line that
-- names the reason and what the client offered:
--
--   PQC-TLS refusing handshake: reason=no_pq_group offered_groups=X25519,secp256r1 ...
--
-- It only observes. It never rejects (nginx/OpenSSL do that, from
-- `ssl_protocols TLSv1.3` and `ssl_conf_command Groups X25519MLKEM768`), and
-- every step is pcall-guarded so a parsing fault can never abort a handshake.
-- REQUIRED_GROUP must match the Groups directive on the same server.
local REQUIRED_GROUP = 0x11ec -- X25519MLKEM768
local TLS13 = 0x0304

local NAMES = {
    [0x11ec] = "X25519MLKEM768", [0x11eb] = "SecP256r1MLKEM768", [0x11ed] = "SecP384r1MLKEM1024",
    [0x0200] = "MLKEM512", [0x0201] = "MLKEM768", [0x0202] = "MLKEM1024",
    [0x001d] = "X25519", [0x001e] = "X448",
    [0x0017] = "secp256r1", [0x0018] = "secp384r1", [0x0019] = "secp521r1",
    [0x0100] = "ffdhe2048", [0x0101] = "ffdhe3072", [0x0102] = "ffdhe4096",
    [0x0103] = "ffdhe6144", [0x0104] = "ffdhe8192",
    [0x6399] = "X25519Kyber768Draft00",
}
local VERSIONS = { [0x0304] = "TLSv1.3", [0x0303] = "TLSv1.2", [0x0302] = "TLSv1.1", [0x0301] = "TLSv1" }

local function u16list(s, lenbytes)
    -- s = raw extension body; first `lenbytes` bytes are the list length
    local out = {}
    if not s or #s < lenbytes then return out end
    for i = lenbytes + 1, #s - 1, 2 do
        out[#out + 1] = s:byte(i) * 256 + s:byte(i + 1)
    end
    return out
end

local function grease(v) return v % 256 == 0x0a and math.floor(v / 256) % 16 == 0x0a end

local function names(list, map)
    local o = {}
    for _, v in ipairs(list) do
        if not grease(v) then o[#o + 1] = map[v] or string.format("0x%04x", v) end
    end
    return table.concat(o, ",")
end

local function inspect()
    local ch = require "ngx.ssl.clienthello"
    local groups = u16list(ch.get_client_hello_ext(10), 2)   -- supported_groups
    local versions = u16list(ch.get_client_hello_ext(43), 1) -- supported_versions
    local has_group, has_13 = false, false
    for _, g in ipairs(groups) do if g == REQUIRED_GROUP then has_group = true end end
    for _, v in ipairs(versions) do if v == TLS13 then has_13 = true end end
    local reason
    if not has_13 then
        reason = "no_tls13"
    elseif not has_group then
        reason = "no_pq_group"
    end
    if reason then
        ngx.log(ngx.WARN, "PQC-TLS refusing handshake: reason=", reason,
            " offered_groups=", (#groups > 0 and names(groups, NAMES) or "none"),
            " offered_versions=", (#versions > 0 and names(versions, VERSIONS) or "none(legacy)"),
            " required=X25519MLKEM768+TLSv1.3",
            " sni=", ch.get_client_hello_server_name() or "")
    end
end

local ok, err = pcall(inspect)
if not ok then
    ngx.log(ngx.ERR, "[tls_hello] ClientHello inspection failed (handshake unaffected): ", tostring(err))
end
