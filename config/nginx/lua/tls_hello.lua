-- tls_hello.lua: ssl_client_hello_by_lua handler for the mTLS listener.
--
-- A handshake that fails on key exchange or protocol version never becomes an
-- HTTP request, so it leaves no access-log line, and nginx reports it only at
-- `info` level with a generic reason ("no suitable key share", "no shared
-- signature algorithms"). This hook reads the ClientHello and, when it cannot
-- be served, logs ONE warn-level line that names the reason and what the
-- client offered:
--
--   PQC-TLS refusing handshake: reason=no_pq_group offered_groups=X25519,secp256r1 ...
--
-- Reasons, checked in this order: no_tls13, no_pq_group, no_pq_sigalg. The
-- last one is a client that has the hybrid group but cannot verify an ML-DSA-65
-- server certificate; current browsers are exactly that.
--
-- It only observes. It never rejects (nginx/OpenSSL do that, from
-- `ssl_protocols TLSv1.3`, `ssl_conf_command Groups X25519MLKEM768` and the
-- ML-DSA-65 server certificate), and every step is pcall-guarded so a parsing
-- fault can never abort a handshake. Used by :443 and :8443; REQUIRED_GROUP
-- must match the Groups directive of both.
local REQUIRED_GROUP = 0x11ec -- X25519MLKEM768
local REQUIRED_SIGALG = 0x0905 -- mldsa65, the server certificate's algorithm
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
local SIGALGS = {
    [0x0904] = "mldsa44", [0x0905] = "mldsa65", [0x0906] = "mldsa87",
    [0x0403] = "ecdsa_secp256r1_sha256", [0x0503] = "ecdsa_secp384r1_sha384",
    [0x0603] = "ecdsa_secp521r1_sha512", [0x0203] = "ecdsa_sha1",
    [0x0804] = "rsa_pss_rsae_sha256", [0x0805] = "rsa_pss_rsae_sha384", [0x0806] = "rsa_pss_rsae_sha512",
    [0x0809] = "rsa_pss_pss_sha256", [0x080a] = "rsa_pss_pss_sha384", [0x080b] = "rsa_pss_pss_sha512",
    [0x0401] = "rsa_pkcs1_sha256", [0x0501] = "rsa_pkcs1_sha384", [0x0601] = "rsa_pkcs1_sha512",
    [0x0201] = "rsa_pkcs1_sha1", [0x0807] = "ed25519", [0x0808] = "ed448",
}

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
    local sigalgs = u16list(ch.get_client_hello_ext(13), 2)  -- signature_algorithms
    local has_group, has_13, has_sigalg = false, false, false
    for _, g in ipairs(groups) do if g == REQUIRED_GROUP then has_group = true end end
    for _, v in ipairs(versions) do if v == TLS13 then has_13 = true end end
    for _, a in ipairs(sigalgs) do if a == REQUIRED_SIGALG then has_sigalg = true end end
    local reason
    if not has_13 then
        reason = "no_tls13"
    elseif not has_group then
        reason = "no_pq_group"
    elseif not has_sigalg then
        reason = "no_pq_sigalg"
    end
    if reason then
        ngx.log(ngx.WARN, "PQC-TLS refusing handshake: reason=", reason,
            " offered_groups=", (#groups > 0 and names(groups, NAMES) or "none"),
            " offered_versions=", (#versions > 0 and names(versions, VERSIONS) or "none(legacy)"),
            " offered_sigalgs=", (#sigalgs > 0 and names(sigalgs, SIGALGS) or "none"),
            " required=X25519MLKEM768+TLSv1.3+mldsa65",
            " sni=", ch.get_client_hello_server_name() or "")
    end
end

local ok, err = pcall(inspect)
if not ok then
    ngx.log(ngx.ERR, "[tls_hello] ClientHello inspection failed (handshake unaffected): ", tostring(err))
end
