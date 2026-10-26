-- tls_telemetry.lua
-- What the TLS handshake actually negotiated, read from the connection's own
-- SSL object (OpenSSL 3.6.2 via FFI), for the access log.
--
-- Why not nginx variables alone: $ssl_curve returns the raw codepoint for the
-- hybrid group ("0x11ec") because this nginx build has no name for it, and
-- nginx has no variable at all for the signature algorithms used in the
-- handshake. Each field was checked against a probe instance (valid ML-DSA-65
-- client, no certificate, classical-keyed certificates, untrusted certificate,
-- resumed session); bench/check-tls-log-evidence.sh asserts the log entries.
--
-- Fields (empty string when not applicable, never an error):
--   group       negotiated key-exchange group     SSL_get0_group_name
--   peer_sig    client CertificateVerify scheme   SSL_get_peer_signature_type_nid
--   local_sig   server CertificateVerify scheme   SSL_get_signature_type_nid
--   peer_key    client certificate key type       SSL_get0_peer_certificate
--
-- A RESUMED session (ssl_session_reused = "r") performs no CertificateVerify
-- on either side, so peer_sig and local_sig are empty there by protocol, not
-- by omission; peer_key still reports the certificate the session carries.
local ffi = require "ffi"
local ngx_ssl = require "ngx.ssl"

ffi.cdef[[
int SSL_get_peer_signature_type_nid(const void *s, int *pnid);
int SSL_get_signature_type_nid(const void *s, int *pnid);
const char *SSL_get0_group_name(void *s);
const char *OBJ_nid2sn(int n);
void *SSL_get0_peer_certificate(const void *s);
void *X509_get0_pubkey(const void *x);
const char *EVP_PKEY_get0_type_name(const void *pkey);
]]

local C = ffi.C
local nidp = ffi.new("int[1]")

local M = {}

local function nid_name(nid)
    if nid <= 0 then
        return ""
    end
    local p = C.OBJ_nid2sn(nid)
    return p ~= nil and ffi.string(p) or ("nid:" .. nid)
end

function M.collect()
    local s = ngx_ssl.get_req_ssl_pointer()
    if not s then
        return nil
    end
    local t = {}

    local g = C.SSL_get0_group_name(s)
    t.group = g ~= nil and ffi.string(g) or ""

    t.peer_sig = C.SSL_get_peer_signature_type_nid(s, nidp) == 1 and nid_name(nidp[0]) or ""
    t.local_sig = C.SSL_get_signature_type_nid(s, nidp) == 1 and nid_name(nidp[0]) or ""

    t.peer_key = ""
    local x = C.SSL_get0_peer_certificate(s)
    if x ~= nil then
        local k = C.X509_get0_pubkey(x)
        if k ~= nil then
            local tn = C.EVP_PKEY_get0_type_name(k)
            t.peer_key = tn ~= nil and ffi.string(tn) or "unknown"
        end
    end
    return t
end

-- log_by_lua entry point (see tls_log.lua). Never raises.
local warned = false -- per worker: module state survives across requests
function M.log_phase()
    local good, t = pcall(M.collect)
    if not good or not t then
        if not warned then
            warned = true
            ngx.log(ngx.ERR, "[tls_telemetry] TLS telemetry unavailable: ", tostring(t))
        end
        return
    end
    ngx.var.pqc_tls_group = t.group
    ngx.var.pqc_tls_client_sig = t.peer_sig
    ngx.var.pqc_tls_server_sig = t.local_sig
    ngx.var.pqc_tls_client_key = t.peer_key
end

return M
