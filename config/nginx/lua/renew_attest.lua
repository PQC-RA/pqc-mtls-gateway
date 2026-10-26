-- renew_attest.lua
-- access_by_lua handler for `location = /renew` on the mTLS listener (item 4,
-- ADR-015 decisions 1, 2 and 4).
--
-- The client renews with its CURRENT certificate. This handler:
--   * clears every client-supplied header not on the allowlist, so nothing the
--     client sends can pose as the attestation below;
--   * requires a verified client certificate that is not revoked (same dict
--     check as revocation_check.lua);
--   * refuses a resumed TLS session, so every renewal carries a fresh ML-DSA-65
--     CertificateVerify from the current key;
--   * attests the client to management-api over the proxy hop with a dedicated
--     renew-hmac secret:
--       renew-v1 \n POST \n /api/renew \n ts \n nonce \n fingerprint \n serial \n notAfter \n sha256(body)
--     management-api (RenewAttestGuard) checks it and takes the identity only
--     from these fields.
--
-- The location is always present (ADR-019); with renewal switched off
-- management-api answers 404. Without the renew-hmac secret this answers 503.

local header_allowlist = require("header_allowlist")
local hmac = require("hmac_sha256")
local cert_fingerprint = require("cert_fingerprint")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")
local resty_random = require("resty.random")

local META = ngx.shared.pqc_route_meta
local UPSTREAM_URI = "/api/renew" -- must equal the path management-api sees

local function fail(status, code, message)
    ngx.log(ngx.WARN, "[renew_attest] ", code, ": ", message)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error":"' .. code .. '","message":"' .. message .. '"}')
    return ngx.exit(status)
end

header_allowlist.enforce()

if ngx.req.get_method() ~= "POST" then
    return fail(405, "method_not_allowed", "Use POST")
end

local serial = ngx.var.ssl_client_serial
if ngx.var.ssl_client_verify ~= "SUCCESS" or not serial or serial == "" then
    return fail(403, "no_client_certificate", "A valid client certificate is required")
end

if META:get("revoked_:" .. string.lower(serial)) then
    ngx.log(ngx.WARN, "CRITICAL PROTECTION: Dropping revoked PQC client serial on /renew: ", serial)
    return ngx.exit(444)
end

if ngx.var.ssl_session_reused == "r" then
    return fail(403, "session_resumed", "Renewal needs a full handshake; open a new connection")
end

local secret = META:get("renew_hmac_key")
if not secret then
    return fail(503, "renewal_unavailable", "Renewal is not configured on this gateway")
end

local fpr, fpr_err = cert_fingerprint.client_sha256()
if not fpr then
    ngx.log(ngx.ERR, "[renew_attest] could not derive client fingerprint: ", fpr_err or "?")
    return fail(403, "no_client_certificate", "Could not read the client certificate")
end

ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body then
    local body_file = ngx.req.get_body_file()
    if body_file then
        local f = io.open(body_file, "rb")
        if f then
            body = f:read("*a")
            f:close()
        end
    end
end
body = body or ""

local sha = resty_sha256:new()
sha:update(body)
local body_hash = resty_string.to_hex(sha:final())

local nonce_bytes = resty_random.bytes(16, true)
if not nonce_bytes then
    return fail(500, "nonce_error", "Could not generate a nonce")
end
local nonce = resty_string.to_hex(nonce_bytes)
local ts = tostring(ngx.time())
local serial_up = string.upper(serial)
local not_after = ngx.var.ssl_client_v_end or ""

local signed = "renew-v1\nPOST\n" .. UPSTREAM_URI .. "\n" .. ts .. "\n" .. nonce .. "\n" .. fpr
    .. "\n" .. serial_up .. "\n" .. not_after .. "\n" .. body_hash
local mac = hmac.hex(secret, signed)
if not mac then
    return fail(500, "hmac_error", "Failed to compute the attestation")
end

ngx.req.set_header("X-PQC-Renew-Timestamp", ts)
ngx.req.set_header("X-PQC-Renew-Nonce", nonce)
ngx.req.set_header("X-PQC-Renew-Fpr", fpr)
ngx.req.set_header("X-PQC-Renew-Serial", serial_up)
ngx.req.set_header("X-PQC-Renew-NotAfter", not_after)
ngx.req.set_header("X-PQC-Renew-Signature", "sha256=" .. mac)
