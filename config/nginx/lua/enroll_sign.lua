-- enroll_sign.lua
-- access_by_lua phase handler for the public :8443 /enroll endpoint.
--
-- The /enroll -> management-api:3000/api/admin/certs/sign proxy hop is signed.
-- Unlike /admin/ it carries no self-authenticating JWT, so without a signature
-- an on-path attacker on this internal segment could substitute the
-- submitted CSR for their own (keeping the legitimate CN), causing
-- management-api to sign the attacker's key under someone else's identity.
--
-- Fix: sign the exact bytes about to be proxied with a dedicated HMAC-SHA256
-- secret, so management-api can detect any tampering in flight and reject
-- before touching the CA or consuming the enrollment token.
--
-- Signed string construction mirrors policy.service.ts's control-plane push
-- EXACTLY (same convention management-api already verifies for
-- control_plane.lua) -- do not invent a different one here:
--   timestamp .. "\n" .. method .. "\n" .. uri .. "\n" .. body
--
-- `uri` is the fixed UPSTREAM path management-api will see on ITS side
-- (/api/admin/certs/sign), not this location's own /enroll path -- proxy_pass
-- rewrites the path, and the signed string must match what the verifying
-- guard reconstructs from its own incoming request.
--
-- Runs in the access phase (before proxy_pass), so the signature covers
-- exactly the bytes about to be proxied onward. enroll_audit.lua (log phase,
-- runs after the response) is unaffected -- the two run in different,
-- non-conflicting phases and can coexist on this location.
--
-- Secret: a dedicated enroll-hmac secret -- deliberately NOT control-plane-hmac
-- or custodian-hmac, same "don't cross trust domains" reasoning already applied
-- to those two. A leaked enroll secret should only ever let an attacker sign
-- CSRs through the public enrollment endpoint, not push routes or directly
-- mint/revoke certs via pqc-ca-custodian.

local hmac = require("hmac_sha256")
local META_DICT = ngx.shared.pqc_route_meta

-- This location only ever proxies to this one fixed upstream path (see
-- proxy_pass below in nginx.conf). management-api's verifying guard computes
-- its own request path the same way -- both sides must agree on this literal.
local UPSTREAM_URI = "/api/admin/certs/sign"

local function fail(status, code, message)
    ngx.log(ngx.ERR, "[enroll_sign] ", code, ": ", message)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error":"' .. code .. '","message":"' .. message .. '"}')
    return ngx.exit(status)
end

local secret = META_DICT:get("enroll_hmac_key")
if not secret then
    return fail(500, "misconfigured", "Enroll HMAC key not initialised")
end

-- Read the raw body -- HMAC is computed over the exact bytes proxy_pass will
-- forward, before any decoding. client_body_buffer_size (set on this
-- location) matches client_max_body_size, so the body is normally available
-- in memory here; the temp-file fallback below covers the rare case where it
-- still spills (e.g. a misconfigured buffer size after a future edit).
ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body then
    local body_file = ngx.req.get_body_file()
    if body_file then
        local f = io.open(body_file, "r")
        if f then
            body = f:read("*a")
            f:close()
        end
    end
end
body = body or ""

local timestamp = tostring(ngx.time())
local signed_string = timestamp .. "\n" .. ngx.req.get_method() .. "\n" .. UPSTREAM_URI .. "\n" .. body
local sig_hex = hmac.hex(secret, signed_string)
if not sig_hex then
    return fail(500, "hmac_error", "Failed to compute HMAC")
end

ngx.req.set_header("X-Timestamp", timestamp)
ngx.req.set_header("X-Hub-Signature-256", "sha256=" .. sig_hex)
