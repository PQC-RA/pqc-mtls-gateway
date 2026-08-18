-- control_plane.lua
-- Handles POST /update-routes on the internal control-plane port (8081).
-- All requests must carry a valid HMAC-SHA256 signature in the
-- X-Hub-Signature-256 header (format: "sha256=<lowercase-hex>").
-- The shared secret is loaded from the Docker secret at nginx startup and
-- stored in pqc_route_meta under key "cp_hmac_key".
--
-- Replay protection: the HMAC binds more than just the body, so a captured
-- request cannot be replayed later or against a different endpoint. The
-- client sends X-Timestamp (unix seconds) and the signed string is
-- `timestamp .. "\n" .. method .. "\n" .. uri .. "\n" .. body`. The timestamp
-- must also be within 5 minutes of gateway time (checked before the HMAC is
-- even computed). The management-api signer implements this identically.

local cjson    = require("cjson.safe")
local hmac     = require("hmac_sha256")
local ROUTES_DICT = ngx.shared.pqc_routes
local META_DICT   = ngx.shared.pqc_route_meta
local PERSIST_DIR = "/var/cache/pqc-gw/routes"
local PERSIST_FILE = PERSIST_DIR .. "/routes.json"

local function json_error(status, code, message)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ error = code, message = message }))
    return ngx.exit(status)
end

-- Read body early -- HMAC is computed over the raw bytes before JSON decode.
-- (PERSIST_DIR is provisioned once at container start by the gateway entrypoint;
-- the atomic write below is guarded, so we avoid a per-request shell spawn here.)
ngx.req.read_body()
local body = ngx.req.get_body_data()

if not body or #body == 0 then
    return json_error(400, "empty_body", "Request body is required")
end

-- HMAC-SHA256 request authentication.
-- The secret is populated in init_by_lua_block from /run/secrets/control-plane-hmac.
-- If absent, the server is misconfigured -- fail closed.
local cp_secret = META_DICT:get("cp_hmac_key")
if not cp_secret then
    ngx.log(ngx.ERR, "[control_plane] HMAC key absent from shared dict")
    return json_error(500, "misconfigured", "Control-plane HMAC key not initialised")
end

-- Timestamp binding (replay protection). Must be a plain integer and within
-- 5 minutes of gateway time; checked before the HMAC is computed so stale or
-- malformed timestamps are rejected cheaply.
local ts_header = ngx.var.http_x_timestamp
if not ts_header or not ts_header:match("^%d+$") then
    ngx.log(ngx.WARN, "[control_plane] Missing/invalid X-Timestamp from ", ngx.var.remote_addr)
    return json_error(401, "missing_timestamp", "X-Timestamp header required")
end

local ts = tonumber(ts_header)
if math.abs(ngx.time() - ts) > 300 then
    ngx.log(ngx.WARN, "[control_plane] Stale X-Timestamp from ", ngx.var.remote_addr)
    return json_error(401, "stale_request", "X-Timestamp is outside the 5-minute window")
end

local sig_header = ngx.var.http_x_hub_signature_256
if not sig_header then
    ngx.log(ngx.WARN, "[control_plane] Missing X-Hub-Signature-256 from ", ngx.var.remote_addr)
    return json_error(401, "missing_signature", "X-Hub-Signature-256 header required")
end

local provided_hex = sig_header:match("^sha256=([0-9a-fA-F]+)$")
if not provided_hex then
    return json_error(401, "invalid_signature_format", "X-Hub-Signature-256 must be sha256=<hex>")
end

-- Compute HMAC-SHA256 via FFI to libcrypto (see hmac_sha256.lua). This avoids
-- lua-resty-hmac (not bundled with this OpenResty build) and ngx.hmac_sha256
-- (not available in this build). Depending on either would make this handler
-- error (500) on every request in a clean build, silently disabling auth.
-- Signed string binds timestamp + method + path + body so a captured request
-- cannot be replayed later or replayed against a different endpoint.
local signed_string = ts_header .. "\n" .. ngx.req.get_method() .. "\n" .. ngx.var.uri .. "\n" .. body
local expected_hex = hmac.hex(cp_secret, signed_string)
if not expected_hex then
    ngx.log(ngx.ERR, "[control_plane] HMAC computation failed")
    return json_error(500, "hmac_error", "Failed to compute HMAC")
end

-- Constant-time comparison to prevent timing side-channel attacks.
-- Both hex strings are always 64 chars (SHA-256 = 32 bytes).
if #expected_hex ~= #provided_hex then
    ngx.log(ngx.WARN, "[control_plane] HMAC length mismatch from ", ngx.var.remote_addr)
    return json_error(401, "invalid_signature", "HMAC signature verification failed")
end
local acc = 0
for i = 1, #expected_hex do
    acc = bit.bor(acc, bit.bxor(expected_hex:byte(i), provided_hex:byte(i)))
end
if acc ~= 0 then
    ngx.log(ngx.WARN, "[control_plane] HMAC mismatch -- unauthorized update from ", ngx.var.remote_addr)
    return json_error(401, "invalid_signature", "HMAC signature verification failed")
end

local decoded, decode_err = cjson.decode(body)

if not decoded or type(decoded.clients) ~= "table" then
    return json_error(400, "invalid_payload", "Payload must contain a clients object")
end

local normalized = cjson.encode(decoded)
local version = tostring(ngx.now())

-- Fail loud on any persistence I/O error rather than silently reporting 200:
-- a push that isn't actually durable would only surface as routes vanishing
-- on the gateway's next restart, long after the caller believed it succeeded.
-- Only update the live shared-dict state once persistence has genuinely
-- succeeded, so the two never diverge.
local tmp_path = PERSIST_FILE .. ".tmp"

local f, open_err = io.open(tmp_path, "w")
if not f then
    ngx.log(ngx.ERR, "[control_plane] failed to open ", tmp_path, " for writing: ", tostring(open_err))
    return json_error(500, "persist_failed", "Failed to persist routing configuration to disk")
end

local write_ok, write_err = f:write(normalized)
f:close()
if not write_ok then
    ngx.log(ngx.ERR, "[control_plane] failed to write ", tmp_path, ": ", tostring(write_err))
    return json_error(500, "persist_failed", "Failed to persist routing configuration to disk")
end

local rename_ok, rename_err = os.rename(tmp_path, PERSIST_FILE)
if not rename_ok then
    ngx.log(ngx.ERR, "[control_plane] failed to rename ", tmp_path, " to ", PERSIST_FILE, ": ", tostring(rename_err))
    return json_error(500, "persist_failed", "Failed to persist routing configuration to disk")
end

ROUTES_DICT:set("routes:json", normalized)
META_DICT:set("version", version)

ngx.status = 200
ngx.header["Content-Type"] = "application/json"
ngx.say(cjson.encode({ ok = true, version = version }))
