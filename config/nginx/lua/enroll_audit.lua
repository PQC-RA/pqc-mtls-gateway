-- enroll_audit.lua
-- log_by_lua phase handler for the public :8443/enroll endpoint.
--
-- Enrollment is the one public mutation exposed by the gateway, so it gets a
-- record of its own. This appends exactly one NDJSON
-- line per request to a DEDICATED audit log on the rw pqc-logs-audit volume.
--
-- This is the ONLY durable record of the :8443 enrollment endpoint. nginx's
-- JSON access_log is attached to the :443 mTLS server only; :8443 has no
-- access_log directive at all.
--
-- It is also the only place REJECTED enrollments appear. The management-api's
-- hash-chained admin-actions.log records `cert.enroll`, but only once a
-- certificate has actually been issued, a bad token, a replayed token, a
-- malformed CSR or a rate-limited request produces no entry there.
--
-- Deliberately NOT hash-chained. nginx runs N workers, each with its own Lua
-- VM, so a correct prev_hash chain would need cross-worker serialisation on
-- every request in the data path, and it would not buy the property anyway:
-- a chain is tamper-EVIDENCE against someone who cannot recompute it, and an
-- attacker who owns the gateway owns this file. Off-host shipping is the real
-- answer if that matters.
--
-- The :8443 server has no ssl_verify_client (client cert optional by design),
-- so there is usually no client certificate; `verify` is reported as-is
-- (commonly "NONE"). CN/token are intentionally NOT extracted: doing so would
-- require buffering the proxied POST body, which we must not do here.
--
-- Runs in the log phase (after the response is sent), so it never buffers or
-- delays the proxied request. Writes go to a rw Docker volume, not the
-- read-only rootfs, so they succeed under the hardened container posture
-- (read-only rootfs + cap_drop ALL + minimal caps).

local cjson = require("cjson.safe")

local AUDIT_PATH = "/var/log/pqc-gw/enroll-audit.log"

local status = tonumber(ngx.var.status) or 0
local level = "info"
if status >= 500 then
    level = "error"
elseif status == 429 or status >= 400 then
    level = "warn"
end

local entry = {
    ts    = ngx.var.time_iso8601,
    event = "enroll",
    level = level,
    client = {
        cn     = "",
        org    = "",
        verify = ngx.var.ssl_client_verify or "NONE",
    },
    tls = {
        version = ngx.var.ssl_protocol or "",
        cipher  = ngx.var.ssl_cipher or "",
    },
    http = {
        method      = ngx.var.request_method,
        uri         = ngx.var.request_uri,
        status      = status,
        remote_addr = ngx.var.remote_addr,
        req_len     = tonumber(ngx.var.request_length) or 0,
    },
}

local line = cjson.encode(entry)
if not line then
    ngx.log(ngx.ERR, "[enroll_audit] failed to encode audit entry")
    return
end

-- Append mode creates the file on first write. The audit directory is a rw
-- Docker volume, so this succeeds even with the read-only container rootfs.
local f, err = io.open(AUDIT_PATH, "a")
if not f then
    ngx.log(ngx.ERR, "[enroll_audit] cannot open ", AUDIT_PATH, ": ", tostring(err))
    return
end
f:write(line, "\n")
f:close()
