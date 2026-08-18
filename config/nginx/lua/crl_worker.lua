-- crl_worker.lua
-- Background poller that mirrors the combined CRL into the shared dict so
-- policy_router.lua can drop revoked client serials inline (Active Enforcement).
--
-- Notes:
--   * Uses the stack's actual OpenSSL via the /opt/openssl alias, never a
--     hardcoded version path. A path that resolves to no binary produces no
--     output, which is indistinguishable from a CRL with no entries: the poll
--     appears to succeed and loads zero revocations. Discarding stderr would
--     hide the difference completely.
--   * Captures stderr and verifies the CRL was actually parsed; if openssl fails
--     or emits no CRL, it logs at ERR (fail-loud) instead of no-op'ing quietly.
--   * Never removes serials once seen, a transient poll failure cannot
--     "un-revoke" a certificate (fail-closed).

local M = {}
local delay = 10 -- seconds

-- Match the binary the rest of the gateway ships (see Dockerfile / healthcheck).
-- Hardcoded rather than sourced from an env var: this path is interpolated
-- directly into an io.popen shell command below, so honoring an
-- attacker-controlled PQC_OPENSSL_BIN would be a shell injection vector.
local OPENSSL  = "/opt/openssl/bin/openssl"
local CRL_FILE = "/etc/pki/pqc-ca/hybrid-combined-crl.pem"

local function poll_crl(premature)
    if premature then
        return
    end

    -- 2>&1 so an openssl failure (missing binary, malformed CRL) shows up in the
    -- stream and is detected below instead of being silently swallowed.
    local cmd = string.format(
        "%s crl -inform PEM -text -noout -in %s 2>&1",
        OPENSSL, CRL_FILE
    )
    local f, err = io.popen(cmd, "r")
    if not f then
        ngx.log(ngx.ERR, "[crl_worker] failed to spawn openssl: ", tostring(err))
    else
        local saw_crl   = false
        local loaded    = 0
        for line in f:lines() do
            -- The header confirms openssl actually parsed a CRL (vs. an error).
            if line:find("Certificate Revocation List", 1, true)
                or line:find("Last Update", 1, true) then
                saw_crl = true
            end
            -- Match plain hex ("1A2B") and colon-delimited serials ("1A:2B:3C").
            local raw = line:match("Serial Number:%s*([0-9A-Fa-f:]+)")
            if raw then
                -- Strip colons + lowercase to match policy_router.lua's lookup
                -- key format: string.lower(client_serial).
                local serial = raw:gsub(":", ""):lower()
                local set_ok, set_err = ngx.shared.pqc_route_meta:set("revoked_:" .. serial, true)
                if not set_ok then
                    -- Dict full (or otherwise unwritable), surface loudly so
                    -- an overflow silently dropping a revocation is never
                    -- mistaken for "0 revocations this cycle".
                    ngx.log(ngx.ERR, "[crl_worker] failed to write revoked serial ", serial,
                        " to pqc_route_meta: ", tostring(set_err))
                end
                loaded = loaded + 1
            end
        end
        f:close()

        if not saw_crl then
            -- No recognisable CRL structure => openssl errored or the file is
            -- missing/empty. Surface it loudly; do NOT pretend "0 revocations".
            ngx.log(ngx.ERR,
                "[crl_worker] CRL poll produced no parsable CRL from ", CRL_FILE,
                " via ", OPENSSL, ", revocation list NOT refreshed this cycle")
        else
            ngx.log(ngx.WARN, "[crl_worker] CRL poll OK, ", loaded, " revoked serial(s) loaded")
        end
    end

    local ok, err2 = ngx.timer.at(delay, poll_crl)
    if not ok then
        ngx.log(ngx.ERR, "[crl_worker] failed to reschedule CRL poller: ", err2)
    end
end

function M.start_polling()
    local ok, err = ngx.timer.at(0, poll_crl)
    if not ok then
        ngx.log(ngx.ERR, "[crl_worker] failed to start CRL poller: ", err)
    end
end

return M
