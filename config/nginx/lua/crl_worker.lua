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
--
-- Why the interval is short, and must stay shorter than the reload watcher:
-- this poller exists to drop revoked serials BEFORE the nginx reload that
-- refreshes the static ssl_crl. That reload is driven by the entrypoint's
-- /signals/reload-nginx watcher at NGINX_RELOAD_POLL_INTERVAL. At the earlier
-- 10 s interval this poller always lost that race, so the inline check in
-- policy_router.lua never fired: nginx was already refusing the certificate at
-- the TLS layer by the time the dict was written, and with ssl_verify_client
-- on, a failed verify is answered before access_by_lua runs at all. The poller
-- also restarts on every worker start, so each reload reset its cycle; it was
-- second by construction. Keep this STRICTLY BELOW NGINX_RELOAD_POLL_INTERVAL
-- or the fast path goes silent again. bench/crl-fastpath.sh asserts it leads.
--
-- 1 s (was 2 s): with the crl-renewer now checking its sentinel every second,
-- this re-read is the second-largest term in revoke-to-refusal time. Each
-- worker runs its own timer (worker_processes auto), and an unchanged CRL costs
-- one ~12 KB read per worker per second; openssl is spawned only on change.

local M = {}
local delay = 1 -- seconds; see the note above before raising this

-- Last CRL text seen, so a short interval does not mean spawning openssl every
-- cycle. The file is ~10 KB: reading it is a couple of syscalls, re-parsing an
-- unchanged one is a process. Only set after a SUCCESSFUL parse, so a transient
-- failure is retried rather than cached as "already handled".
local last_pem = nil
-- Liveness bookkeeping. Change-detection means the "CRL poll OK" line only
-- appears when the CRL actually changes, so on a quiet system the log could no
-- longer distinguish "nothing to do" from "the poller died". Emit a heartbeat
-- about once a minute instead.
local held      = 0
local last_beat = 0
local BEAT_EVERY = 60 -- seconds

-- Liveness is also published to pqc_route_meta, because last_beat is an upvalue
-- and with worker_processes auto there are several workers: a /metrics request
-- served by one worker cannot see another's. Written at both success points and
-- never on the failure path, so the age climbs exactly when the poller stops
-- confirming a good CRL, which is the signal a silent revocation failure lacks.
-- Deliberately separate from last_beat: BEAT_EVERY rate-limits the *log line*,
-- which would otherwise flood. The metric has no such problem and wants the
-- opposite: publishing on every successful poll keeps the healthy age bounded
-- by the poll interval instead of by the log cadence.
local function publish(now)
    local ok, err = ngx.shared.pqc_route_meta:set("crl_last_update", now)
    if not ok then
        ngx.log(ngx.ERR, "[crl_worker] failed to publish crl_last_update: ", tostring(err))
    end
end

-- Match the binary the rest of the gateway ships (see Dockerfile / healthcheck).
-- Hardcoded rather than sourced from an env var: this path is interpolated
-- directly into an io.popen shell command below, so honoring an
-- attacker-controlled PQC_OPENSSL_BIN would be a shell injection vector.
local OPENSSL  = "/opt/openssl/bin/openssl"
local CRL_FILE = "/etc/pki/pqc-ca/hybrid-combined-crl.pem"

-- nextUpdate of the CRL this poller last loaded, published for
-- pqc_crl_next_update_seconds (ADR-024). pqc_crl_age_seconds says whether this
-- poller is alive, and is refreshed on an unchanged file, so it cannot see a
-- CRL that nobody renews run out. This value can: the metric falls by one per
-- second until a new CRL arrives and goes negative once the CRL has expired,
-- which is when nginx's ssl_crl starts refusing every client certificate.
-- `openssl crl -text` reads only the FIRST CRL in the file, so this is the
-- intermediate CRL as long as the combined file is written intermediate first,
-- as pqc-crl-renew.sh does.
local MONTHS = {
    Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
    Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12,
}

-- "Nov 10 08:52:27 2026 GMT", as ASN1_TIME_print writes it (day space-padded,
-- optional fractional seconds) -> seconds since the epoch, or nil. Computed
-- here rather than with os.time, which reads its table as LOCAL time.
function M.parse_openssl_time(s)
    if type(s) ~= "string" then
        return nil
    end
    local mon, d, h, mi, sec, y =
        s:match("^(%a%a%a)%s+(%d%d?)%s+(%d%d):(%d%d):(%d%d)%.?%d*%s+(%d%d%d%d)%s+GMT$")
    local m = mon and MONTHS[mon]
    if not m then
        return nil
    end
    d, h, mi, sec, y = tonumber(d), tonumber(h), tonumber(mi), tonumber(sec), tonumber(y)
    if d < 1 or d > 31 or h > 23 or mi > 59 or sec > 60 then
        return nil
    end
    -- Days since 1970-01-01 in the proleptic Gregorian calendar
    -- (H. Hinnant's days_from_civil).
    local yy  = (m <= 2) and (y - 1) or y
    local era = math.floor(yy / 400)
    local yoe = yy - era * 400
    local mp  = (m + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + h * 3600 + mi * 60 + sec
end

-- Forward declaration: reschedule() refers to poll_crl, which refers back to
-- reschedule(). Declared local so neither ever becomes a global: a global here
-- would be shared across every request in the worker's Lua VM.
local poll_crl

local function reschedule()
    local ok, err = ngx.timer.at(delay, poll_crl)
    if not ok then
        ngx.log(ngx.ERR, "[crl_worker] failed to reschedule CRL poller: ", err)
    end
end

poll_crl = function(premature)
    if premature then
        return
    end

    -- Cheap change detection. An unreadable file falls through to the openssl
    -- path below so the existing fail-loud handling still reports it.
    local pem
    local fh = io.open(CRL_FILE, "r")
    if fh then
        pem = fh:read("*a")
        fh:close()
        if pem and last_pem and pem == last_pem then
            local now = ngx.now()
            publish(now)
            if now - last_beat >= BEAT_EVERY then
                last_beat = now
                ngx.log(ngx.WARN, "[crl_worker] CRL unchanged, poller alive, ",
                    held, " revoked serial(s) held")
            end
            return reschedule()   -- unchanged since the last successful parse
        end
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
        local next_update_text
        for line in f:lines() do
            -- The header confirms openssl actually parsed a CRL (vs. an error).
            if line:find("Certificate Revocation List", 1, true)
                or line:find("Last Update", 1, true) then
                saw_crl = true
            end
            if not next_update_text then
                next_update_text = line:match("^%s*Next Update:%s*(.-)%s*$")
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
            -- Only now is the file's content known-good, so only now may it be
            -- remembered. Caching it earlier would skip re-parsing a file whose
            -- serials never made it into the dict.
            last_pem  = pem
            held      = loaded
            last_beat = ngx.now()
            publish(last_beat)
            -- A CRL without a parsable nextUpdate ("NONE") withdraws the value,
            -- so the metric disappears rather than reporting the previous CRL's.
            local next_update = M.parse_openssl_time(next_update_text)
            if next_update then
                local nu_ok, nu_err = ngx.shared.pqc_route_meta:set("crl_next_update", next_update)
                if not nu_ok then
                    ngx.log(ngx.ERR, "[crl_worker] failed to publish crl_next_update: ", tostring(nu_err))
                end
            else
                ngx.shared.pqc_route_meta:delete("crl_next_update")
                ngx.log(ngx.ERR, "[crl_worker] CRL has no parsable Next Update (",
                    tostring(next_update_text), "), pqc_crl_next_update_seconds withdrawn")
            end
            ngx.log(ngx.WARN, "[crl_worker] CRL poll OK, ", loaded, " revoked serial(s) loaded")
        end
    end

    reschedule()
end

function M.start_polling()
    local ok, err = ngx.timer.at(0, poll_crl)
    if not ok then
        ngx.log(ngx.ERR, "[crl_worker] failed to start CRL poller: ", err)
    end
end

return M
