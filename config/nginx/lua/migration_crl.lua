-- migration_crl.lua: revocation for the migration listener, per issuer.
--
-- The migration listener trusts more than one CA: the gateway's ML-DSA-65 chain
-- and the customer's classical CA(s). A serial number is unique only within its
-- issuer, so revocations are held per issuer: key "rev|<issuer DN>|<serial>" in
-- the shared dict migration_crl, with "<issuer DN>" in RFC 2253 form, the form
-- nginx gives $ssl_client_i_dn.
--
-- Sources, every PEM CRL in:
--   /etc/pki/pqc-ca/hybrid-combined-crl.pem   the gateway's own (crl-renewer)
--   /etc/nginx/migration/crl-bundle.pem       the customer CAs', kept current by
--                                             the operator
-- A CRL is loaded only if its signature verifies against client-ca-bundle.pem,
-- so a file that merely claims an issuer's name revokes nothing.
--
-- Per request (check()), for a verified client certificate:
--   no CRL loaded for its issuer   -> refused (no_crl_for_issuer), unless
--                                     $pqc_migration_crl_required is "off"
--   its serial revoked              -> refused (certificate_revoked)
--   the issuer's CRL past nextUpdate -> refused (crl_stale), unless
--                                     $pqc_migration_crl_stale is "accept"
--
-- Like crl_worker.lua: a revocation, once loaded, is never removed (a transient
-- read failure or an older file cannot un-revoke); openssl runs only when a
-- source file changes; failures are logged at ERR, never read as "no entries".

local cjson = require "cjson.safe"

local M = {}

-- Fixed paths only: they are interpolated into io.popen commands.
local OPENSSL = "/opt/openssl/bin/openssl"
local CA_BUNDLE = "/etc/nginx/migration/client-ca-bundle.pem"
local SOURCES = {
    "/etc/pki/pqc-ca/hybrid-combined-crl.pem",
    "/etc/nginx/migration/crl-bundle.pem",
}
local TMP = "/tmp/migration-crl-block.pem"
local DELAY = 1 -- seconds, as crl_worker.lua

local MONTHS = { Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
                 Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12 }

-- "Nov  1 21:05:37 2026 GMT" -> unix seconds (UTC), or nil
local function parse_time(s)
    local mon, d, h, mi, sec, y = (s or ""):match("(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)%s+(%d+)%s+GMT")
    if not mon or not MONTHS[mon] then return nil end
    y, mon, d = tonumber(y), MONTHS[mon], tonumber(d)
    -- days from civil (Howard Hinnant), no dependence on the local time zone
    if mon <= 2 then y = y - 1 end
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = (mon + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(sec)
end

-- Load one PEM CRL block; returns true on success.
local function load_block(block, source)
    local f = io.open(TMP, "w")
    if not f then
        ngx.log(ngx.ERR, "[migration_crl] cannot write ", TMP)
        return false
    end
    f:write(block)
    f:close()
    local p = io.popen(string.format(
        "%s crl -in %s -CAfile %s -noout -issuer -nextupdate -nameopt RFC2253 -text 2>&1",
        OPENSSL, TMP, CA_BUNDLE), "r")
    if not p then
        ngx.log(ngx.ERR, "[migration_crl] failed to spawn openssl")
        return false
    end
    local verified, issuer, next_update, serials = false, nil, nil, {}
    for line in p:lines() do
        if line == "verify OK" then verified = true end
        issuer = issuer or line:match("^issuer=(.+)$")
        next_update = next_update or line:match("^nextUpdate=(.+)$")
        local raw = line:match("Serial Number:%s*([0-9A-Fa-f:]+)")
        if raw then serials[#serials + 1] = raw:gsub(":", ""):lower() end
    end
    p:close()
    os.remove(TMP)
    if not verified or not issuer then
        ngx.log(ngx.ERR, "[migration_crl] a CRL in ", source, " (issuer ", tostring(issuer),
            ") does not verify against ", CA_BUNDLE, "; ignored")
        return false
    end
    local dict = ngx.shared.migration_crl
    -- Revocations first: from any verified CRL, however old, they only add refusals.
    for _, s in ipairs(serials) do
        local ok, err = dict:safe_set("rev|" .. issuer .. "|" .. s, true)
        if not ok then
            ngx.log(ngx.ERR, "[migration_crl] revocation NOT recorded for ", issuer, " ", s, ": ", err)
        end
    end
    local nu = parse_time(next_update)
    local meta_key = "meta|" .. issuer
    local old = cjson.decode(dict:get(meta_key) or "")
    -- An older CRL for the same issuer (an earlier nextUpdate) must not roll the
    -- issuer's freshness back.
    if old and old.next_update and nu and nu < old.next_update then
        ngx.log(ngx.WARN, "[migration_crl] older CRL for ", issuer, " in ", source, ": revocations kept, freshness not")
        return true
    end
    if not old then
        -- Index of issuers, so status() never walks the revocation keys.
        local list = cjson.decode(dict:get("issuers") or "") or {}
        list[#list + 1] = issuer
        dict:safe_set("issuers", cjson.encode(list))
    end
    local ok, err = dict:safe_set(meta_key, cjson.encode({
        issuer = issuer, next_update = nu, loaded = ngx.time(), revoked = #serials, source = source }))
    if not ok then
        ngx.log(ngx.ERR, "[migration_crl] issuer state not recorded for ", issuer, ": ", err)
        return false
    end
    return true
end

local last_seen = {}

local function poll(premature)
    if premature then return end
    for _, src in ipairs(SOURCES) do
        local f = io.open(src, "r")
        local text = f and f:read("*a")
        if f then f:close() end
        if text and text ~= last_seen[src] then
            local all_ok, n = true, 0
            for block in text:gmatch("%-%-%-%-%-BEGIN X509 CRL%-%-%-%-%-.-%-%-%-%-%-END X509 CRL%-%-%-%-%-") do
                n = n + 1
                if not load_block(block .. "\n", src) then all_ok = false end
            end
            if n == 0 then
                ngx.log(ngx.ERR, "[migration_crl] no CRL in ", src)
            else
                ngx.log(ngx.WARN, "[migration_crl] ", src, ": ", n, " CRL(s) read",
                    all_ok and "" or ", some ignored")
            end
            -- Remembered even when a block failed: a bad block stays bad until the
            -- file changes, and is not re-reported every second.
            last_seen[src] = text
        end
    end
    local ok, err = ngx.timer.at(DELAY, poll)
    if not ok then ngx.log(ngx.ERR, "[migration_crl] failed to reschedule: ", err) end
end

-- Worker 0 only (the dict is shared). Does nothing unless the migration
-- listener is configured (its CA bundle exists).
function M.start()
    local f = io.open(CA_BUNDLE, "r")
    if not f then return end
    f:close()
    local ok, err = ngx.timer.at(0, poll)
    if not ok then ngx.log(ngx.ERR, "[migration_crl] failed to start: ", err) end
end

local function refuse(status, code, detail)
    ngx.log(ngx.WARN, "[migration_crl] refused ", detail, ": ", code)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ error = code }))
    return ngx.exit(status)
end

-- Access phase. Only a verified certificate is checked: without one there is
-- nothing to revoke, and an unverified one never reaches this phase.
function M.check()
    if ngx.var.ssl_client_verify ~= "SUCCESS" then return end
    local issuer = ngx.var.ssl_client_i_dn or ""
    local serial = (ngx.var.ssl_client_serial or ""):lower()
    local dict = ngx.shared.migration_crl
    local who = "serial " .. serial .. " from " .. issuer
    local meta = cjson.decode(dict:get("meta|" .. issuer) or "")
    if not meta then
        if ngx.var.pqc_migration_crl_required == "off" then return end
        return refuse(403, "no_crl_for_issuer", who)
    end
    if dict:get("rev|" .. issuer .. "|" .. serial) then
        return refuse(403, "certificate_revoked", who)
    end
    if meta.next_update and ngx.time() > meta.next_update
        and ngx.var.pqc_migration_crl_stale ~= "accept" then
        return refuse(403, "crl_stale", who)
    end
end

-- For the inventory: what is loaded, per issuer.
function M.status()
    local dict = ngx.shared.migration_crl
    local out = {}
    for _, issuer in ipairs(cjson.decode(dict:get("issuers") or "") or {}) do
        local m = cjson.decode(dict:get("meta|" .. issuer) or "")
        if m then
            m.stale = m.next_update ~= nil and ngx.time() > m.next_update
            out[#out + 1] = m
        end
    end
    table.sort(out, function(a, b) return (a.issuer or "") < (b.issuer or "") end)
    return out
end

return M
