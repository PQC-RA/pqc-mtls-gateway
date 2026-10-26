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
-- A CRL is used only if its signature verifies against the one certificate in
-- client-ca-bundle.pem whose subject is the CRL's issuer. Two certificates with
-- the same subject (a CA key rolled over under the same name) are refused for
-- that name: openssl would verify against one of them only, and the other key's
-- revocations would be lost. Their clients get no_crl_for_issuer.
--
-- Per request (check()), for a verified client certificate:
--   its serial revoked               -> refused (certificate_revoked)
--   no usable CRL for its issuer     -> refused (no_crl_for_issuer), unless
--                                       $pqc_migration_crl_required is "off"
--   the issuer's CRL past nextUpdate -> refused (crl_stale), unless
--   (or without nextUpdate)             $pqc_migration_crl_stale is "accept"
--
-- Like crl_worker.lua: a revocation, once loaded, is never removed; openssl runs
-- only when a file changes. If even one revocation of a CRL cannot be stored
-- (dict full), its issuer is marked as having no usable CRL, so nothing is
-- served on an incomplete list. A failure that may be transient (openssl not
-- spawned, a read error) is retried on the next tick. openssl runs through
-- ngx.pipe (no shell; worker 0 keeps serving while it runs), the CRL on stdin,
-- each CA certificate from a directory private to the worker.

local cjson = require "cjson.safe"
local ngx_pipe = require "ngx.pipe"

local M = {}

local OPENSSL = "/opt/openssl/bin/openssl"
local CA_BUNDLE = "/etc/nginx/migration/client-ca-bundle.pem"
local SOURCES = {
    "/etc/pki/pqc-ca/hybrid-combined-crl.pem",
    "/etc/nginx/migration/crl-bundle.pem",
}
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

-- Run openssl with `input` on stdin; returns output (stdout+stderr) or nil, err.
local function openssl(args, input)
    local argv = { OPENSSL }
    for _, a in ipairs(args) do argv[#argv + 1] = a end
    local proc, err = ngx_pipe.spawn(argv, { merge_stderr = true, buffer_size = 65536 })
    if not proc then return nil, "spawn: " .. tostring(err) end
    proc:set_timeouts(10000, 60000, 60000, 60000)
    local ok, werr = proc:write(input)
    if not ok then proc:kill(9); return nil, "write: " .. tostring(werr) end
    proc:shutdown("stdin")
    local out, rerr = proc:stdout_read_all()
    proc:wait()
    if not out then return nil, "read: " .. tostring(rerr) end
    return out
end

local function pem_blocks(text, kind)
    local out = {}
    local pat = "%-%-%-%-%-BEGIN " .. kind .. "%-%-%-%-%-.-%-%-%-%-%-END " .. kind .. "%-%-%-%-%-"
    for b in (text or ""):gmatch(pat) do out[#out + 1] = b .. "\n" end
    return out
end

-- The CA bundle, by subject: subject -> file holding that one certificate, and
-- the subjects that occur more than once.
local cas, duplicate = {}, {}
local workdir

local function run(argv)
    local proc, err = ngx_pipe.spawn(argv, { merge_stderr = true })
    if not proc then return nil, tostring(err) end
    proc:set_timeouts(10000, 60000, 60000, 60000)
    proc:shutdown("stdin")
    local out = proc:stdout_read_all()
    local ok, reason, status = proc:wait()
    if not ok then return nil, (out or "") .. " " .. tostring(reason) .. " " .. tostring(status) end
    return out or ""
end

-- returns true, or nil on a failure worth retrying
local function index_bundle(text)
    if not workdir then
        local dir = "/tmp/pqc-migration-crl-" .. ngx.worker.pid()
        run({ "/bin/rm", "-rf", dir })
        -- mkdir fails if anything already sits at that name: no symlink is followed.
        local _, err = run({ "/bin/mkdir", "-m", "700", dir })
        if err then
            ngx.log(ngx.ERR, "[migration_crl] cannot create ", dir, ": ", err)
            return nil
        end
        workdir = dir
    end
    local by, dup = {}, {}
    for i, pem in ipairs(pem_blocks(text, "CERTIFICATE")) do
        local out, err = openssl({ "x509", "-noout", "-subject", "-nameopt", "RFC2253" }, pem)
        if not out then
            ngx.log(ngx.ERR, "[migration_crl] reading ", CA_BUNDLE, ": ", err)
            return nil
        end
        local subject = out:match("subject=([^\n]+)")
        if subject then
            local path = workdir .. "/ca-" .. i .. ".pem"
            local f = io.open(path, "w")
            if not f then return nil end
            f:write(pem); f:close()
            if by[subject] then dup[subject] = true end
            by[subject] = path
        end
    end
    for s in pairs(dup) do
        ngx.log(ngx.ERR, "[migration_crl] two certificates named ", s, " in ", CA_BUNDLE,
            ": no CRL is used for that name, its clients are refused (no_crl_for_issuer)")
    end
    cas, duplicate = by, dup
    return true
end

local function remember_issuer(dict, issuer)
    local list = cjson.decode(dict:get("issuers") or "") or {}
    for _, i in ipairs(list) do if i == issuer then return end end
    list[#list + 1] = issuer
    local ok, err = dict:safe_set("issuers", cjson.encode(list))
    if not ok then ngx.log(ngx.ERR, "[migration_crl] issuer index: ", err) end
end

local function mark_unusable(dict, issuer, why)
    dict:delete("meta|" .. issuer)
    ngx.log(ngx.ERR, "[migration_crl] no usable CRL for ", issuer, ": ", why)
end

-- Load one PEM CRL block. Returns "ok", "bad" (stays bad until the file
-- changes) or nil (transient: retry next tick).
local function load_block(block, source)
    local dict = ngx.shared.migration_crl
    local out, err = openssl({ "crl", "-noout", "-issuer", "-nameopt", "RFC2253" }, block)
    if not out then
        ngx.log(ngx.ERR, "[migration_crl] ", source, ": ", err)
        return nil
    end
    local issuer = out:match("issuer=([^\n]+)")
    if not issuer then
        ngx.log(ngx.ERR, "[migration_crl] unreadable CRL in ", source)
        return "bad"
    end
    if duplicate[issuer] then
        mark_unusable(dict, issuer, "two CA certificates in the bundle carry this name")
        return "bad"
    end
    if not cas[issuer] then
        ngx.log(ngx.ERR, "[migration_crl] CRL of ", issuer, " in ", source,
            ": no CA certificate of that name in ", CA_BUNDLE, "; ignored")
        return "bad"
    end
    out, err = openssl({ "crl", "-CAfile", cas[issuer], "-noout", "-nextupdate", "-text" }, block)
    if not out then
        ngx.log(ngx.ERR, "[migration_crl] ", source, ": ", err)
        return nil
    end
    if not out:find("verify OK", 1, true) then
        ngx.log(ngx.ERR, "[migration_crl] a CRL in ", source, " claiming issuer ", issuer,
            " does not verify against that CA's certificate; ignored")
        return "bad"
    end
    -- Revocations first: from any verified CRL, however old, they only add refusals.
    local count, lost = 0, nil
    for raw in out:gmatch("Serial Number:%s*(%-?[0-9A-Fa-f:]+)") do
        count = count + 1
        local ok, serr = dict:safe_set("rev|" .. issuer .. "|" .. raw:gsub(":", ""):lower(), true)
        if not ok then lost = serr end
    end
    remember_issuer(dict, issuer)
    if lost then
        mark_unusable(dict, issuer, "revocations not stored (" .. tostring(lost) .. "); lua_shared_dict migration_crl is too small")
        return "bad"
    end
    local nu = parse_time(out:match("nextUpdate=([^\n]+)"))
    local meta_key = "meta|" .. issuer
    local old = cjson.decode(dict:get(meta_key) or "")
    -- An older CRL must not roll the issuer's freshness back. A CRL without
    -- nextUpdate counts as stale (next_update 0).
    if old and (old.next_update or 0) > (nu or 0) then
        ngx.log(ngx.WARN, "[migration_crl] older CRL for ", issuer, " in ", source, ": revocations kept, freshness not")
        return "ok"
    end
    local ok, merr = dict:safe_set(meta_key, cjson.encode({
        issuer = issuer, next_update = nu or 0, loaded = ngx.time(), revoked = count, source = source }))
    if not ok then
        mark_unusable(dict, issuer, "state not stored (" .. tostring(merr) .. ")")
        return "bad"
    end
    return "ok"
end

local last_seen, last_bundle = {}, nil

local function poll(premature)
    if premature then return end
    local f = io.open(CA_BUNDLE, "r")
    local bundle = f and f:read("*a")
    if f then f:close() end
    if bundle and bundle ~= last_bundle then
        if index_bundle(bundle) then
            last_bundle = bundle
            last_seen = {} -- the CAs changed: verify every CRL again
        end
    end
    if last_bundle then
        for _, src in ipairs(SOURCES) do
            f = io.open(src, "r")
            local text = f and f:read("*a")
            if f then f:close() end
            if text and text ~= last_seen[src] then
                local blocks = pem_blocks(text, "X509 CRL")
                local retry, bad = false, 0
                for _, b in ipairs(blocks) do
                    local r = load_block(b, src)
                    if r == nil then retry = true elseif r == "bad" then bad = bad + 1 end
                end
                ngx.log(ngx.WARN, "[migration_crl] ", src, ": ", #blocks, " CRL(s), ", bad, " not used",
                    retry and ", retrying" or "")
                -- Remembered only when nothing needs retrying: a CRL that failed for
                -- a passing reason is read again on the next tick.
                if not retry then last_seen[src] = text end
            end
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
-- nothing to revoke, and an unverified one never reaches this phase. Only the
-- leaf is checked; an intermediate is withdrawn by removing it from the bundle.
function M.check()
    if ngx.var.ssl_client_verify ~= "SUCCESS" then return end
    local issuer = ngx.var.ssl_client_i_dn or ""
    local serial = (ngx.var.ssl_client_serial or ""):lower()
    local dict = ngx.shared.migration_crl
    local who = "serial " .. serial .. " from " .. issuer
    -- A known revocation refuses whatever the issuer's state.
    if dict:get("rev|" .. issuer .. "|" .. serial) then
        return refuse(403, "certificate_revoked", who)
    end
    local meta = cjson.decode(dict:get("meta|" .. issuer) or "")
    if not meta then
        if ngx.var.pqc_migration_crl_required == "off" then return end
        return refuse(403, "no_crl_for_issuer", who)
    end
    if ngx.time() > (meta.next_update or 0) and ngx.var.pqc_migration_crl_stale ~= "accept" then
        return refuse(403, "crl_stale", who)
    end
end

-- For the inventory: what is loaded, per issuer.
function M.status()
    local dict = ngx.shared.migration_crl
    local out = {}
    for _, issuer in ipairs(cjson.decode(dict:get("issuers") or "") or {}) do
        local m = cjson.decode(dict:get("meta|" .. issuer) or "")
        out[#out + 1] = m and {
            issuer = issuer, next_update = m.next_update, loaded = m.loaded, revoked = m.revoked,
            source = m.source, stale = ngx.time() > (m.next_update or 0),
        } or { issuer = issuer, usable = false }
    end
    return out
end

return M
