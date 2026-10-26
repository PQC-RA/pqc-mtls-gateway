-- migration.lua: the migration listener's classification, policy and inventory.
--
-- The migration listener (config/nginx/migration/listener.conf.example) sits in
-- front of an existing service under the service's own name and port. It serves
-- post-quantum clients with ML-DSA-65 and X25519MLKEM768 and classical clients
-- with the service's classical certificate, and records what each client
-- actually negotiated. It refuses nobody for being classical unless the policy
-- says "pq-required" for that client.
--
-- Classes (per connection, from what the handshake negotiated):
--   pq          post-quantum key exchange, ML-DSA server signature, and either no
--               client certificate or an ML-DSA one: migrated
--   pq-kex      post-quantum key exchange, but a classical signature somewhere:
--               the traffic is protected against harvest-now-decrypt-later, the
--               identities are not yet post-quantum
--   classical   classical key exchange: fully exposed
--
-- Policy (shared dict migration_policy, loaded from policy.json at worker start):
--   key = client identity, value = "observe" (default) or "pq-required".
-- Identity = "sha256:<fingerprint of the client certificate>" when the client
-- presented one, otherwise "ip:<address>".
--
-- Inventory (shared dict migration_inventory): one JSON record per identity and
-- endpoint (Host), served on the control-plane listener at /migration/inventory.

local cjson = require "cjson.safe"
local telemetry = require "tls_telemetry"

local M = {}

-- Groups that include a post-quantum KEM (OpenSSL 3.5+ names).
local PQ_GROUPS = {
    X25519MLKEM768 = true, SecP256r1MLKEM768 = true, SecP384r1MLKEM1024 = true,
    MLKEM512 = true, MLKEM768 = true, MLKEM1024 = true,
}

local function pq_name(s)
    if not s or s == "" then return false end
    s = s:lower()
    return s:find("ml%-dsa", 1, false) ~= nil or s:find("mldsa", 1, true) ~= nil
        or s:find("slh%-dsa", 1, false) ~= nil
end

-- classify(t, has_client_cert) -> class, details
-- t comes from tls_telemetry.collect(): group, local_sig, peer_sig, peer_key.
-- On a resumed TLS 1.3 session no CertificateVerify runs, so the signatures are
-- empty: the class then rests on the key exchange and the client key type, and
-- details.resumed is set.
function M.classify(t, has_client_cert)
    local d = { group = t.group or "", server_sig = t.local_sig or "",
                client_sig = t.peer_sig or "", client_key = t.peer_key or "" }
    d.resumed = (d.server_sig == "" and d.group ~= "")
    local kex_pq = PQ_GROUPS[d.group] == true
    if not kex_pq then return "classical", d end
    local server_pq = pq_name(d.server_sig) or (d.resumed and nil)
    local client_pq = (not has_client_cert) or pq_name(d.client_sig) or pq_name(d.client_key)
    if server_pq == nil then
        -- resumed: the server signature is unknown; judge by the client side only
        return client_pq and "pq" or "pq-kex", d
    end
    if server_pq and client_pq then return "pq", d end
    return "pq-kex", d
end

function M.identity()
    local fp
    if ngx.var.ssl_client_escaped_cert and ngx.var.ssl_client_escaped_cert ~= "" then
        local ok, cf = pcall(require, "cert_fingerprint")
        if ok and cf.client_sha256 then fp = cf.client_sha256() end
    end
    if fp then return "sha256:" .. fp, true end
    return "ip:" .. (ngx.var.remote_addr or "?"), false
end

-- Access phase: classify, apply the policy, tell the backend.
function M.access()
    local id, has_cert = M.identity()
    local t = telemetry.collect() or {}
    local class, d = M.classify(t, has_cert)
    ngx.ctx.migration = { id = id, class = class, d = d, has_cert = has_cert }
    ngx.var.pqc_pq_class = class
    ngx.req.set_header("X-PQ-Class", class)
    local policy = ngx.shared.migration_policy:get(id) or ngx.shared.migration_policy:get("default") or "observe"
    if policy == "pq-required" and class ~= "pq" then
        ngx.log(ngx.WARN, "[migration] refused ", id, ": class ", class, " under pq-required")
        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ error = "pq_required", class = class }))
        return ngx.exit(403)
    end
end

-- Log phase: inventory record per identity and endpoint.
function M.log()
    local m = ngx.ctx.migration
    if not m then
        -- refused before the access phase (no or bad certificate): still classify
        local id, has_cert = M.identity()
        local t = telemetry.collect() or {}
        local class, d = M.classify(t, has_cert)
        m = { id = id, class = class, d = d, has_cert = has_cert }
        ngx.var.pqc_pq_class = class
    end
    local inv = ngx.shared.migration_inventory
    local key = m.id .. "|" .. (ngx.var.host or "")
    local now = ngx.time()
    local rec = cjson.decode(inv:get(key) or "") or { identity = m.id, endpoint = ngx.var.host, first_seen = now, count = 0 }
    rec.last_seen = now
    rec.count = (rec.count or 0) + 1
    rec.class = m.class
    -- Connections per class: one identity can show several (an address behind
    -- which several clients sit, or a client mid-migration).
    rec.classes = type(rec.classes) == "table" and rec.classes or {}
    rec.classes[m.class] = (rec.classes[m.class] or 0) + 1
    rec.group = m.d.group
    if m.d.server_sig ~= "" then rec.server_sig = m.d.server_sig end
    if m.d.client_sig ~= "" then rec.client_sig = m.d.client_sig end
    rec.client_key = m.d.client_key ~= "" and m.d.client_key or rec.client_key
    rec.client_cn = ngx.var.ssl_client_s_dn ~= "" and ngx.var.ssl_client_s_dn or rec.client_cn
    rec.client_not_after = ngx.var.ssl_client_v_end ~= "" and ngx.var.ssl_client_v_end or rec.client_not_after
    rec.tls = ngx.var.ssl_protocol
    local ok, err = inv:set(key, cjson.encode(rec))
    if not ok then ngx.log(ngx.WARN, "[migration] inventory full: ", err) end
end

-- /migration/inventory on the control-plane listener.
function M.inventory_json()
    local inv = ngx.shared.migration_inventory
    local out = {}
    for _, k in ipairs(inv:get_keys(0)) do
        local r = cjson.decode(inv:get(k) or "")
        if r then out[#out + 1] = r end
    end
    table.sort(out, function(a, b) return (a.identity .. a.endpoint) < (b.identity .. b.endpoint) end)
    return cjson.encode({ generated = ngx.time(), records = out })
end

-- Worker start: load the policy file (JSON object identity -> policy, plus an
-- optional "default"). Unknown values are ignored with a warning.
function M.load_policy(path)
    local f = io.open(path, "r")
    if not f then return end
    local p = cjson.decode(f:read("*a") or "")
    f:close()
    if type(p) ~= "table" then
        ngx.log(ngx.ERR, "[migration] ", path, " is not a JSON object; no policy loaded")
        return
    end
    local dict = ngx.shared.migration_policy
    dict:flush_all()
    for k, v in pairs(p) do
        if v == "observe" or v == "pq-required" then dict:set(k, v)
        else ngx.log(ngx.WARN, "[migration] ignoring policy ", tostring(k), "=", tostring(v)) end
    end
end

return M
