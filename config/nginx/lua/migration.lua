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
-- presented one that verified, otherwise "ip:<address>". Under
-- ssl_verify_client optional a client can leave its certificate out and is then
-- judged by its address and the "default" policy (README.md).
--
-- Inventory (shared dict migration_inventory): one JSON record per identity and
-- endpoint (the listener's server_name and port, never the client's Host),
-- served on the control-plane listener at /migration/inventory behind the
-- control-plane HMAC.

local cjson = require "cjson.safe"
local telemetry = require "tls_telemetry"
local cert_fingerprint = require "cert_fingerprint"
local hmac = require "hmac_sha256"

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

-- classify(t, has_client_cert, resumed) -> class, details
-- t comes from tls_telemetry.collect(): group, local_sig, peer_sig, peer_key.
-- A resumed session ran no CertificateVerify, so which server certificate the
-- original handshake used is unknown: such a connection is at most pq-kex. If
-- it could reach pq, a client could make its first handshake with the classical
-- certificate and resume its way past pq-required. listener.conf.example turns
-- resumption off so that every connection is judged on a full handshake.
function M.classify(t, has_client_cert, resumed)
    local d = { group = t.group or "", server_sig = t.local_sig or "",
                client_sig = t.peer_sig or "", client_key = t.peer_key or "" }
    if resumed == nil then resumed = (d.server_sig == "" and d.group ~= "") end
    d.resumed = resumed
    if PQ_GROUPS[d.group] ~= true then return "classical", d end
    if resumed then return "pq-kex", d end
    local client_pq = (not has_client_cert) or pq_name(d.client_sig) or pq_name(d.client_key)
    if pq_name(d.server_sig) and client_pq then return "pq", d end
    return "pq-kex", d
end

-- The certificate is the identity only once it has verified: an unverified one
-- (refused by nginx before the access phase, but still seen by the log phase)
-- would let anyone create inventory records under any name.
function M.identity()
    if ngx.var.ssl_client_verify == "SUCCESS" then
        local fp = cert_fingerprint.client_sha256()
        if fp then return "sha256:" .. fp, true end
    end
    return "ip:" .. (ngx.var.remote_addr or "?"), false
end

local function judge()
    local id = M.identity()
    local t = telemetry.collect() or {}
    local has_cert = (t.peer_key or "") ~= ""
    local class, d = M.classify(t, has_cert, ngx.var.ssl_session_reused == "r")
    return id, class, d, has_cert
end

-- Access phase: classify, apply the policy, tell the backend.
function M.access()
    local id, class, d, has_cert = judge()
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

local last_full_warning = 0

-- Log phase: inventory record per identity and endpoint. Counts are per request
-- and best effort (read-modify-write across workers can lose an increment).
function M.log()
    local m = ngx.ctx.migration
    if not m then
        -- refused before the access phase (no or bad certificate): still classify
        local id, class, d, has_cert = judge()
        m = { id = id, class = class, d = d, has_cert = has_cert }
        ngx.var.pqc_pq_class = class
    end
    local inv = ngx.shared.migration_inventory
    local endpoint = (ngx.var.server_name or "") .. ":" .. (ngx.var.server_port or "")
    local key = m.id .. "|" .. endpoint
    local now = ngx.time()
    local rec = cjson.decode(inv:get(key) or "") or { identity = m.id, endpoint = endpoint, first_seen = now, count = 0 }
    rec.last_seen = now
    rec.count = (rec.count or 0) + 1
    rec.class = m.class
    -- Requests per class: one identity can show several (an address behind
    -- which several clients sit, or a client mid-migration).
    rec.classes = type(rec.classes) == "table" and rec.classes or {}
    rec.classes[m.class] = (rec.classes[m.class] or 0) + 1
    rec.group = m.d.group
    if m.d.server_sig ~= "" then rec.server_sig = m.d.server_sig end
    if m.d.client_sig ~= "" then rec.client_sig = m.d.client_sig end
    rec.client_key = m.d.client_key ~= "" and m.d.client_key or rec.client_key
    rec.resumed = m.d.resumed or nil
    rec.verify = ngx.var.ssl_client_verify
    if m.has_cert and rec.verify == "SUCCESS" then
        rec.client_cn = ngx.var.ssl_client_s_dn
        rec.client_issuer = ngx.var.ssl_client_i_dn
        rec.client_not_after = ngx.var.ssl_client_v_end
    end
    rec.tls = ngx.var.ssl_protocol
    -- safe_set: a full dictionary refuses new records instead of evicting old ones.
    local ok, err = inv:safe_set(key, cjson.encode(rec))
    if not ok and now - last_full_warning >= 60 then
        last_full_warning = now
        ngx.log(ngx.WARN, "[migration] inventory not recording new clients: ", err)
    end
end

-- /migration/inventory on the control-plane listener.
function M.inventory_json()
    local inv = ngx.shared.migration_inventory
    local out = {}
    for _, k in ipairs(inv:get_keys(0)) do
        local r = cjson.decode(inv:get(k) or "")
        if r then out[#out + 1] = r end
    end
    table.sort(out, function(a, b)
        return (a.identity or "") .. (a.endpoint or "") < (b.identity or "") .. (b.endpoint or "")
    end)
    return cjson.encode({ generated = ngx.time(), records = out })
end

-- The inventory names clients, so reading it needs the control-plane HMAC, the
-- scheme lua/control_plane.lua uses: X-Timestamp (unix seconds, within 5
-- minutes) and X-Hub-Signature-256 = "sha256=" .. hex(HMAC(key,
-- timestamp .. "\n" .. method .. "\n" .. uri .. "\n" .. body)), body empty here.
function M.inventory_authorized()
    local secret = ngx.shared.pqc_route_meta:get("cp_hmac_key")
    local ts = ngx.var.http_x_timestamp
    local sig = (ngx.var.http_x_hub_signature_256 or ""):match("^sha256=(%x+)$")
    if not secret or not sig or not ts or not ts:match("^%d+$") then return false end
    if math.abs(ngx.time() - tonumber(ts)) > 300 then return false end
    local want = hmac.hex(secret, ts .. "\n" .. ngx.req.get_method() .. "\n" .. ngx.var.uri .. "\n")
    sig = sig:lower()
    if not want or #want ~= #sig then return false end
    local acc = 0
    for i = 1, #want do acc = bit.bor(acc, bit.bxor(want:byte(i), sig:byte(i))) end
    return acc == 0
end

-- Worker start (and every reload): load the policy file, a JSON object
-- identity -> policy plus an optional "default". No file: everyone is observed
-- (a removed file takes effect at the next reload; the dictionary outlives it).
-- A malformed file keeps the policy already loaded. Unknown values are ignored
-- with a warning; fingerprints are matched in lower case.
function M.load_policy(path)
    local dict = ngx.shared.migration_policy
    local f = io.open(path, "r")
    if not f then dict:flush_all(); return end
    local p = cjson.decode(f:read("*a") or "")
    f:close()
    if type(p) ~= "table" then
        ngx.log(ngx.ERR, "[migration] ", path, " is not a JSON object; the previous policy stays")
        return
    end
    dict:flush_all()
    for k, v in pairs(p) do
        k = tostring(k)
        if k:sub(1, 7) == "sha256:" then k = k:lower() end
        if v ~= "observe" and v ~= "pq-required" then
            ngx.log(ngx.WARN, "[migration] ignoring policy ", k, "=", tostring(v))
        else
            local ok, err = dict:safe_set(k, v)
            if not ok then ngx.log(ngx.ERR, "[migration] policy not loaded for ", k, ": ", err) end
        end
    end
end

return M
