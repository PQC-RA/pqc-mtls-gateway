-- policy_router.lua
-- Routes incoming mTLS requests to the appropriate backend based on the
-- client certificate CN.  After a backend is selected, it signs two
-- short-lived RS256 JWTs carrying the verified client identity: Token 1
-- (aud=pqc-backend, key jwt_key_backend/kid=backend-v1) injected as
-- Authorization, for request attestation; and Token 2 (aud=pqc-cert-lookup,
-- key jwt_key_lookup/kid=lookup-v1) injected as X-PQC-Lookup-Token, scoped
-- solely to management-api's cert-by-fingerprint lookup route so Token 1 is
-- never accepted there (JWT audience confusion, RFC 8725).

local cjson            = require("cjson.safe")
local jwt_rs256        = require("jwt_rs256")
local cert_fingerprint = require("cert_fingerprint")
local header_allowlist = require("header_allowlist")

-- Default-deny header allowlist, strips every inbound header except a small
-- fixed set before anything else runs. See header_allowlist.lua.
header_allowlist.enforce()

local ROUTES_DICT = ngx.shared.pqc_routes

-- Both minted JWTs (Token 1 backend-attestation and Token 2 cert-lookup) live
-- for this long: long enough for the proxied request to complete, short
-- enough to bound the replay window.
local JWT_TTL_SECONDS = 60

-- Mirrors control_plane.lua's json_error: every error body goes through
-- cjson.encode (never string-concatenation) so a value that reaches this
-- point from client-controlled input (e.g. the CN below) can't break out of
-- the JSON structure, and every error response gets a Content-Type.
local function json_error(status, code, extra)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    local body = { error = code }
    if extra then
        for k, v in pairs(extra) do
            body[k] = v
        end
    end
    ngx.say(cjson.encode(body))
    return ngx.exit(status)
end

-- Active Enforcement Layer (Asynchronous Non-Blocking Revocation Check)
local client_serial = ngx.var.ssl_client_serial
if client_serial then
    local is_revoked = ngx.shared.pqc_route_meta:get("revoked_:" .. string.lower(client_serial))
    if is_revoked then
        ngx.log(ngx.WARN, "CRITICAL PROTECTION: Dropping revoked PQC client serial: ", client_serial)
        return ngx.exit(444)
    end
end

-- ── Helpers ──────────────────────────────────────────────────────────────────

local function extract_cn(dn)
    return dn and dn:match("CN=([^,/]+)") or ""
end

-- ── Route resolution ─────────────────────────────────────────────────────────

-- Escape Lua pattern metacharacters in a string so it can be used as a
-- plain prefix in uri:find().  Prevents confused-deputy routing attacks
-- when route paths stored in the shared dict contain special characters.
local function escape_pattern(s)
    return s:gsub("([%.%+%-%*%?%[%]%^%$%(%)%%])", "%%%1")
end

local raw = ROUTES_DICT:get("routes:json")
if not raw then
    return json_error(403, "no_routes_loaded")
end

local routes, decode_err = cjson.decode(raw)
if not routes or type(routes.clients) ~= "table" then
    ngx.log(ngx.ERR, "[policy_router] routes:json failed to decode: ", tostring(decode_err))
    return json_error(403, "no_routes_loaded")
end

local s_dn   = ngx.var.ssl_client_s_dn or ""
local cn     = extract_cn(s_dn)

local client = routes.clients[cn]
if not client then
    return json_error(403, "unauthorized_client", { cn = cn })
end

local uri                     = ngx.var.uri
local selected_backend        = nil
local selected_send_raw_cert  = false

if type(client.routes) == "table" then
    for _, route in ipairs(client.routes) do
        if type(route) == "table" and route.path and route.backend then
            if uri:find("^" .. escape_pattern(route.path)) then
                selected_backend       = route.backend
                selected_send_raw_cert = route.sendRawCert == true
                break
            end
        end
    end
end

if not selected_backend and client.backend then
    local allowed = false
    if type(client.allowed_paths) == "table" then
        for _, path in ipairs(client.allowed_paths) do
            if uri:find("^" .. escape_pattern(path)) then
                allowed = true
                break
            end
        end
    else
        allowed = true
    end

    if allowed then
        selected_backend       = client.backend
        selected_send_raw_cert = client.sendRawCert == true
    end
end

if not selected_backend then
    return json_error(403, "path_not_allowed")
end

ngx.var.pqc_backend = selected_backend
ngx.var.pqc_cn      = cn

-- Narrow, self-contained opt-in, not the full policy schema.
-- Route-level sendRawCert overrides the
-- client-level default, exactly like backend resolution above. Strict ==
-- true (not a loose truthy check) so a config typo like "sendRawCert": "true"
-- (string) can't silently re-enable this. The unconditional
-- proxy_set_header X-Client-Cert line is absent from nginx.conf by design;
-- this is an explicit, logged, per-backend exception to that.
if selected_send_raw_cert then
    ngx.req.set_header("X-Client-Cert", ngx.var.ssl_client_escaped_cert)
    ngx.log(ngx.WARN, "[policy_router] sendRawCert enabled for cn=", cn,
        " backend=", selected_backend, ", forwarding raw client certificate")
end

-- ── Per-client rate limiting ─────────────────────────────────────────────────
-- Enforced after the backend/CN is resolved (so an unknown/denied CN never
-- reaches this check) and before the JWT is minted / the request is proxied.
-- Atomic per-second fixed-window counter via ngx.shared.pqc_rate:incr(),
-- avoids the read-modify-write race a get()/set() pair would have. Each
-- window's key carries its own 2s TTL so slots self-expire; no cleanup needed.
local rps = (client.rate_limit and client.rate_limit.rps)
    or (routes.defaults and routes.defaults.rate_limit and routes.defaults.rate_limit.rps)
    or 50

local rl   = ngx.shared.pqc_rate
local slot = math.floor(ngx.now())
local key  = "rl:" .. cn .. ":" .. slot
local n, rl_err = rl:incr(key, 1, 0, 2) -- init 0, ttl 2s so slots self-expire
if not n then
    -- Fail OPEN on a shared-dict error (availability), but log loudly so a
    -- persistently broken dict doesn't silently disable rate limiting.
    ngx.log(ngx.ERR, "[rate] shared dict error: ", tostring(rl_err))
elseif n > rps then
    ngx.header["Retry-After"] = "1"
    return json_error(429, "rate_limited", { message = "per-client request rate exceeded" })
end

-- ── RS256 JWT signing & injection ────────────────────────────────────────────
-- Now that the client is authenticated and a backend is chosen, mint a
-- short-lived RS256 JWT attesting the client identity.  This gives the backend
-- a cryptographically verifiable identity handoff instead of plain headers.
--
-- The JWT is valid for 60 seconds, enough for the proxied request to complete
-- while limiting the window for replay attacks.

-- Derive the SHA-256 certificate fingerprint (NOT nginx's SHA-1
-- $ssl_client_fingerprint) so the fpr claim is uniform with admin_jwt.lua and
-- the management-api allowlist.  A SHA-1 value here would silently mismatch any
-- backend that authorizes on fpr.  Fail closed if it cannot be derived.
local fpr, fpr_err = cert_fingerprint.client_sha256()
if not fpr then
    ngx.log(ngx.ERR, "[policy_router] could not derive client SHA-256 fingerprint: ",
        tostring(fpr_err), ", refusing to proxy without a verifiable identity")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local now = ngx.now()
local payload = {
    iss  = "pqc-gateway",
    aud  = "pqc-backend",    -- backend attestation; NOT accepted by the admin API
    sub  = cn,               -- client Common Name from mTLS cert
    fpr  = fpr,              -- SHA-256(DER), uniform with the admin allowlist
    iat  = math.floor(now),
    exp  = math.floor(now) + JWT_TTL_SECONDS,
}

local pem = ngx.shared.pqc_route_meta:get("jwt_key_backend")
if not pem then
    -- The signing key must be populated by init_by_lua_block at startup.
    -- If it is missing here the shared dict was not initialised correctly;
    -- proxying without JWT attestation would violate the identity contract.
    ngx.log(ngx.ERR, "[jwt_rs256] Signing key absent from shared dict, refusing to proxy without JWT attestation")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local token, sign_err = jwt_rs256.sign(pem, payload, "backend-v1")
if not token then
    ngx.log(ngx.ERR, "[jwt_rs256] Signing failed: ", sign_err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

ngx.req.set_header("Authorization", "Bearer " .. token)

-- ── Token 2: purpose-scoped cert-lookup token ────────────────────────────────
-- Do NOT reuse Token 1 for the cert-lookup call, its audience (pqc-backend)
-- is stated for request-attestation verifiers, and accepting it at
-- management-api's lookup route would be JWT audience confusion (RFC 8725).
-- Signed with a dedicated key (jwt_key_lookup / kid=lookup-v1) distinct from
-- both Token 1's backend key and the admin key, so a compromised lookup key
-- can be rotated without invalidating in-flight admin or backend tokens.
-- Injected as its own header, separate from Authorization, which keeps
-- carrying Token 1 unchanged.
local lookup_payload = {
    iss = "pqc-gateway",
    aud = "pqc-cert-lookup",
    sub = cn,
    fpr = fpr,
    iat = math.floor(now),
    exp = math.floor(now) + JWT_TTL_SECONDS,
}

local lookup_pem = ngx.shared.pqc_route_meta:get("jwt_key_lookup")
if not lookup_pem then
    ngx.log(ngx.ERR, "[jwt_rs256] Lookup signing key absent from shared dict, refusing to proxy without Token 2 attestation")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local lookup_token, lookup_sign_err = jwt_rs256.sign(lookup_pem, lookup_payload, "lookup-v1")
if not lookup_token then
    ngx.log(ngx.ERR, "[jwt_rs256] Lookup token signing failed: ", lookup_sign_err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

ngx.req.set_header("X-PQC-Lookup-Token", lookup_token)
