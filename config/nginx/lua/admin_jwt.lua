-- admin_jwt.lua
-- Runs in access_by_lua for the /admin/ location. Mints a short-lived JWT
-- attesting the verified mTLS client identity and injects it as the
-- Authorization header for the management-api, which authorizes the caller
-- against an explicit certificate-fingerprint allowlist.
--
-- Signer and kid come from configuration (ADR-022): ADMIN_JWT_KID=admin-v1
-- (default, RS256, jwt_rs256.lua) or admin-v2 (ML-DSA-65, jwt_mldsa.lua),
-- read once by init_by_lua into the shared dict. Both carry jti (single use at
-- the API) and htm/htu, binding the token to this request's method and to the
-- path the API receives after the proxy_pass rewrite below.
--
-- Key handling:
--   * The signing key is read from the shared dict (populated by
--     init_by_lua_block from the Docker secret), NOT from a baked file path
--     that does not exist in the runtime image.
--   * Any client-supplied Authorization header is cleared first, so a client
--     can never smuggle its own bearer token past the gateway.
--   * Fails CLOSED: if the client cert did not verify, or the key is missing,
--     or signing fails, the request is rejected instead of being proxied
--     without (or with a spoofed) attestation.
--   * Emits fpr (cert SHA-256 fingerprint), iss and aud claims.
--   * Uses SHA-256 (not nginx's built-in $ssl_client_fingerprint which is SHA-1).

local jwt_rs256        = require("jwt_rs256")
local jwt_mldsa        = require("jwt_mldsa")
local resty_random     = require("resty.random")
local cert_fingerprint = require("cert_fingerprint")
local header_allowlist = require("header_allowlist")

-- Default-deny header allowlist, strips every inbound header except a small
-- fixed set before anything else runs. Authorization is deliberately not in
-- that set, so a client cannot supply one: the only Authorization the backend
-- ever sees is the attestation minted at the end of this file. See
-- header_allowlist.lua.
header_allowlist.enforce()

-- Only mint attestation for a successfully verified mTLS client certificate.
if ngx.var.ssl_client_verify ~= "SUCCESS" then
    ngx.log(ngx.WARN, "[admin_jwt] client cert not verified (",
        tostring(ngx.var.ssl_client_verify), "), rejecting")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Active Enforcement: the same revocation check policy_router.lua runs, before
-- any attestation is minted. ssl_client_verify above reflects nginx's STATIC
-- ssl_crl, which only refreshes on reload; between a revocation and that reload
-- a revoked certificate still verifies as SUCCESS. crl_worker.lua writes the
-- serial into the shared dict ahead of the reload, so this is what closes that
-- window. Without it, /admin/ (the higher-privilege path, proxied to the
-- management-api with a freshly signed admin JWT) would be the one route
-- lacking the check that /api/ has.
local client_serial = ngx.var.ssl_client_serial
if client_serial then
    local revoked = ngx.shared.pqc_route_meta:get("revoked_:" .. string.lower(client_serial))
    if revoked then
        ngx.log(ngx.WARN, "CRITICAL PROTECTION: Dropping revoked PQC admin serial: ", client_serial)
        return ngx.exit(444)
    end
end

-- Expiry, per request: a keep-alive connection outlives the handshake check.
require("client_cert_expiry").refuse_if_expired("admin_jwt")

local function extract_cn(dn)
    if not dn then return "" end
    -- Exactly one "CN=" in the DN, read only at the start of an attribute: a
    -- value such as "emailAddress=xCN=victim" or a type such as "ISO-CN" must
    -- not be taken for the CN. Anything else yields no CN (refused upstream).
    local _, n = dn:lower():gsub("cn%s*=", "")
    if n ~= 1 then return "" end
    return dn:match("^CN=([^,/]+)") or dn:match(",CN=([^,/]+)") or ""
end

local function extract_ou(dn)
    return dn and dn:match("OU=([^,/]+)") or ""
end

local s_dn = ngx.var.ssl_client_s_dn or ""
local cn   = extract_cn(s_dn)
local ou   = extract_ou(s_dn)
-- A subject without exactly one CN gets no admin token (the API would refuse
-- one with sub="" anyway; refusing here keeps the decision local).
if cn == "" then
    ngx.log(ngx.WARN, "[admin_jwt] client DN without a single CN, refused: ", s_dn)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Compute SHA-256 fingerprint from the URL-encoded client cert PEM via the
-- shared helper.  nginx's built-in $ssl_client_fingerprint is SHA-1
-- (cryptographically broken) and would never match the control plane's SHA-256
-- allowlist, see cert_fingerprint.lua for the single source of truth.
-- Fingerprint = SHA-256(DER), matching `openssl x509 -fingerprint -sha256`.
local fpr, fpr_err = cert_fingerprint.client_sha256()
if not fpr then
    ngx.log(ngx.ERR, "[admin_jwt] could not derive client SHA-256 fingerprint: ",
        tostring(fpr_err), ", refusing to proxy")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local meta = ngx.shared.pqc_route_meta
local kid  = meta:get("admin_jwt_kid") or "admin-v1"
local pem
if kid == "admin-v2" then
    pem = meta:get("jwt_key_admin_v2")
elseif kid == "admin-v1" then
    pem = meta:get("jwt_key_admin")
end
if not pem then
    ngx.log(ngx.ERR, "[admin_jwt] signing key for ", tostring(kid), " absent from shared dict, refusing to proxy")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- htu: the path management-api receives. nginx.conf proxies location /admin/
-- to http://management-api:3000/api/admin/, which replaces the "/admin/" prefix
-- of the NORMALIZED uri ($uri) and sends the result re-escaped. A path made only
-- of characters nginx never escapes is sent byte for byte, so the API can
-- compare htu with what it received; anything else is refused here rather than
-- minted with a binding that would not match. The query string is not bound.
local uri = ngx.var.uri or ""
if uri:sub(1, 7) ~= "/admin/" or uri:find("[^%w%._~!%$&%(%)%*%+,;=:@/%-]") then
    ngx.log(ngx.WARN, "[admin_jwt] admin path with characters outside the bound set, refused")
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end
local htu = "/api/admin/" .. uri:sub(8)

local rnd = resty_random.bytes(16, true)
if not rnd then
    ngx.log(ngx.ERR, "[admin_jwt] no strong random bytes for jti, refusing to proxy")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end
local jti = (ngx.encode_base64(rnd):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))

-- CSRF / Origin: a gateway-side Origin check on mutating /admin/ methods is
-- deliberately NOT done here. Primary anti-CSRF enforcement lives in the
-- management-api, and a gateway Origin allowlist would risk breaking
-- non-browser admin tooling (issue-cert.sh, request-client-cert.sh, CI) which
-- sends no Origin header. If ever added, it must be env/shared-dict
-- configurable and skip requests with no Origin. Left to the API by design.
local now = ngx.now()
local payload = {
    iss  = "pqc-gateway",
    aud  = "pqc-mtls-management-api",
    sub  = cn,
    -- role claim retained for forward-compatibility. The
    -- management-api RBAC authorizes by a server-side fingerprint→role map, not
    -- this claim, so it is informational only, neither weakened nor expanded.
    role = ou:lower(),  -- informational only; authorization is by fpr allowlist
    fpr  = fpr,
    iat  = math.floor(now),
    exp  = math.floor(now) + 60,
    jti  = jti,
    htm  = ngx.req.get_method(),
    htu  = htu,
}

local token, sign_err
if kid == "admin-v2" then
    token, sign_err = jwt_mldsa.sign(pem, payload, "admin-v2")
else
    token, sign_err = jwt_rs256.sign(pem, payload, "admin-v1")
end
if not token then
    ngx.log(ngx.ERR, "[admin_jwt] signing failed: ", tostring(sign_err))
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

ngx.req.set_header("Authorization", "Bearer " .. token)
