-- admin_jwt.lua
-- Runs in access_by_lua for the /admin/ location. Mints a short-lived RS256
-- JWT attesting the verified mTLS client identity and injects it as the
-- Authorization header for the management-api, which authorizes the caller
-- against an explicit certificate-fingerprint allowlist.
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

local function extract_cn(dn)
    return dn and dn:match("CN=([^,/]+)") or ""
end

local function extract_ou(dn)
    return dn and dn:match("OU=([^,/]+)") or ""
end

local s_dn = ngx.var.ssl_client_s_dn or ""
local cn   = extract_cn(s_dn)
local ou   = extract_ou(s_dn)

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

local pem = ngx.shared.pqc_route_meta:get("jwt_key_admin")
if not pem then
    ngx.log(ngx.ERR, "[admin_jwt] signing key absent from shared dict, refusing to proxy")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

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
}

local token, sign_err = jwt_rs256.sign(pem, payload, "admin-v1")
if not token then
    ngx.log(ngx.ERR, "[admin_jwt] signing failed: ", tostring(sign_err))
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

ngx.req.set_header("Authorization", "Bearer " .. token)
