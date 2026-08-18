-- cert_fingerprint.lua
-- Single source of truth for the client-certificate fingerprint used across the
-- gateway.  Computes the SHA-256 digest of the DER-encoded client certificate,
-- matching `openssl x509 -fingerprint -sha256` and the 64-char lowercase hex
-- value the management-api expects in ADMIN_CERT_FINGERPRINTS.
--
-- Why this module exists:
--   nginx's built-in $ssl_client_fingerprint is SHA-1 (40 hex chars,
--   cryptographically broken).  The control plane authorizes admins by a
--   SHA-256 (64 hex char) allowlist, so emitting SHA-1 anywhere causes a
--   permanent 403 mismatch.  Centralising the derivation here guarantees every
--   call site (admin_jwt.lua, policy_router.lua, ...) hashes identically.
--
-- Implementation notes:
--   * Uses resty.sha256 + lua-resty-string, both bundled with OpenResty.
--   * Input is $ssl_client_escaped_cert (URL-encoded PEM) so we never depend on
--     a SHA-1 variable nor shell out to openssl on the request path.

local resty_sha256 = require("resty.sha256")
local resty_str    = require("resty.string")

local _M = { _VERSION = "1.0.0" }

-- Decode the URL-encoded PEM that nginx exposes as $ssl_client_escaped_cert
-- into the raw DER bytes of the certificate.
-- Returns: der (string) on success, or nil + error message.
local function escaped_pem_to_der(escaped)
    if not escaped or escaped == "" then
        return nil, "no client certificate present"
    end

    -- URL-decode %XX escapes back to the original PEM text.
    local cert_pem = escaped:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)

    -- Strip PEM armor ("-----BEGIN/END CERTIFICATE-----") and all whitespace,
    -- leaving a pure base64 body.
    local b64 = cert_pem
        :gsub("%-%-%-%-%-[^\r\n]+%-%-%-%-%-", "")
        :gsub("[\r\n%s]", "")

    if b64 == "" then
        return nil, "certificate PEM body was empty after stripping armor"
    end

    local der = ngx.decode_base64(b64)
    if not der or #der == 0 then
        return nil, "failed to base64-decode certificate DER"
    end

    -- A DER-encoded X.509 certificate is always an ASN.1 SEQUENCE (tag 0x30).
    -- Reject anything else outright rather than hashing arbitrary bytes as if
    -- they were a genuine certificate, fail closed on malformed input.
    if der:byte(1) ~= 0x30 then
        return nil, "decoded certificate data is not a valid DER SEQUENCE (bad tag byte)"
    end

    return der
end

-- Compute the lowercase-hex SHA-256 fingerprint of the verified client cert.
-- `escaped` defaults to ngx.var.ssl_client_escaped_cert when omitted.
-- Returns: fingerprint (64-char lowercase hex) on success, or nil + error.
function _M.client_sha256(escaped)
    escaped = escaped or ngx.var.ssl_client_escaped_cert
    local der, err = escaped_pem_to_der(escaped)
    if not der then
        return nil, err
    end

    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil, "failed to create SHA-256 context"
    end
    sha256:update(der)

    -- to_hex yields lowercase hex; the management-api normalises to lowercase
    -- too, so the comparison is exact and case-insensitive regardless.
    return resty_str.to_hex(sha256:final())
end

return _M
