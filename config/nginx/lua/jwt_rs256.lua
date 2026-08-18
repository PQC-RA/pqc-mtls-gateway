-- jwt_rs256.lua
-- RS256 JWT signer implemented entirely with LuaJIT FFI bindings to
-- OpenSSL's libcrypto, which is already loaded into the process by
-- OpenResty.  No external Lua packages are required.
--
-- Public API:
--   local jwt = require("jwt_rs256")
--   local token, err = jwt.sign(private_key_pem, payload_table)
--   -- token is the complete "header.payload.signature" JWT string
--   -- err   is nil on success, a string message on failure
--
-- Security notes:
--   * Algorithm is hardcoded to RS256 (RSASSA-PKCS1-v1_5 + SHA-256).
--     The "alg" header field is never derived from user input.
--   * The private key string is expected to be a PEM-encoded PKCS#8 or
--     traditional RSA private key.  It is not cached here; callers should
--     cache the PEM at the module or shared-dict level.

local ffi  = require("ffi")
local cjson = require("cjson.safe")

-- ── FFI declarations ─────────────────────────────────────────────────────────
ffi.cdef([[
  void OPENSSL_cleanse(void *ptr, size_t len);

  /* BIO */
  typedef struct bio_st BIO;
  BIO *BIO_new_mem_buf(const void *buf, int len);
  int  BIO_free(BIO *a);

  /* EVP_PKEY */
  typedef struct evp_pkey_st EVP_PKEY;
  EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                    void *cb, void *u);
  void EVP_PKEY_free(EVP_PKEY *pkey);

  /* EVP_MD */
  typedef struct evp_md_st EVP_MD;
  const EVP_MD *EVP_sha256(void);

  /* EVP_MD_CTX */
  typedef struct evp_md_ctx_st EVP_MD_CTX;
  EVP_MD_CTX *EVP_MD_CTX_new(void);
  void        EVP_MD_CTX_free(EVP_MD_CTX *ctx);

  int EVP_DigestSignInit(EVP_MD_CTX *ctx, void **pctx,
                         const EVP_MD *type, void *e, EVP_PKEY *pkey);
  int EVP_DigestSignUpdate(EVP_MD_CTX *ctx,
                           const void *d, size_t cnt);
  int EVP_DigestSignFinal(EVP_MD_CTX *ctx,
                          unsigned char *sigret, size_t *siglen);
]])

-- Load libcrypto, OpenResty already has it in process memory; ffi.load
-- returns the already-loaded handle without a second dlopen().
local crypto = ffi.load("crypto")

-- ── Helpers ──────────────────────────────────────────────────────────────────

--- base64url-encode a byte string (no padding, URL-safe alphabet).
local function b64url(s)
    local b64 = ngx.encode_base64(s)
    -- Convert standard base64 → base64url and strip padding.
    return b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
end

--- JSON-encode a table then base64url-encode the result.
local function b64url_json(tbl)
    local json, err = cjson.encode(tbl)
    if not json then
        return nil, "json encode: " .. (err or "unknown")
    end
    return b64url(json)
end

-- ── Public: sign ─────────────────────────────────────────────────────────────

local M = {}

--- Sign a JWT with RS256.
-- @param pem_key  string  PEM-encoded RSA private key (PKCS#8 or traditional)
-- @param payload  table   JWT claims table (sub, role, iat, exp, ...)
-- @param kid      string  key ID to embed in the header, identifying which of
--                         the gateway's published JWKS keys verifies this
--                         token (e.g. "admin-v1", "backend-v1", "lookup-v1")
-- @return token string, nil       on success
-- @return nil,   err string       on failure
function M.sign(pem_key, payload, kid)
    if type(pem_key) ~= "string" or #pem_key == 0 then
        return nil, "pem_key must be a non-empty string"
    end
    if type(payload) ~= "table" then
        return nil, "payload must be a table"
    end

    -- 1. Build header + payload segments.
    local header = { alg = "RS256", typ = "JWT", kid = kid or "gw-rs256-v1" }
    local hdr_b64, err1 = b64url_json(header)
    if not hdr_b64 then return nil, err1 end

    local pay_b64, err2 = b64url_json(payload)
    if not pay_b64 then return nil, err2 end

    local signing_input = hdr_b64 .. "." .. pay_b64

    -- Allocate unmanaged buffer for private key to allow secure cleansing
    local pem_len = #pem_key
    local pem_buf = ffi.new("unsigned char[?]", pem_len)
    ffi.copy(pem_buf, pem_key, pem_len)

    -- 2. Load private key from PEM.
    local bio = crypto.BIO_new_mem_buf(pem_buf, pem_len)
    if bio == nil then
        crypto.OPENSSL_cleanse(pem_buf, pem_len)
        return nil, "BIO_new_mem_buf failed"
    end

    local pkey = crypto.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
    crypto.BIO_free(bio)
    crypto.OPENSSL_cleanse(pem_buf, pem_len)

    if pkey == nil then
        return nil, "PEM_read_bio_PrivateKey failed (invalid PEM?)"
    end

    -- 3. Create digest-sign context.
    local md_ctx = crypto.EVP_MD_CTX_new()
    if md_ctx == nil then
        crypto.EVP_PKEY_free(pkey)
        return nil, "EVP_MD_CTX_new failed"
    end

    local sha256 = crypto.EVP_sha256()
    local rc = crypto.EVP_DigestSignInit(md_ctx, nil, sha256, nil, pkey)
    if rc ~= 1 then
        crypto.EVP_MD_CTX_free(md_ctx)
        crypto.EVP_PKEY_free(pkey)
        return nil, "EVP_DigestSignInit failed (rc=" .. rc .. ")"
    end

    -- 4. Feed the signing input.
    rc = crypto.EVP_DigestSignUpdate(md_ctx, signing_input, #signing_input)
    if rc ~= 1 then
        crypto.EVP_MD_CTX_free(md_ctx)
        crypto.EVP_PKEY_free(pkey)
        return nil, "EVP_DigestSignUpdate failed"
    end

    -- 5. Determine signature length, then produce signature.
    local siglen = ffi.new("size_t[1]", 0)
    rc = crypto.EVP_DigestSignFinal(md_ctx, nil, siglen)
    if rc ~= 1 then
        crypto.EVP_MD_CTX_free(md_ctx)
        crypto.EVP_PKEY_free(pkey)
        return nil, "EVP_DigestSignFinal (size query) failed"
    end

    local sig_buf = ffi.new("unsigned char[?]", siglen[0])
    rc = crypto.EVP_DigestSignFinal(md_ctx, sig_buf, siglen)

    crypto.EVP_MD_CTX_free(md_ctx)
    crypto.EVP_PKEY_free(pkey)

    if rc ~= 1 then
        crypto.OPENSSL_cleanse(sig_buf, siglen[0])
        return nil, "EVP_DigestSignFinal (sign) failed"
    end

    -- 6. Base64url-encode the signature and assemble the JWT.
    local sig_str = ffi.string(sig_buf, siglen[0])
    crypto.OPENSSL_cleanse(sig_buf, siglen[0])
    local sig_b64 = b64url(sig_str)

    return signing_input .. "." .. sig_b64, nil
end

return M
