-- jwt_mldsa.lua
-- ML-DSA-65 JWT signer (RFC 9964, JOSE "alg":"ML-DSA-65") through LuaJIT FFI
-- to the OpenSSL libcrypto OpenResty already has loaded. Same pattern as
-- jwt_rs256.lua; used for the admin token admin-v2 (ADR-022 decision 1).
--
-- Public API:
--   local jwt_mldsa = require("jwt_mldsa")
--   local token, err = jwt_mldsa.sign(private_key_pem, payload_table, kid)
--   local ok, err    = jwt_mldsa.check_key(private_key_pem)   -- startup self-test
--
-- What is fixed here, never taken from input:
--   * The header is exactly {"alg":"ML-DSA-65","typ":"JWT","kid":<kid>}, written
--     as a literal so its members and their order do not depend on cjson.
--   * Pure ML-DSA (not HashML-DSA) with an EMPTY context string (RFC 9964
--     section 5): EVP_DigestSignInit with a NULL digest, then one-shot
--     EVP_DigestSign over the ASCII signing input. No context or
--     message-encoding parameter is ever set, so OpenSSL's defaults apply
--     (empty context, FIPS 204 message encoding, hedged signing).
--   * The key must be an ML-DSA-65 key (EVP_PKEY_is_a) and the signature must
--     be 3,309 bytes, or the token is not produced.
-- The private key PEM is copied into a buffer that is cleansed after parsing.

local ffi   = require("ffi")
local cjson = require("cjson.safe")

-- jwt_rs256.lua declares several of the same types and functions in ONE
-- ffi.cdef block, and ffi.cdef refuses a redefinition. If this module declared
-- them first (init_by_lua_block loads it in the master, before any worker
-- requires jwt_rs256), that block would fail in every worker. So jwt_rs256 is
-- loaded first, and each declaration below is made on its own with a
-- redefinition ignored. A declaration that is genuinely missing still fails
-- loudly, at the first use below.
require("jwt_rs256")
local function cdef(decl) pcall(ffi.cdef, decl) end
cdef("void OPENSSL_cleanse(void *ptr, size_t len);")
cdef("typedef struct bio_st BIO;")
cdef("BIO *BIO_new_mem_buf(const void *buf, int len);")
cdef("int BIO_free(BIO *a);")
cdef("typedef struct evp_pkey_st EVP_PKEY;")
cdef("EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, void *cb, void *u);")
cdef("void EVP_PKEY_free(EVP_PKEY *pkey);")
cdef("int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);")
cdef("typedef struct evp_md_st EVP_MD;")
cdef("typedef struct evp_md_ctx_st EVP_MD_CTX;")
cdef("EVP_MD_CTX *EVP_MD_CTX_new(void);")
cdef("void EVP_MD_CTX_free(EVP_MD_CTX *ctx);")
cdef("int EVP_DigestSignInit(EVP_MD_CTX *ctx, void **pctx, const EVP_MD *type, void *e, EVP_PKEY *pkey);")
cdef("int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);")
cdef("int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, void **pctx, const EVP_MD *type, void *e, EVP_PKEY *pkey);")
cdef("int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);")

local crypto = ffi.load("crypto")

local ALG     = "ML-DSA-65"
local SIG_LEN = 3309

local M = { ALG = ALG, SIG_LEN = SIG_LEN }

local function b64url(s)
    return (ngx.encode_base64(s):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

local function load_key(pem_key)
    if type(pem_key) ~= "string" or #pem_key == 0 then
        return nil, "pem_key must be a non-empty string"
    end
    local pem_len = #pem_key
    local pem_buf = ffi.new("unsigned char[?]", pem_len)
    ffi.copy(pem_buf, pem_key, pem_len)
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
    if crypto.EVP_PKEY_is_a(pkey, ALG) ~= 1 then
        crypto.EVP_PKEY_free(pkey)
        return nil, "the key is not an " .. ALG .. " key"
    end
    return pkey
end

-- Pure ML-DSA, empty context: NULL digest and no parameters.
local function raw_sign(pkey, tbs)
    local ctx = crypto.EVP_MD_CTX_new()
    if ctx == nil then return nil, "EVP_MD_CTX_new failed" end
    if crypto.EVP_DigestSignInit(ctx, nil, nil, nil, pkey) ~= 1 then
        crypto.EVP_MD_CTX_free(ctx)
        return nil, "EVP_DigestSignInit failed"
    end
    local siglen = ffi.new("size_t[1]", 0)
    if crypto.EVP_DigestSign(ctx, nil, siglen, tbs, #tbs) ~= 1 then
        crypto.EVP_MD_CTX_free(ctx)
        return nil, "EVP_DigestSign (size query) failed"
    end
    local sig = ffi.new("unsigned char[?]", siglen[0])
    local rc = crypto.EVP_DigestSign(ctx, sig, siglen, tbs, #tbs)
    crypto.EVP_MD_CTX_free(ctx)
    if rc ~= 1 then return nil, "EVP_DigestSign failed" end
    if tonumber(siglen[0]) ~= SIG_LEN then
        return nil, "signature is " .. tostring(siglen[0]) .. " bytes, not " .. SIG_LEN
    end
    return ffi.string(sig, siglen[0])
end

local function raw_verify(pkey, tbs, sig)
    local ctx = crypto.EVP_MD_CTX_new()
    if ctx == nil then return false end
    local ok = crypto.EVP_DigestVerifyInit(ctx, nil, nil, nil, pkey) == 1
        and crypto.EVP_DigestVerify(ctx, sig, #sig, tbs, #tbs) == 1
    crypto.EVP_MD_CTX_free(ctx)
    return ok
end

--- Sign a JWT with ML-DSA-65.
-- @param pem_key string  PEM PKCS#8 ML-DSA-65 private key
-- @param payload table   claims
-- @param kid     string  key ID ([A-Za-z0-9_-] only)
-- @return token | nil, err
function M.sign(pem_key, payload, kid)
    if type(payload) ~= "table" then return nil, "payload must be a table" end
    if type(kid) ~= "string" or not kid:match("^[%w_%-]+$") then
        return nil, "kid must be [A-Za-z0-9_-]+"
    end
    local pay_json, jerr = cjson.encode(payload)
    if not pay_json then return nil, "json encode: " .. tostring(jerr) end

    local header = '{"alg":"' .. ALG .. '","typ":"JWT","kid":"' .. kid .. '"}'
    local signing_input = b64url(header) .. "." .. b64url(pay_json)

    local pkey, kerr = load_key(pem_key)
    if not pkey then return nil, kerr end
    local sig, serr = raw_sign(pkey, signing_input)
    crypto.EVP_PKEY_free(pkey)
    if not sig then return nil, serr end
    return signing_input .. "." .. b64url(sig)
end

--- Startup self-test: the key loads, is ML-DSA-65, signs 3,309 bytes, and the
-- signature verifies under the same key. Run from init_by_lua so a wrong or
-- unusable key stops the gateway instead of failing every admin request.
function M.check_key(pem_key)
    local pkey, kerr = load_key(pem_key)
    if not pkey then return nil, kerr end
    local probe = "jwt_mldsa self-test"
    local sig, serr = raw_sign(pkey, probe)
    local ok = sig and raw_verify(pkey, probe, sig)
    crypto.EVP_PKEY_free(pkey)
    if not sig then return nil, serr end
    if not ok then return nil, "self-test signature did not verify" end
    return true
end

return M
