-- hmac_sha256.lua
-- HMAC-SHA256 via LuaJIT FFI bindings to OpenSSL's libcrypto, which is already
-- loaded into the OpenResty process. This avoids depending on lua-resty-hmac
-- (not bundled with this OpenResty build) or ngx.hmac_sha256 (not available in
-- this build). Consistent with the FFI approach used by jwt_rs256.lua.
--
--   local hmac = require("hmac_sha256")
--   local hex  = hmac.hex(secret, message)   -- lowercase hex string, or nil

local ffi = require("ffi")

-- These types/functions may already be declared by jwt_rs256.lua in the same
-- LuaJIT VM; wrap each cdef in pcall so a redefinition is harmless.
pcall(ffi.cdef, "typedef struct evp_md_st EVP_MD;")
pcall(ffi.cdef, "const EVP_MD *EVP_sha256(void);")
pcall(ffi.cdef, [[
  unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                      const unsigned char *d, size_t n,
                      unsigned char *md, unsigned int *md_len);
]])

local crypto = ffi.load("crypto")

local M = {}

--- Compute HMAC-SHA256(key, data) and return it as lowercase hex (64 chars).
-- @return string hex on success, nil on failure
function M.hex(key, data)
    if type(key) ~= "string" or type(data) ~= "string" then
        return nil
    end
    local md     = ffi.new("unsigned char[32]")
    local md_len = ffi.new("unsigned int[1]")
    local rc = crypto.HMAC(crypto.EVP_sha256(), key, #key, data, #data, md, md_len)
    if rc == nil then
        return nil
    end
    local parts = {}
    for i = 0, 31 do
        parts[i + 1] = string.format("%02x", md[i])
    end
    return table.concat(parts)
end

return M
