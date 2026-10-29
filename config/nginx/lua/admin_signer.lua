-- admin_signer.lua
-- Which key signs the /admin/ token (ADR-022), set once by init_by_lua_block
-- in nginx.conf and inherited by every worker as a module upvalue. Kept out of
-- the pqc_route_meta shared dict on purpose: that dict is LRU-evictable (it
-- also holds every revoked serial), and an evicted kid must never turn into a
-- silent fallback to RS256. admin_jwt.lua answers 500 if this is unset.
local M = { kid = nil, v2_pem = nil }

function M.configure(kid, v2_pem)
    M.kid = kid
    M.v2_pem = v2_pem
end

return M
