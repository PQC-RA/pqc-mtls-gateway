-- revocation_check.lua
-- Revocation-only access check for locations on the mTLS listener that do not
-- run policy_router.lua or admin_jwt.lua (today: the static `location /`).
--
-- Without it those locations relied on nginx's ssl_crl alone, which refreshes
-- only on reload, so a revoked client could still fetch them for a few seconds
-- after /api/ and /admin/ already refused it.
-- Same dict, same key format and same response as the inline checks in
-- policy_router.lua and admin_jwt.lua (crl_worker.lua lowercases serials).
local client_serial = ngx.var.ssl_client_serial
if client_serial then
    local revoked = ngx.shared.pqc_route_meta:get("revoked_:" .. string.lower(client_serial))
    if revoked then
        ngx.log(ngx.WARN, "CRITICAL PROTECTION: Dropping revoked PQC client serial: ", client_serial)
        return ngx.exit(444)
    end
end
