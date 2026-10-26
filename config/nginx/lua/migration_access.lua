-- migration_access.lua: access phase of the migration listener. Revocation and
-- per-request expiry are checked for client certificates exactly as on the strict
-- listener; then the connection is classified and the per-client policy applied
-- (observe by default; see migration.lua).
local serial = ngx.var.ssl_client_serial
if serial and serial ~= "" and ngx.shared.pqc_route_meta:get("revoked_:" .. string.lower(serial)) then
    ngx.log(ngx.WARN, "[migration] dropping revoked client serial ", serial)
    return ngx.exit(444)
end
require("client_cert_expiry").refuse_if_expired("migration")
require("migration").access()
