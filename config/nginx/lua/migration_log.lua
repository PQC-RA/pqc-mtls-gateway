-- migration_log.lua: log phase of the migration listener: TLS telemetry for the
-- access log, then the inventory record (migration.lua). Server level, so requests
-- refused before a location is chosen are recorded too.
local ok, telemetry = pcall(require, "tls_telemetry")
if ok then telemetry.log_phase() end
local ok2, migration = pcall(require, "migration")
if ok2 then
    local good, err = pcall(migration.log)
    if not good then ngx.log(ngx.ERR, "[migration] inventory: ", tostring(err)) end
end
