-- tls_log.lua: log_by_lua handler for the mTLS listener.
-- Fills $pqc_tls_group / $pqc_tls_client_sig / $pqc_tls_server_sig /
-- $pqc_tls_client_key for the access log (see tls_telemetry.lua for what each
-- one means and when it is legitimately empty).
--
-- Configured at SERVER level on purpose: requests that nginx finalizes before
-- a location is chosen (no client certificate, failed verification -> 400)
-- never run a location-level log_by_lua, and those are exactly the refusals
-- the log has to explain. The work is in the module so its once-per-worker
-- error flag survives across requests; this chunk re-runs on every request.
local ok, telemetry = pcall(require, "tls_telemetry")
if ok then
    telemetry.log_phase()
end
