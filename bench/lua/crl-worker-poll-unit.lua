-- crl-worker-poll-unit.lua: runs ONE real poll of crl_worker.lua with a stub
-- `ngx`, against the CRL at /etc/pki/pqc-ca/hybrid-combined-crl.pem and the
-- openssl at /opt/openssl/bin/openssl (both hard-coded in crl_worker.lua), and
-- checks what it publishes. Run by crl-worker-unit.sh inside an image that has
-- both, never on a gateway host.
-- Usage: luajit crl-worker-poll-unit.lua <expected nextUpdate epoch> <revoked serial, lowercase hex>
local here = arg[0]:match("^(.*)/[^/]*$") or "."
package.path = here .. "/../../config/nginx/lua/?.lua;" .. package.path

local store, timers, errors = {}, {}, {}
local dict = {}
function dict:set(k, v) store[k] = v; return true end
function dict:get(k) return store[k] end
function dict:delete(k) store[k] = nil end
ngx = {
    shared = { pqc_route_meta = dict },
    now = function() return os.time() end,
    ERR = "ERR", WARN = "WARN",
    log = function(level, ...)
        if level == "ERR" then errors[#errors + 1] = table.concat({ ... }) end
    end,
    timer = { at = function(_, fn) timers[#timers + 1] = fn; return true end },
}

local crl = require("crl_worker")
crl.start_polling()
table.remove(timers, 1)(false)   -- the first poll, synchronously

local fails = 0
local function check(name, got, want)
    if got == want then print("PASS  " .. name)
    else fails = fails + 1; print("FAIL  " .. name .. ": got " .. tostring(got) .. ", want " .. tostring(want)) end
end
check("no error logged", #errors, 0)
for _, e in ipairs(errors) do print("      ERR " .. e) end
check("poller liveness published", type(store.crl_last_update), "number")
check("nextUpdate published", store.crl_next_update, tonumber(arg[1]))
check("revoked serial loaded", store["revoked_:" .. arg[2]], true)
if fails > 0 then print(fails .. " FAILED"); os.exit(1) end
print("all passed")
