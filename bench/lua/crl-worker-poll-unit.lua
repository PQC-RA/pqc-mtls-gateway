-- crl-worker-poll-unit.lua: runs ONE real poll of crl_worker.lua with a stub
-- `ngx`, against the CRL at /etc/pki/pqc-ca/hybrid-combined-crl.pem and the
-- openssl at /opt/openssl/bin/openssl (both hard-coded in crl_worker.lua), and
-- checks what it publishes. Run by crl-worker-unit.sh inside an image that has
-- both, never on a gateway host.
-- Usage: luajit crl-worker-poll-unit.lua <expected nextUpdate epoch | withdrawn> <revoked serial, lowercase hex>
--   withdrawn: the first CRL is not the intermediate's (a root-first file); the
--   metric value must be withdrawn and say why. The intermediate's revocations
--   are then NOT loaded either (crl_worker reads only the first CRL), which is
--   why every writer of the file puts the intermediate first.
--   nochain: the chain file cannot be read; the metric value must be withdrawn
--   and the ERR must carry openssl's own message, not a guess.
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
if arg[1] == "withdrawn" then
    local said = false
    for _, e in ipairs(errors) do said = said or e:find("not by the intermediate", 1, true) ~= nil end
    check("root-first file: nextUpdate withdrawn, not the root CRL's", store.crl_next_update, nil)
    check("  ... and the ERR says why", said, true)
    check("  ... and only that reason (one ERR)", #errors, 1)
elseif arg[1] == "nochain" then
    local said = false
    for _, e in ipairs(errors) do
        said = said or (e:find("cannot read the intermediate's subject", 1, true) ~= nil
            and e:find("Could not", 1, true) ~= nil)
    end
    check("chain unreadable: nextUpdate withdrawn", store.crl_next_update, nil)
    check("  ... and the ERR carries openssl's own message", said, true)
    check("  ... and only that reason (one ERR)", #errors, 1)
    for _, e in ipairs(errors) do print("      ERR " .. e) end
else
    check("no error logged", #errors, 0)
    for _, e in ipairs(errors) do print("      ERR " .. e) end
    check("nextUpdate published (the intermediate's)", store.crl_next_update, tonumber(arg[1]))
end
check("poller liveness published", type(store.crl_last_update), "number")
if arg[1] == "withdrawn" then
    check("  ... root first hides the intermediate's revocations from the fast path (hence the fixed order)", store["revoked_:" .. arg[2]], nil)
else
    check("revoked serial loaded", store["revoked_:" .. arg[2]], true)
end
if fails > 0 then print(fails .. " FAILED"); os.exit(1) end
print("all passed")
