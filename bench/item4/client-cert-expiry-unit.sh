#!/usr/bin/env bash
# client-cert-expiry-unit.sh: unit test of config/nginx/lua/client_cert_expiry.lua
# parse() against GNU date, plus refuse_if_expired() with a stubbed ngx, run
# with the LuaJIT of the ISOLATED stand's gateway container.
set -uo pipefail
C=${STAND_PROJECT:?source STAND_DIR/stand.env first}-gateway
cases=("Oct 25 18:03:00 2026 GMT" "Oct  5 08:03:00 2026 GMT" "Jan  1 00:00:00 1970 GMT" "Feb 29 23:59:59 2028 GMT"
       "Mar  1 00:00:00 2028 GMT" "Dec 31 23:59:59 2049 GMT" "Jan  1 00:00:00 2050 GMT" "Nov 24 09:54:53 2036 GMT")
exp=""; for c in "${cases[@]}"; do exp="$exp$(date -u -d "${c% GMT} UTC" +%s) "; done
docker exec -i -e EXP="$exp" $C /usr/local/openresty/luajit/bin/luajit - <<'LUA'
package.path = "/etc/nginx/lua/?.lua;" .. package.path
local exited, logged = nil, {}
ngx = { var = {}, WARN = 1, ERR = 2, time = function() return NOW end,
        log = function(_, ...) logged[#logged + 1] = table.concat({...}) end,
        exit = function(c) exited = c; return c end }
local M = require("client_cert_expiry")
local cases = { "Oct 25 18:03:00 2026 GMT", "Oct  5 08:03:00 2026 GMT", "Jan  1 00:00:00 1970 GMT", "Feb 29 23:59:59 2028 GMT",
                "Mar  1 00:00:00 2028 GMT", "Dec 31 23:59:59 2049 GMT", "Jan  1 00:00:00 2050 GMT", "Nov 24 09:54:53 2036 GMT" }
local fail, i = 0, 0
for e in os.getenv("EXP"):gmatch("%d+") do
    i = i + 1; local got = M.parse(cases[i])
    if got ~= tonumber(e) then fail = fail + 1; print("FAIL parse", cases[i], got, e) end
end
print(("parse vs GNU date: %d cases, %d failed"):format(i, fail))
for _, bad in ipairs({ "", "Foo 25 18:03:00 2026 GMT", "Oct 25 18:03:00 2026", "Oct 25 18:03 2026 GMT", "2026-10-25T18:03:00Z" }) do
    if M.parse(bad) ~= nil then fail = fail + 1; print("FAIL malformed accepted:", bad) end
end
local function run(v_end, now) exited = nil; ngx.var.ssl_client_v_end = v_end; ngx.var.ssl_client_serial = "ABCD"; NOW = now; M.refuse_if_expired("unit"); return exited end
local na = M.parse("Oct 25 18:03:00 2026 GMT")
local checks = {
    { "valid, 1 s before notAfter", run("Oct 25 18:03:00 2026 GMT", na - 1), nil },
    { "expired at notAfter (as OpenSSL X509_cmp_time)", run("Oct 25 18:03:00 2026 GMT", na), 495 },
    { "expired, 1 s after",          run("Oct 25 18:03:00 2026 GMT", na + 1), 495 },
    { "no client certificate",       run(nil, na + 1), nil },
    { "unparsable notAfter",         run("garbage", na - 100), 495 },
}
for _, c in ipairs(checks) do
    if c[2] ~= c[3] then fail = fail + 1; print("FAIL", c[1], tostring(c[2]), "expected", tostring(c[3])) else print("PASS", c[1], tostring(c[2])) end
end
print(fail == 0 and "RESULT: all passed" or ("RESULT: " .. fail .. " failed")); os.exit(fail == 0 and 0 or 1)
LUA
