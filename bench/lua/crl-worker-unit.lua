-- crl-worker-unit.lua: unit test of crl_worker.lua's nextUpdate parsing (ADR-024),
-- run with plain Lua 5.1+ or LuaJIT, no nginx. crl_worker.lua touches `ngx`
-- only inside its functions, so requiring it outside OpenResty is safe.
-- Usage: lua crl-worker-unit.lua [<rfc822 time> <iso8601 time>]
-- The optional pair is one CRL's nextUpdate as openssl prints it both ways
-- (crl-worker-unit.sh produces it); the two must agree.
local here = arg[0]:match("^(.*)/[^/]*$") or "."
package.path = here .. "/../../config/nginx/lua/?.lua;" .. package.path
local crl = require("crl_worker")

local fails = 0
local function check(name, got, want)
    if got == want then
        print("PASS  " .. name)
    else
        fails = fails + 1
        print("FAIL  " .. name .. ": got " .. tostring(got) .. ", want " .. tostring(want))
    end
end

local parse = crl.parse_openssl_time
-- Expected values from Python's calendar.timegm.
check("ordinary date",            parse("Nov 10 08:52:27 2026 GMT"), 1794300747)
check("epoch, space-padded day",  parse("Jan  1 00:00:00 1970 GMT"), 0)
check("leap day",                 parse("Feb 29 23:59:59 2024 GMT"), 1709251199)
check("2000 is a leap year",      parse("Mar  1 00:00:00 2000 GMT"), 951868800)
check("2100 is not",              parse("Mar  1 00:00:00 2100 GMT"), 4107542400)
check("UTCTime/GeneralizedTime boundary", parse("Jan  1 00:00:00 2050 GMT"), 2524608000)
check("fractional seconds",       parse("Nov 10 08:52:27.5 2026 GMT"), 1794300747)
-- Anything else must be nil, never a wrong number.
check("NONE",                     parse("NONE"), nil)
check("nil",                      parse(nil), nil)
check("no GMT",                   parse("Nov 10 08:52:27 2026"), nil)
check("unknown month",            parse("Foo 10 08:52:27 2026 GMT"), nil)
check("hour out of range",        parse("Nov 10 24:00:00 2026 GMT"), nil)
check("day zero",                 parse("Nov  0 08:52:27 2026 GMT"), nil)
check("trailing text",            parse("Nov 10 08:52:27 2026 GMT x"), nil)

-- Cross-check against OpenSSL's own ISO 8601 rendering of the same field.
if arg[1] and arg[2] then
    local y, mo, d, h, mi, s = arg[2]:match("^(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)Z$")
    local names = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }
    local rebuilt = y and string.format("%s %2d %s:%s:%s %s GMT",
        names[tonumber(mo)], tonumber(d), h, mi, s, y)
    check("openssl -text vs -dateopt iso_8601 (" .. arg[1] .. ")",
        parse(arg[1]) ~= nil and parse(arg[1]) == parse(rebuilt), true)
end

if fails > 0 then
    print(fails .. " FAILED")
    os.exit(1)
end
print("all passed")
