-- client_cert_expiry.lua
-- Per-request expiry check for the client certificate on the mTLS listener.
--
-- nginx verifies the client certificate once, at the handshake. A client that
-- keeps its keep-alive connection busy (one request at least every 75 s; nginx
-- ends a connection after 1000 requests or 1 h, keepalive_requests and
-- keepalive_time) keeps using a certificate after its notAfter, while fresh
-- connections with the same certificate are refused. Revocation does not have
-- this gap (the CRL reload closes connections, and the Lua revocation check
-- runs per request); expiry did. A certificate's lifetime is only as short as
-- the longest connection unless every request checks it.
--
-- refuse_if_expired() answers 495, which nginx turns into the same
-- "400 The SSL certificate error" a fresh connection with that certificate gets.
-- On HTTP/1.1 nginx then closes the connection (ngx_http_special_response_handler
-- clears keep-alive for 495), so the client has to reconnect. On HTTP/2 only the
-- stream ends: the connection stays open and every further stream on it is
-- refused the same way until the client opens a new connection.
-- "Expired" is >= notAfter, the comparison OpenSSL's X509_cmp_time makes at
-- the handshake, so an open connection and a fresh one agree to the second.
--
-- A client that obtained a new certificate must open a new connection to use
-- it; requests still sent on a connection authenticated with the old one are
-- refused once the old one expires.
--
-- $ssl_client_v_end is OpenSSL's ASN1_TIME_print form, always GMT, e.g.
--   "Oct 25 18:03:00 2026 GMT" or "Oct  5 08:03:00 2026 GMT".
-- A value that does not parse is treated as expired (fail closed) and logged.

local M = {}

local MONTHS = { Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
                 Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12 }

-- Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's
-- days_from_civil); no os.time, so the container's time zone cannot matter.
local function days_from_civil(y, m, d)
    if m <= 2 then y = y - 1 end
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = (m + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    return era * 146097 + doe - 719468
end

-- Returns the epoch seconds of an ASN1_TIME_print string, or nil.
function M.parse(s)
    if type(s) ~= "string" then return nil end
    local mon, d, hh, mm, ss, y = s:match("^(%a%a%a) +(%d%d?) (%d%d):(%d%d):(%d%d) (%d%d%d%d) GMT$")
    local m = mon and MONTHS[mon]
    if not m then return nil end
    return days_from_civil(tonumber(y), m, tonumber(d)) * 86400
        + tonumber(hh) * 3600 + tonumber(mm) * 60 + tonumber(ss)
end

-- Ends the request with 495 when the client certificate is past its notAfter.
-- Does nothing when there is no client certificate (the callers handle that).
function M.refuse_if_expired(where)
    local v_end = ngx.var.ssl_client_v_end
    if not v_end or v_end == "" then return end
    local not_after = M.parse(v_end)
    if not not_after then
        ngx.log(ngx.ERR, "[client_cert_expiry] cannot parse notAfter '", v_end, "' on ", where or "?",
            "; refusing (fail closed)")
        return ngx.exit(495)
    end
    if ngx.time() >= not_after then
        ngx.log(ngx.WARN, "[client_cert_expiry] expired client certificate on an open connection: serial ",
            tostring(ngx.var.ssl_client_serial), ", notAfter ", v_end, ", on ", where or "?")
        return ngx.exit(495)
    end
end

return M
