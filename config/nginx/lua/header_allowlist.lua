-- header_allowlist.lua
-- Default-deny inbound header filter. Call at the very top of an
-- access_by_lua handler, before any trusted identity header is set, so a
-- client-supplied header can never ride through to the backend unmodified.
--
-- Replaces relying on nginx's location proxy_set_header inheritance rule
-- (a location that sets any proxy_set_header stops inheriting all of the
-- parent's) to strip client-supplied identity headers, that only holds by
-- accident wherever the parent happens to set X-Client-*, and silently stops
-- holding on any location that doesn't. Clearing everything not explicitly
-- allowed closes the whole class of gap instead of one header at a time.

local ALLOWED = {
    ["host"]           = true,
    ["content-type"]   = true,
    ["content-length"] = true,
    ["accept"]         = true,
    -- Read by management-api's CsrfGuard on mutating /admin/ routes (Origin
    -- allowlist + non-empty X-PQC-CSRF). Not identity/auth-bearing on
    -- their own, the guard's Origin check is the actual control, so
    -- passing them through does not re-open the identity-header gap.
    ["origin"]         = true,
    ["x-pqc-csrf"]     = true,
}

local _M = {}

function _M.enforce()
    local headers = ngx.req.get_headers()
    for name, _ in pairs(headers) do
        if not ALLOWED[string.lower(name)] then
            ngx.req.clear_header(name)
        end
    end
end

return _M
