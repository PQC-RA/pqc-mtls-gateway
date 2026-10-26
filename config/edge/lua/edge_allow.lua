-- edge_allow.lua: which verified client certificates may reach the device.
--
-- The edge box trusts the CA that issued the central gateway's client
-- certificate, and that CA issues other client certificates too. So after the
-- TLS layer has verified the chain, only the SHA-256 fingerprints listed in
-- allowed-clients.txt (one per line, 64 hex characters, "#" starts a comment)
-- are let through. Anything else is closed before a byte reaches the device.
-- An absent or empty file lets nobody through.

local cert_fingerprint = require "cert_fingerprint"

local M = {}

function M.load(path)
    local dict = ngx.shared.edge_allow
    dict:flush_all()
    local f = io.open(path, "r")
    if not f then
        ngx.log(ngx.ERR, "[edge_allow] ", path, " not readable: nobody is let through")
        return
    end
    local n = 0
    for line in f:lines() do
        local fp = line:gsub("#.*$", ""):match("^%s*(%x+)%s*$")
        if fp and #fp == 64 then
            dict:set(fp:lower(), true)
            n = n + 1
        elseif line:match("%S") and not line:match("^%s*#") then
            ngx.log(ngx.WARN, "[edge_allow] ignoring line: ", line)
        end
    end
    f:close()
    ngx.log(ngx.WARN, "[edge_allow] ", n, " allowed client fingerprint(s)")
end

function M.check()
    if ngx.var.ssl_client_verify ~= "SUCCESS" then
        ngx.log(ngx.WARN, "[edge_allow] closed: client certificate ", ngx.var.ssl_client_verify or "?")
        return ngx.exit(ngx.ERROR)
    end
    -- The stream module has no $ssl_client_escaped_cert; the raw PEM carries no
    -- "%" escapes, so it goes through the same decoder unchanged.
    local fp = cert_fingerprint.client_sha256(ngx.var.ssl_client_raw_cert)
    if not fp or not ngx.shared.edge_allow:get(fp) then
        ngx.log(ngx.WARN, "[edge_allow] closed: ", ngx.var.ssl_client_s_dn or "?",
            " (sha256 ", tostring(fp), ") is not in the allowed list")
        return ngx.exit(ngx.ERROR)
    end
end

return M
