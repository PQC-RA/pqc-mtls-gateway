-- migration_access.lua: access phase of the migration listener. Revocation is
-- checked per issuer (migration_crl.lua: the gateway's CRL and the customer
-- CAs'), expiry per request as on the strict listener; then the connection is
-- classified and the per-client policy applied (observe by default; see
-- migration.lua).
require("migration_crl").check()
require("client_cert_expiry").refuse_if_expired("migration")
require("migration").access()
