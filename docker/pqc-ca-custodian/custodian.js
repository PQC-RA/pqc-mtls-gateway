#!/usr/bin/env node
"use strict";

// pqc-ca-custodian, the ONLY component with any access to the intermediate CA
// private key. Exposes exactly the narrow operations management-api needs
// (sign a CSR, revoke a serial, read the public index/issued-cert data) over
// an internal-only HTTP API on the pqc-pki network. Every mutating/reading
// call is HMAC-authenticated; there is no endpoint that returns the private
// key or the CA config, and no arbitrary file/command access.
//
// Deliberately zero npm dependencies, this is the single most sensitive
// process in the stack, so its dependency surface should be as close to
// nothing as possible.

const http = require("http");
const os = require("os");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");

const execFileAsync = promisify(execFile);

const OPENSSL = process.env.OPENSSL_BIN || "/opt/openssl/bin/openssl";
const CA_DIR = process.env.CA_DIR || "/etc/pki/pqc-ca/intermediate";
const CA_CNF = process.env.CA_CNF || "openssl-intermediate.cnf";
const INDEX_FILE = path.join(CA_DIR, "db", "index.txt");
const ISSUED_DIR = path.resolve(path.join(CA_DIR, "issued"));
// Lives in db/, not directly under CA_DIR, CA_DIR's own root dir is
// root:root 755 (appuser can traverse it, not write into it); db/ is the
// subdirectory setup-pki.sh actually chowns to the app uid, so that's where
// anything this process needs to create (as opposed to just read) has to go.
const FINGERPRINT_INDEX_FILE = path.join(CA_DIR, "db", "fingerprint-index.json");
// Combined CRL, public data (not the private key), but it lives under the
// same CA tree that management-api no longer mounts, so it's served through
// the same narrow, fixed-path read surface as /index and /issued/:serial.
const CRL_FILE = process.env.CRL_FILE || path.join(path.dirname(CA_DIR), "hybrid-combined-crl.pem");
// Custodian-owned default: NOT accepted from the caller, so a compromised
// management-api can never request a non-standard validity window.
const CERT_VALIDITY_DAYS = String(Number(process.env.CERT_VALIDITY_DAYS || 365));
const PORT = Number(process.env.PORT || 8091);
const HMAC_SECRET_FILE = process.env.CUSTODIAN_HMAC_SECRET_FILE || "/run/secrets/custodian-hmac";
const MAX_BODY_BYTES = 1_000_000; // CSRs/certs are small; refuse anything larger

const VALID_REVOKE_REASONS = new Set([
	"unspecified",
	"keyCompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"privilegeWithdrawn",
]);

function log(level, msg) {
	const line = `${new Date().toISOString()} [custodian] [${level}] ${msg}`;
	if (level === "ERROR" || level === "WARN") console.error(line);
	else console.log(line);
}

function loadHmacSecret() {
	try {
		return fs.readFileSync(HMAC_SECRET_FILE, "utf8").trim();
	} catch {
		return "";
	}
}

// Loaded once at startup; rotate by restarting the container.
const HMAC_SECRET = loadHmacSecret();
if (!HMAC_SECRET) {
	log("ERROR", `No HMAC secret at ${HMAC_SECRET_FILE}, refusing to start (fail closed)`);
	process.exit(1);
}

/**
 * Validates + normalizes a caller-supplied serial to the exact form OpenSSL
 * uses on disk (uppercase hex, even length). Mirrors certs.service.ts's
 * normalizeSerial() in management-api, duplicated deliberately: this
 * process must never trust a value it did not itself validate, since a
 * serial is what turns into a filesystem path under the CA tree. Returns
 * null on anything that doesn't match.
 */
function normalizeSerial(raw) {
	if (typeof raw !== "string") return null;
	const trimmed = raw.trim();

	let rawHex;
	if (trimmed.toLowerCase().startsWith("dec:")) {
		const n = parseInt(trimmed.slice(4), 10);
		if (!Number.isInteger(n) || n < 0) return null;
		rawHex = n.toString(16);
	} else if (trimmed.toLowerCase().startsWith("0x")) {
		rawHex = trimmed.slice(2);
	} else {
		rawHex = trimmed;
	}

	if (!/^[0-9A-Fa-f]{1,40}$/.test(rawHex)) return null;
	const hex = rawHex.toUpperCase();
	return hex.length % 2 === 0 ? hex : "0" + hex;
}

/**
 * Resolves a normalized serial to its issued-cert path and verifies the
 * result is still inside ISSUED_DIR. Defense in depth on top of
 * normalizeSerial's strict charset, the path check is what actually stops
 * a traversal ("../private/intermediate-ca.key") from ever reaching fs.
 */
function issuedCertPath(serial) {
	const full = path.resolve(path.join(ISSUED_DIR, `${serial}.pem`));
	if (full !== path.join(ISSUED_DIR, `${serial}.pem`)) return null;
	return full;
}

/**
 * SHA-256 of the DER-encoded cert, 64-char lowercase hex, same derivation as
 * cert_fingerprint.lua (extract the PEM armor, base64-decode to DER, hash the
 * raw bytes). Pure data manipulation, no cert parsing, so it works regardless
 * of the cert's signature algorithm (ML-DSA included).
 *
 * Extracts the block between the BEGIN/END markers rather than just
 * stripping those two lines: `openssl ca` (no `-notext` in this CA's config)
 * prepends a full human-readable text dump of the cert before the PEM armor,
 * and Buffer.from(..., "base64") silently ignores non-base64 characters
 * instead of erroring, so a naive strip would decode a mix of text-dump and
 * armor bytes into a wrong fingerprint with no visible failure.
 */
function computeCertFingerprint(certPem) {
	const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(certPem);
	if (!m) throw new Error("certificate PEM has no BEGIN/END CERTIFICATE armor");
	const b64 = m[1].replace(/[\r\n\s]/g, "");
	const der = Buffer.from(b64, "base64");
	return crypto.createHash("sha256").update(der).digest("hex");
}

/**
 * Validates a caller-supplied fingerprint is exactly 64 hex characters before
 * it's ever used to look anything up. Mirrors normalizeSerial's discipline:
 * this process must never trust an unvalidated value, even one that only
 * feeds an in-memory index lookup rather than a filesystem path.
 */
function normalizeFingerprint(raw) {
	if (typeof raw !== "string") return null;
	if (!/^[0-9A-Fa-f]{64}$/.test(raw)) return null;
	return raw.toLowerCase();
}

/**
 * Extracts the CN= component of a DN string, stopping at the next `,` or
 * `/`, same discipline as policy_router.lua's extract_cn (`dn:match("CN=([^,/]+)")`).
 * Deliberately not a substring match: a naive `.includes("CN=" + cn)` would
 * false-positive on e.g. CN=notCN=foo. Works against both DN spellings this
 * process sees: `openssl req -noout -subject`'s comma-separated form and
 * index.txt's slash-separated form.
 */
function extractCn(dn) {
	if (typeof dn !== "string") return null;
	const m = /CN=([^,/]+)/.exec(dn);
	// .trim() handles trailing "\n" from `openssl req -noout -subject`'s
	// stdout, not a DN-parsing concern, just CLI-output hygiene. index.txt
	// lines have no such trailing whitespace, so this is a no-op there.
	return m ? m[1].trim() : null;
}

/**
 * A CN must map to at most one *active* (status V) certificate at a
 * time. index.txt is OpenSSL's own authoritative status ledger (tab-separated:
 * status, expiry, revocation, serial, filename, subject DN), reused directly
 * rather than duplicating CN tracking into a second index. `unique_subject =
 * no` in openssl-intermediate.cnf means OpenSSL itself won't stop a re-sign,
 * so this check is the only enforcement point.
 */
function cnHasActiveCertificate(cn) {
	const content = fs.readFileSync(INDEX_FILE, "utf8");
	for (const line of content.split("\n")) {
		if (!line) continue;
		const fields = line.split("\t");
		if (fields[0] !== "V") continue;
		if (extractCn(fields[5]) === cn) return true;
	}
	return false;
}

function readFingerprintIndex() {
	try {
		const parsed = JSON.parse(fs.readFileSync(FINGERPRINT_INDEX_FILE, "utf8"));
		return Array.isArray(parsed) ? parsed : [];
	} catch {
		return [];
	}
}

// Synchronous read-modify-write: Node never yields between these two calls,
// so concurrent /sign requests can't interleave and clobber each other's entry.
function appendFingerprintIndexEntry(fingerprint, serialNumber) {
	const entries = readFingerprintIndex();
	entries.push({ fingerprint, serialNumber });
	fs.writeFileSync(FINGERPRINT_INDEX_FILE, JSON.stringify(entries));
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		req.on("data", chunk => {
			size += chunk.length;
			if (size > MAX_BODY_BYTES) {
				reject(new Error("payload_too_large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}

function verifyHmac(bodyBuf, sigHeader) {
	if (!sigHeader || typeof sigHeader !== "string") return false;
	const m = /^sha256=([0-9a-fA-F]+)$/.exec(sigHeader);
	if (!m) return false;
	const expected = crypto.createHmac("sha256", HMAC_SECRET).update(bodyBuf).digest("hex");
	const expectedBuf = Buffer.from(expected, "hex");
	const providedBuf = Buffer.from(m[1], "hex");
	if (expectedBuf.length !== providedBuf.length) return false;
	return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

function sendJson(res, status, obj) {
	const body = JSON.stringify(obj);
	res.writeHead(status, {
		"Content-Type": "application/json",
		"Content-Length": Buffer.byteLength(body),
	});
	res.end(body);
}

function sendError(res, status, error, message) {
	sendJson(res, status, { error, message });
}

function handleGetCrl(res) {
	try {
		const stat = fs.statSync(CRL_FILE);
		const content = fs.readFileSync(CRL_FILE, "utf8");
		return sendJson(res, 200, { content, mtimeMs: stat.mtimeMs });
	} catch (err) {
		if (err.code === "ENOENT") {
			return sendError(res, 404, "not_found", "CRL file not found");
		}
		log("ERROR", `Failed to read CRL file: ${err.message}`);
		return sendError(res, 500, "read_failed", "Failed to read CRL");
	}
}

function handleGetIndex(res) {
	try {
		const content = fs.readFileSync(INDEX_FILE, "utf8");
		return sendJson(res, 200, { content });
	} catch (err) {
		log("ERROR", `Failed to read index file: ${err.message}`);
		return sendError(res, 500, "index_read_failed", "Failed to read CA index");
	}
}

function handleGetIssued(res, serialRaw) {
	const serial = normalizeSerial(serialRaw);
	if (!serial) {
		return sendError(res, 400, "invalid_serial", "Serial must be hexadecimal, 0x-prefixed hex, or dec:-prefixed decimal");
	}
	const certPath = issuedCertPath(serial);
	if (!certPath) {
		return sendError(res, 400, "invalid_serial", "Serial does not resolve inside the issued certificate directory");
	}
	if (!fs.existsSync(certPath)) {
		return sendError(res, 404, "not_found", `No issued certificate for serial ${serial}`);
	}
	try {
		const content = fs.readFileSync(certPath, "utf8");
		return sendJson(res, 200, { content });
	} catch (err) {
		log("ERROR", `Failed to read issued cert ${serial}: ${err.message}`);
		return sendError(res, 500, "read_failed", "Failed to read issued certificate");
	}
}

async function handleGetCertByFingerprint(res, fprRaw) {
	const fpr = normalizeFingerprint(fprRaw);
	if (!fpr) {
		return sendError(res, 400, "invalid_fingerprint", "Fingerprint must be exactly 64 hexadecimal characters");
	}

	const entries = readFingerprintIndex();
	const match = entries.find(e => typeof e.fingerprint === "string" && e.fingerprint.toLowerCase() === fpr);
	if (!match) {
		return sendError(res, 404, "not_found", `No certificate found for fingerprint ${fpr}`);
	}

	const serial = normalizeSerial(match.serialNumber);
	const certPath = serial ? issuedCertPath(serial) : null;
	if (!certPath || !fs.existsSync(certPath)) {
		log("ERROR", `Fingerprint index entry ${fpr} references missing/invalid serial ${match.serialNumber}`);
		return sendError(res, 404, "not_found", `No certificate found for fingerprint ${fpr}`);
	}

	try {
		const certificate = fs.readFileSync(certPath, "utf8");
		const { stdout: textOut } = await execFileAsync(OPENSSL, ["x509", "-in", certPath, "-noout", "-enddate"]);
		const endDateMatch = textOut.match(/notAfter=(.+)/);
		const expiresAt = endDateMatch ? new Date(endDateMatch[1]).toISOString() : "";
		return sendJson(res, 200, { certificate, serialNumber: serial, expiresAt });
	} catch (err) {
		log("ERROR", `Failed to read certificate for fingerprint ${fpr}: ${err.message}`);
		return sendError(res, 500, "read_failed", "Failed to read certificate");
	}
}

async function handleSign(res, payload) {
	const csrPem = payload && typeof payload.csrPem === "string" ? payload.csrPem : null;
	if (!csrPem || !csrPem.includes("BEGIN CERTIFICATE REQUEST")) {
		return sendError(res, 400, "invalid_csr", "csrPem is required and must be a PEM-encoded CSR");
	}

	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-custodian-"));
	const csrPath = path.join(tmpDir, "client.csr");
	const crtPath = path.join(tmpDir, "client.crt");
	try {
		fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });

		let cn;
		try {
			// Unlike the `x509` invocations elsewhere in this file, `req` loads a
			// config file even for pure read-only display ops, OPENSSL_CONF is
			// otherwise unset in this container. Point it at /dev/null rather than
			// a real openssl.cnf: this is just a subject-line parse, and pulling in
			// unrelated config content is unnecessary surface for the single most
			// sensitive process in the stack.
			const { stdout: subjectOut } = await execFileAsync(
				OPENSSL,
				["req", "-in", csrPath, "-noout", "-subject"],
				{ env: { ...process.env, OPENSSL_CONF: "/dev/null" } }
			);
			cn = extractCn(subjectOut);
		} catch (err) {
			log("ERROR", `Failed to read subject from CSR: ${err.stderr || err.message}`);
			return sendError(res, 400, "invalid_csr", "Could not read subject from CSR");
		}
		if (!cn) {
			return sendError(res, 400, "invalid_csr", "CSR subject has no CN component");
		}

		if (cnHasActiveCertificate(cn)) {
			log("WARN", `Rejected signing request: CN=${cn} already has an active certificate`);
			return sendError(res, 409, "cn_already_active", `Certificate CN ${cn} already has an active certificate, revoke it first to renew`);
		}

		let stderr = "";
		try {
			const result = await execFileAsync(
				OPENSSL,
				["ca", "-config", CA_CNF, "-in", csrPath, "-out", crtPath, "-batch", "-days", CERT_VALIDITY_DAYS],
				{ cwd: CA_DIR }
			);
			stderr = result.stderr || "";
		} catch (err) {
			log("ERROR", `openssl ca signing failed: ${err.stderr || err.message}`);
			return sendError(res, 400, "signing_failed", "CA signing failed, check CSR subject and CA state");
		}

		if (stderr && /\berror:/i.test(stderr)) {
			log("ERROR", `CA signing reported an error: ${stderr}`);
			return sendError(res, 400, "signing_failed", "CA signing failed, check CSR subject and CA state");
		}

		if (!fs.existsSync(crtPath)) {
			log("ERROR", "openssl ca exited cleanly but produced no certificate file");
			return sendError(res, 500, "signing_failed", "Certificate file was not created by the CA");
		}

		const certificate = fs.readFileSync(crtPath, "utf8");

		const { stdout: textOut } = await execFileAsync(OPENSSL, ["x509", "-in", crtPath, "-noout", "-serial", "-enddate"]);
		const serialMatch = textOut.match(/serial=([0-9A-Fa-f]+)/);
		const endDateMatch = textOut.match(/notAfter=(.+)/);
		const serialNumber = serialMatch ? serialMatch[1].toUpperCase() : null;
		const expiresAt = endDateMatch ? new Date(endDateMatch[1]).toISOString() : "";

		if (!serialNumber) {
			log("ERROR", "Could not extract serial number from freshly issued certificate");
			return sendError(res, 500, "signing_failed", "Could not determine serial number of issued certificate");
		}

		log("INFO", `Signed certificate serial=${serialNumber} expires=${expiresAt}`);

		try {
			const fingerprint = computeCertFingerprint(certificate);
			appendFingerprintIndexEntry(fingerprint, serialNumber);
			log("INFO", `Recorded fingerprint index entry fingerprint=${fingerprint} serial=${serialNumber}`);
		} catch (err) {
			// The issued cert is still valid and already returned below via
			// /issued/:serial, losing the fingerprint-index entry only means
			// /cert/by-fingerprint won't find it, not that issuance failed.
			log("ERROR", `Failed to update fingerprint index for serial=${serialNumber}: ${err.message}`);
		}

		return sendJson(res, 201, { certificate, serialNumber, expiresAt });
	} finally {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	}
}

async function handleRevoke(res, payload) {
	const serial = normalizeSerial(payload && payload.serialNumber);
	if (!serial) {
		return sendError(res, 400, "invalid_serial", "serialNumber is required and must be hexadecimal");
	}
	const reason = payload && payload.reason;
	if (reason !== undefined && !VALID_REVOKE_REASONS.has(reason)) {
		return sendError(res, 400, "invalid_reason", `Invalid revocation reason: ${reason}`);
	}

	const certPath = issuedCertPath(serial);
	if (!certPath) {
		return sendError(res, 400, "invalid_serial", "Serial does not resolve inside the issued certificate directory");
	}
	if (!fs.existsSync(certPath)) {
		return sendError(res, 404, "not_found", `No issued certificate for serial ${serial}`);
	}

	// RFC 5280 §5.3.1 / BR §7.2.2: when reason is unspecified, the CRL
	// reasonCode extension MUST be omitted.
	const relativeCertPath = path.join("issued", `${serial}.pem`);
	const args = ["ca", "-config", CA_CNF, "-revoke", relativeCertPath];
	if (reason && reason !== "unspecified") {
		args.push("-crl_reason", reason);
	}

	try {
		const { stdout, stderr } = await execFileAsync(OPENSSL, args, { cwd: CA_DIR });
		const output = `${stdout}\n${stderr}`;
		if (/already revoked/i.test(output)) {
			return sendError(res, 409, "already_revoked", `Certificate ${serial} is already revoked`);
		}
		if (/\berror:/i.test(stderr) && !/Data Base Updated/i.test(output)) {
			log("ERROR", `openssl ca revoke reported an error: ${stderr}`);
			return sendError(res, 500, "revoke_failed", "CA revocation failed");
		}
	} catch (err) {
		const output = `${err.stdout || ""}\n${err.stderr || ""}`;
		if (/already revoked/i.test(output)) {
			return sendError(res, 409, "already_revoked", `Certificate ${serial} is already revoked`);
		}
		log("ERROR", `openssl ca revoke failed: ${err.stderr || err.message}`);
		return sendError(res, 500, "revoke_failed", "CA revocation failed");
	}

	log("INFO", `Revoked certificate serial=${serial} reason=${reason || "unspecified"}`);
	return sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
	try {
		// Unauthenticated liveness probe only, no CA data, just booleans on
		// whether the two files this process serves are reachable. Used by the
		// compose healthcheck and management-api's own health indicator.
		if (req.method === "GET" && req.url === "/healthz") {
			const indexOk = fs.existsSync(INDEX_FILE);
			const crlOk = fs.existsSync(CRL_FILE);
			return sendJson(res, indexOk && crlOk ? 200 : 503, { ok: indexOk && crlOk, indexOk, crlOk });
		}

		let bodyBuf;
		try {
			bodyBuf = await readBody(req);
		} catch {
			return sendError(res, 413, "payload_too_large", "Request body too large");
		}

		if (!verifyHmac(bodyBuf, req.headers["x-hub-signature-256"])) {
			log("WARN", `HMAC verification failed for ${req.method} ${req.url} from ${req.socket.remoteAddress}`);
			return sendError(res, 401, "invalid_signature", "HMAC signature verification failed");
		}

		let payload = {};
		if (bodyBuf.length > 0) {
			try {
				payload = JSON.parse(bodyBuf.toString("utf8"));
			} catch {
				return sendError(res, 400, "invalid_json", "Request body must be valid JSON");
			}
		}

		const url = req.url || "";

		if (req.method === "GET" && url === "/index") {
			return handleGetIndex(res);
		}

		if (req.method === "GET" && url === "/crl") {
			return handleGetCrl(res);
		}

		const issuedMatch = /^\/issued\/([^/]+)$/.exec(url);
		if (req.method === "GET" && issuedMatch) {
			return handleGetIssued(res, decodeURIComponent(issuedMatch[1]));
		}

		const fprMatch = /^\/cert\/by-fingerprint\/([^/]+)$/.exec(url);
		if (req.method === "GET" && fprMatch) {
			return await handleGetCertByFingerprint(res, decodeURIComponent(fprMatch[1]));
		}

		if (req.method === "POST" && url === "/sign") {
			return await handleSign(res, payload);
		}

		if (req.method === "POST" && url === "/revoke") {
			return await handleRevoke(res, payload);
		}

		return sendError(res, 404, "not_found", "No such endpoint");
	} catch (err) {
		log("ERROR", `Unhandled error: ${err && err.stack ? err.stack : err}`);
		if (!res.headersSent) sendError(res, 500, "internal_error", "Internal custodian error");
	}
});

server.listen(PORT, () => {
	log("INFO", `pqc-ca-custodian listening on :${PORT} (CA_DIR=${CA_DIR})`);
});
