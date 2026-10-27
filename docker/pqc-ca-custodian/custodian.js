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

// Renewal (item 4). Off by default: with RENEWAL_ENABLED unset the custodian
// issues exactly what it always has (CERT_VALIDITY_DAYS via -days) and refuses
// every renewal request. The lifetime is never taken from the caller: the
// caller may only name one of these profiles, and the custodian maps it.
const RENEWAL_ENABLED = process.env.RENEWAL_ENABLED === "1";
const DEMO_PROFILE_ENABLED = process.env.CUSTODIAN_DEMO_PROFILE === "1";
const PROFILES = { "client-30d": 30 * 86400, "demo-120s": 120 };
const LINEAGE_CAP_S = 365 * 86400; // a renewal chain ends this long after its bootstrap enrollment
const REBOOTSTRAP_WINDOW_S = 30 * 86400; // a new bootstrap is allowed this close to the cap
const BACKDATE_S = 60; // notBefore = issue time - 60 s, for client clock skew
// One lock for every writer of the CA database, shared with the CRL renewer
// (which runs -updatedb and -gencrl against the same index). `openssl ca` itself
// does no locking. Inside this process the mutex below serialises the CN check
// with the signing that follows it.
const CA_LOCK_FILE = process.env.CA_LOCK_FILE || path.join(CA_DIR, "db", ".ca-db.lock");
const LINEAGE_FILE = path.join(CA_DIR, "db", "lineage.json");
const IDEMPOTENCY_FILE = path.join(CA_DIR, "db", "idempotency.json");
const CLOCK_SKEW_MS = 30_000;
const NONCE_TTL_MS = 120_000;

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
	// Exactly one "CN=" in the whole DN, read only at the start of an attribute:
	// "emailAddress=xCN=victim" or "ISO-CN=victim" must not be taken for a CN
	// (the management API refuses such subjects too; this is the second layer).
	if ((dn.match(/cn\s*=/gi) || []).length !== 1) return null;
	const m = /(?:^|[,/])\s*CN=([^,/]+)/.exec(dn);
	// .trim() handles trailing "\n" from `openssl req -noout -subject`'s
	// stdout, not a DN-parsing concern, just CLI-output hygiene. index.txt
	// lines have no such trailing whitespace, so this is a no-op there.
	return m ? m[1].trim() : null;
}

/**
 * A CN may map to at most one active certificate, plus at most one successor
 * named by a renewal. index.txt is OpenSSL's status ledger (tab-separated:
 * status, expiry, revocation, serial, filename, subject DN). "Active" means
 * status V AND expiry still in the future: nothing runs `openssl ca -updatedb`
 * on every request, so an expired certificate can still read V here.
 * `unique_subject` in openssl-intermediate.cnf must be `no` for a renewal to
 * overlap its predecessor; this check is then the only guard.
 */
function parseIndexTime(s) {
	const m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s || "");
	if (!m) return null;
	let y = Number(m[1]);
	if (m[1].length === 2) y = y < 50 ? 2000 + y : 1900 + y;
	return Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

function readIndexRows() {
	const content = fs.readFileSync(INDEX_FILE, "utf8");
	const rows = [];
	for (const line of content.split("\n")) {
		if (!line) continue;
		const f = line.split("\t");
		rows.push({ status: f[0], expiryMs: parseIndexTime(f[1]), serial: (f[3] || "").toUpperCase(), dn: f[5] || "" });
	}
	return rows;
}

function activeRowsForCn(cn, now = Date.now()) {
	return readIndexRows().filter(r => r.status === "V" && r.expiryMs !== null && r.expiryMs > now && extractCn(r.dn) === cn);
}

function cnHasActiveCertificate(cn) {
	return activeRowsForCn(cn).length > 0;
}

// Atomic JSON state: temp file beside the target, fsync, rename. A torn write
// can never leave a half file in place, and a file that does not parse is an
// error (fail closed), never an empty list.
function writeJsonAtomic(file, obj) {
	const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
	const fd = fs.openSync(tmp, "w", 0o640);
	try {
		fs.writeSync(fd, JSON.stringify(obj));
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
	fs.renameSync(tmp, file);
}

function readJsonState(file) {
	try {
		return JSON.parse(fs.readFileSync(file, "utf8"));
	} catch (err) {
		if (err.code === "ENOENT") return {};
		throw new Error(`state file ${path.basename(file)} unreadable: ${err.message}`);
	}
}

// In-process mutex: every CA mutation runs one at a time.
let caChain = Promise.resolve();
function withCaMutex(fn) {
	const run = caChain.then(fn, fn);
	caChain = run.catch(() => {});
	return run;
}

// `openssl ca` under the CA-wide file lock shared with the CRL renewer.
function opensslCaLocked(args) {
	return execFileAsync("flock", ["-w", "20", CA_LOCK_FILE, OPENSSL, ...args], { cwd: CA_DIR });
}

async function subjectRfc2253(kind, file) {
	const { stdout } = await execFileAsync(OPENSSL, [kind, "-in", file, "-noout", "-subject", "-nameopt", "RFC2253"],
		{ env: { ...process.env, OPENSSL_CONF: "/dev/null" } });
	return stdout.replace(/^subject=\s*/, "").trim();
}

async function spkiSha256(kind, file) {
	const { stdout } = await execFileAsync(OPENSSL, [kind, "-in", file, "-noout", "-pubkey"],
		{ env: { ...process.env, OPENSSL_CONF: "/dev/null" } });
	const m = /-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/.exec(stdout);
	if (!m) throw new Error("no public key");
	return crypto.createHash("sha256").update(Buffer.from(m[1].replace(/\s/g, ""), "base64")).digest("hex");
}

function opensslTime(ms) {
	const d = new Date(ms);
	const p = n => String(n).padStart(2, "0");
	return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

function normalizeIdempotencyKey(raw) {
	if (raw === undefined) return undefined;
	if (typeof raw !== "string" || !/^[A-Za-z0-9:_-]{8,160}$/.test(raw)) return null;
	return raw;
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
	writeJsonAtomic(FINGERPRINT_INDEX_FILE, entries);
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

// Request authentication (v2): HMAC-SHA256 over method, path, timestamp,
// nonce and the SHA-256 of the body. A request older or newer than 30 s, or a
// nonce already seen in the last 120 s, is refused, so a captured request
// cannot be replayed and two different GETs no longer share one signature.
// Nonces are kept in memory: a restart reopens a replay window of at most the
// 30 s clock tolerance.
const seenNonces = new Map();

function hmacHex(data) {
	return crypto.createHmac("sha256", HMAC_SECRET).update(data).digest("hex");
}

function sha256Hex(buf) {
	return crypto.createHash("sha256").update(buf).digest("hex");
}

function safeEqualHex(a, b) {
	const ab = Buffer.from(a, "hex"), bb = Buffer.from(b, "hex");
	return ab.length === bb.length && ab.length > 0 && crypto.timingSafeEqual(ab, bb);
}

function verifyRequest(req, bodyBuf) {
	const sig = req.headers["x-hub-signature-256"];
	const ts = req.headers["x-custodian-timestamp"];
	const nonce = req.headers["x-custodian-nonce"];
	if (typeof sig !== "string" || typeof ts !== "string" || typeof nonce !== "string") return { ok: false, why: "missing_headers" };
	const m = /^sha256=([0-9a-f]{64})$/.exec(sig);
	if (!m || !/^\d{10,16}$/.test(ts) || !/^[0-9a-f]{32}$/.test(nonce)) return { ok: false, why: "malformed_headers" };
	const now = Date.now();
	if (Math.abs(now - Number(ts)) > CLOCK_SKEW_MS) return { ok: false, why: "stale_timestamp" };
	const expected = hmacHex(`v2\n${req.method}\n${req.url}\n${ts}\n${nonce}\n${sha256Hex(bodyBuf)}`);
	if (!safeEqualHex(expected, m[1])) return { ok: false, why: "bad_signature" };
	for (const [n, exp] of seenNonces) if (exp < now) seenNonces.delete(n);
	if (seenNonces.has(nonce)) return { ok: false, why: "replayed_nonce" };
	seenNonces.set(nonce, now + NONCE_TTL_MS);
	return { ok: true, nonce };
}

// Responses are signed too, bound to the request's nonce, so the caller's
// decision never rests on unauthenticated data.
function sendJson(res, status, obj) {
	const body = JSON.stringify(obj);
	const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) };
	if (res.pqcNonce) headers["X-Custodian-Response-Signature"] = "sha256=" + hmacHex(`v2r\n${status}\n${res.pqcNonce}\n${sha256Hex(Buffer.from(body))}`);
	res.writeHead(status, headers);
	res.end(body);
}

function sendError(res, status, error, message, extra) {
	sendJson(res, status, { error, message, ...(extra || {}) });
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

function readIssuedResult(serial) {
	const certPath = issuedCertPath(serial);
	if (!certPath || !fs.existsSync(certPath)) return null;
	return fs.readFileSync(certPath, "utf8");
}

async function certResult(serial) {
	const certPath = issuedCertPath(serial);
	const certificate = readIssuedResult(serial);
	if (!certificate) return null;
	const { stdout } = await execFileAsync(OPENSSL, ["x509", "-in", certPath, "-noout", "-startdate", "-enddate"]);
	const nb = stdout.match(/notBefore=(.+)/), na = stdout.match(/notAfter=(.+)/);
	return { certificate, serialNumber: serial, notBefore: nb ? new Date(nb[1]).toISOString() : "", expiresAt: na ? new Date(na[1]).toISOString() : "" };
}

// R5 fallback: an intent with no serial (crash between `openssl ca` and the
// record) is resolved by looking for an issued certificate with this CN and
// this public key.
async function findIssuedBySpki(cn, spki) {
	for (const row of readIndexRows()) {
		if (extractCn(row.dn) !== cn) continue;
		const certPath = issuedCertPath(row.serial);
		if (!certPath || !fs.existsSync(certPath)) continue;
		try {
			if ((await spkiSha256("x509", certPath)) === spki) return row.serial;
		} catch { /* unreadable entry: skip */ }
	}
	return null;
}

async function handleSign(res, payload) {
	const csrPem = payload && typeof payload.csrPem === "string" ? payload.csrPem : null;
	if (!csrPem || !csrPem.includes("BEGIN CERTIFICATE REQUEST")) {
		return sendError(res, 400, "invalid_csr", "csrPem is required and must be a PEM-encoded CSR");
	}
	const profile = payload.profile === undefined ? "legacy" : payload.profile;
	if (profile !== "legacy" && !Object.prototype.hasOwnProperty.call(PROFILES, profile)) {
		return sendError(res, 400, "invalid_profile", "Unknown profile");
	}
	if (profile !== "legacy" && !RENEWAL_ENABLED) return sendError(res, 403, "renewal_disabled", "Renewal profiles are disabled");
	if (profile === "demo-120s" && !DEMO_PROFILE_ENABLED) return sendError(res, 403, "profile_disabled", "The demo profile is disabled");
	const renewsSerial = payload.renewsSerial === undefined ? undefined : normalizeSerial(payload.renewsSerial);
	if (renewsSerial === null) return sendError(res, 400, "invalid_serial", "renewsSerial must be hexadecimal");
	if (renewsSerial && !RENEWAL_ENABLED) return sendError(res, 403, "renewal_disabled", "Renewal is disabled");
	const idemKey = normalizeIdempotencyKey(payload.idempotencyKey);
	if (idemKey === null) return sendError(res, 400, "invalid_idempotency_key", "idempotencyKey must be 8 to 160 characters of [A-Za-z0-9:_-]");

	return withCaMutex(async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-custodian-"));
		const csrPath = path.join(tmpDir, "client.csr");
		const crtPath = path.join(tmpDir, "client.crt");
		try {
			fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });
			let cn, subject, spki;
			try {
				subject = await subjectRfc2253("req", csrPath);
				cn = extractCn(subject.replace(/,/g, "/"));
				spki = await spkiSha256("req", csrPath);
			} catch (err) {
				log("ERROR", `Failed to read CSR: ${err.stderr || err.message}`);
				return sendError(res, 400, "invalid_csr", "Could not read subject or key from CSR");
			}
			if (!cn) return sendError(res, 400, "invalid_csr", "CSR subject must carry exactly one CN");
			// Same CN alphabet and single-attribute RDNs as the management API.
			if (!/^[A-Za-z0-9._-]{1,64}$/.test(cn) || /(^|[^\\])\+/.test(subject)) {
				return sendError(res, 400, "invalid_csr", "CSR subject: CN outside [A-Za-z0-9._-]{1,64} or a multi-valued RDN");
			}

			const now = Date.now();
			const idem = readJsonState(IDEMPOTENCY_FILE);
			if (idemKey && idem[idemKey]) {
				const rec = idem[idemKey];
				if (rec.spki !== spki) return sendError(res, 409, "idempotency_conflict", "This idempotency key was used with a different key pair");
				let serial = rec.serial || (await findIssuedBySpki(cn, spki));
				if (serial) {
					if (!rec.serial) { idem[idemKey] = { ...rec, serial, state: "done" }; writeJsonAtomic(IDEMPOTENCY_FILE, idem); }
					const r = await certResult(serial);
					if (r) return sendJson(res, 200, { ...r, replay: true });
				}
			}

			const lineage = readJsonState(LINEAGE_FILE);
			let lifetimeS = null, notAfterMs = null, lineageId, bootstrapAt, closes = null;
			const active = activeRowsForCn(cn, now);

			if (renewsSerial) {
				const pred = readIndexRows().find(r => r.serial === renewsSerial);
				if (!pred || pred.status !== "V" || !(pred.expiryMs > now)) return sendError(res, 409, "predecessor_not_active", "The certificate being renewed is not valid");
				if (extractCn(pred.dn) !== cn) return sendError(res, 400, "subject_mismatch", "CSR CN differs from the certificate being renewed");
				const predPath = issuedCertPath(renewsSerial);
				if (!predPath || !fs.existsSync(predPath)) return sendError(res, 409, "predecessor_not_active", "No issued certificate for that serial");
				if ((await subjectRfc2253("x509", predPath)) !== subject) return sendError(res, 400, "subject_mismatch", "CSR subject differs from the certificate being renewed");
				if ((await spkiSha256("x509", predPath)) === spki) return sendError(res, 400, "same_key", "A renewal must use a new key pair");
				const L = lineage[renewsSerial];
				if (!L) return sendError(res, 403, "not_renewable", "This certificate was not issued under a renewal profile");
				if (L.frozen) return sendError(res, 403, "lineage_frozen", "This identity is frozen; a new bootstrap enrollment is required");
				if (L.successor) {
					if (L.successorSpki === spki) { const r = await certResult(L.successor); if (r) return sendJson(res, 200, { ...r, replay: true }); }
					return sendError(res, 409, "successor_exists", "This certificate already has a successor with a different key", { successorSerial: L.successor });
				}
				if (!(active.length === 1 && active[0].serial === renewsSerial)) return sendError(res, 409, "cn_already_active", "The CN has another active certificate");
				lifetimeS = PROFILES[L.profile];
				lineageId = L.lineageId; bootstrapAt = L.bootstrapAt;
				notAfterMs = Math.min(now + lifetimeS * 1000, bootstrapAt + LINEAGE_CAP_S * 1000);
				if (notAfterMs - now < (lifetimeS * 1000) / 2) return sendError(res, 409, "lineage_cap_reached", "This renewal chain has reached its cap; a new bootstrap enrollment is required");
			} else {
				if (active.length > 0) {
					const L = active.length === 1 ? lineage[active[0].serial] : null;
					const nearCap = L && !L.frozen && (L.bootstrapAt + LINEAGE_CAP_S * 1000 - now) <= REBOOTSTRAP_WINDOW_S * 1000;
					if (!(nearCap && profile !== "legacy")) {
						log("WARN", `Rejected signing request: CN=${cn} already has an active certificate`);
						return sendError(res, 409, "cn_already_active", `Certificate CN ${cn} already has an active certificate; revoke it first`);
					}
					closes = active[0].serial; // a new lineage for a CN whose chain is in its last 30 days
				}
				if (profile !== "legacy") {
					lifetimeS = PROFILES[profile];
					notAfterMs = now + lifetimeS * 1000;
					bootstrapAt = now;
				}
			}

			if (idemKey) { idem[idemKey] = { spki, cn, state: "intent", at: now }; writeJsonAtomic(IDEMPOTENCY_FILE, idem); }

			const args = ["ca", "-config", CA_CNF, "-in", csrPath, "-out", crtPath, "-batch"];
			if (notAfterMs === null) args.push("-days", CERT_VALIDITY_DAYS);
			else args.push("-startdate", opensslTime(now - BACKDATE_S * 1000), "-enddate", opensslTime(notAfterMs));
			let stderr = "";
			try {
				const result = await opensslCaLocked(args);
				stderr = result.stderr || "";
			} catch (err) {
				log("ERROR", `openssl ca signing failed: ${err.stderr || err.message}`);
				return sendError(res, 400, "signing_failed", "CA signing failed", { mayHaveIssued: true });
			}
			if (stderr && /\berror:/i.test(stderr)) {
				log("ERROR", `CA signing reported an error: ${stderr}`);
				return sendError(res, 400, "signing_failed", "CA signing failed", { mayHaveIssued: true });
			}
			if (!fs.existsSync(crtPath)) {
				log("ERROR", "openssl ca exited cleanly but produced no certificate file");
				return sendError(res, 500, "signing_failed", "Certificate file was not created by the CA", { mayHaveIssued: true });
			}
			const certificate = fs.readFileSync(crtPath, "utf8");
			const { stdout: textOut } = await execFileAsync(OPENSSL, ["x509", "-in", crtPath, "-noout", "-serial", "-startdate", "-enddate"]);
			const serialMatch = textOut.match(/serial=([0-9A-Fa-f]+)/);
			const serialNumber = serialMatch ? serialMatch[1].toUpperCase() : null;
			const na = textOut.match(/notAfter=(.+)/), nb = textOut.match(/notBefore=(.+)/);
			const expiresAt = na ? new Date(na[1]).toISOString() : "";
			if (!serialNumber) {
				log("ERROR", "Could not extract serial number from freshly issued certificate");
				return sendError(res, 500, "signing_failed", "Could not determine serial number of issued certificate", { mayHaveIssued: true });
			}
			log("INFO", `Signed certificate serial=${serialNumber} profile=${renewsSerial ? "renewal" : profile} expires=${expiresAt}`);

			if (idemKey) { idem[idemKey] = { spki, cn, state: "done", serial: serialNumber, at: now }; writeJsonAtomic(IDEMPOTENCY_FILE, idem); }
			if (renewsSerial || profile !== "legacy") {
				const L2 = readJsonState(LINEAGE_FILE);
				const prof = renewsSerial ? L2[renewsSerial].profile : profile;
				L2[serialNumber] = { lineageId: lineageId || serialNumber, bootstrapAt, profile: prof, predecessor: renewsSerial || null, spki, at: now };
				if (renewsSerial) { L2[renewsSerial].successor = serialNumber; L2[renewsSerial].successorSpki = spki; }
				if (closes && L2[closes]) L2[closes].closedBy = serialNumber;
				writeJsonAtomic(LINEAGE_FILE, L2);
			}
			try {
				const fingerprint = computeCertFingerprint(certificate);
				appendFingerprintIndexEntry(fingerprint, serialNumber);
			} catch (err) {
				log("ERROR", `Failed to update fingerprint index for serial=${serialNumber}: ${err.message}`);
			}
			return sendJson(res, 201, { certificate, serialNumber, notBefore: nb ? new Date(nb[1]).toISOString() : "", expiresAt, lineageId: lineageId || (profile !== "legacy" ? serialNumber : undefined) });
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
}

async function handleSignResult(res, keyRaw) {
	const key = normalizeIdempotencyKey(keyRaw);
	if (!key) return sendError(res, 400, "invalid_idempotency_key", "Invalid key");
	const rec = readJsonState(IDEMPOTENCY_FILE)[key];
	if (!rec) return sendJson(res, 200, { state: "none" });
	const serial = rec.serial || (await findIssuedBySpki(rec.cn, rec.spki));
	if (!serial) return sendJson(res, 200, { state: "intent_without_certificate" });
	const r = await certResult(serial);
	return sendJson(res, 200, { state: "issued", ...r });
}

function handleGetLineage(res, serialRaw) {
	const serial = normalizeSerial(serialRaw);
	if (!serial) return sendError(res, 400, "invalid_serial", "Serial must be hexadecimal");
	const L = readJsonState(LINEAGE_FILE)[serial];
	if (!L) return sendError(res, 404, "not_found", "No lineage record for that serial");
	return sendJson(res, 200, { serial, ...L, capAt: new Date(L.bootstrapAt + LINEAGE_CAP_S * 1000).toISOString() });
}

function handleFreeze(res, payload) {
	const serial = normalizeSerial(payload && payload.serialNumber);
	if (!serial) return sendError(res, 400, "invalid_serial", "serialNumber is required");
	return withCaMutex(async () => {
		const L = readJsonState(LINEAGE_FILE);
		if (!L[serial]) return sendError(res, 404, "not_found", "No lineage record for that serial");
		const id = L[serial].lineageId;
		let n = 0;
		for (const s of Object.keys(L)) if (L[s].lineageId === id) { L[s].frozen = true; n++; }
		writeJsonAtomic(LINEAGE_FILE, L);
		log("WARN", `Froze lineage ${id} (${n} certificate(s))`);
		return sendJson(res, 200, { ok: true, lineageId: id, frozen: n });
	});
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

	return withCaMutex(async () => {
	try {
		const { stdout, stderr } = await opensslCaLocked(args.slice(0));
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
	});
}

let stopping = false; // set by shutdown() below
const server = http.createServer(async (req, res) => {
	if (stopping) {
		// Graceful stop in progress (see shutdown() below): retryable refusal.
		res.shouldKeepAlive = false;
		return sendError(res, 503, "stopping", "Custodian is stopping; retry");
	}
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

		const auth = verifyRequest(req, bodyBuf);
		if (!auth.ok) {
			log("WARN", `Request authentication failed (${auth.why}) for ${req.method} ${req.url} from ${req.socket.remoteAddress}`);
			return sendError(res, 401, "invalid_signature", "Request authentication failed");
		}
		res.pqcNonce = auth.nonce;

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

		const resultMatch = /^\/sign-result\/([^/]+)$/.exec(url);
		if (req.method === "GET" && resultMatch) {
			return await handleSignResult(res, decodeURIComponent(resultMatch[1]));
		}

		const lineageMatch = /^\/lineage\/([^/]+)$/.exec(url);
		if (req.method === "GET" && lineageMatch) {
			return handleGetLineage(res, decodeURIComponent(lineageMatch[1]));
		}

		if (req.method === "POST" && url === "/lineage/freeze") {
			return await handleFreeze(res, payload);
		}

		return sendError(res, 404, "not_found", "No such endpoint");
	} catch (err) {
		log("ERROR", `Unhandled error: ${err && err.stack ? err.stack : err}`);
		if (!res.headersSent) sendError(res, 500, "internal_error", "Internal custodian error");
	}
});

server.listen(PORT, () => {
	log("INFO", `pqc-ca-custodian listening on :${PORT} (CA_DIR=${CA_DIR}, renewal=${RENEWAL_ENABLED ? "on" : "off"}, demo profile=${DEMO_PROFILE_ENABLED ? "on" : "off"})`);
});

// Graceful stop. As PID 1, node ignores SIGTERM unless it is handled, so every
// `docker stop` ended in SIGKILL after 10 s, possibly in the middle of a CA
// mutation. Now: refuse new requests (503, retryable), close idle keep-alive
// connections, and exit once the requests in progress have answered and the CA
// mutations already queued have finished, at most 8 s (below Docker's 10 s).
function shutdown(signal) {
	if (stopping) return;
	stopping = true;
	log("INFO", `${signal}: refusing new requests; finishing work in progress`);
	const bound = setTimeout(() => {
		log("WARN", "work still running after 8 s; exiting");
		process.exit(1);
	}, 8000);
	bound.unref();
	const closed = new Promise(resolve => server.close(resolve));
	server.closeIdleConnections();
	Promise.all([closed, caChain]).then(() => {
		log("INFO", "work finished; exiting");
		process.exit(0);
	});
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
