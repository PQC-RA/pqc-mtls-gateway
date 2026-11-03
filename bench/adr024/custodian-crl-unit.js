// custodian-crl-unit.js: unit test of the custodian as CRL issuer (ADR-024 PR 2).
// Runs as root inside run-custodian-crl-unit.sh's throwaway container, against
// a throwaway PKI made by setup-pki.sh. Starts custodian.js as uid 1001 several
// times with different settings, and acts as management-api (HMAC) and as the
// offline root-CRL operator (root key). Prints PASS/FAIL lines; exits 1 on any FAIL.
"use strict";
const http = require("http"), crypto = require("crypto"), fs = require("fs");
const { spawn, execFileSync } = require("child_process");

const O = "/opt/openssl/bin/openssl", CUST = "/repo/docker/pqc-ca-custodian/custodian.js";
const PKI = "/tmp/pki", INT = `${PKI}/intermediate`, ROOT = `${PKI}/root`;
const PUB = "/pub", STATUS = "/status", INBOX = "/inbox", FAILFLAG = "/tmp/crl-fail";
const SECRET = fs.readFileSync("/t/hmac", "utf8").trim();
const BASE_ENV = { PATH: process.env.PATH, HOME: "/tmp", CA_DIR: INT, CUSTODIAN_HMAC_SECRET_FILE: "/t/hmac", RENEWAL_ENABLED: "1", CUSTODIAN_DEMO_PROFILE: "1" };
const CRL_ENV = {
	CUSTODIAN_ISSUES_CRL: "1", CRL_PUBLIC_DIR: PUB, CRL_STATUS_DIR: STATUS, ROOT_CRL_INBOX: INBOX,
	ROOT_CA_CERT: `${ROOT}/certs/root-ca.crt`, CA_KEY_URI: `file:${INT}/private/intermediate-ca.key`,
};

const results = [];
const check = (name, cond, extra) => results.push(`${cond ? "PASS" : "FAIL"}  ${name}${extra !== undefined ? `  [${extra}]` : ""}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const osslEnv = { env: { ...process.env, OPENSSL_CONF: "/dev/null" } };
const ossl = args => execFileSync(O, args, osslEnv).toString();

// --- HMAC client, as management-api signs requests (custodian.js verifyRequest)
const sha = b => crypto.createHash("sha256").update(b).digest("hex");
const mac = d => crypto.createHmac("sha256", SECRET).update(d).digest("hex");
function req(method, path, body) {
	return new Promise((resolve, reject) => {
		const b = body ? Buffer.from(JSON.stringify(body)) : Buffer.alloc(0);
		const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString("hex");
		const r = http.request({ host: "127.0.0.1", port: 8091, method, path, headers: {
			"Content-Type": "application/json", "Content-Length": b.length, "X-Custodian-Timestamp": ts, "X-Custodian-Nonce": nonce,
			"X-Hub-Signature-256": "sha256=" + mac(`v2\n${method}\n${path}\n${ts}\n${nonce}\n${sha(b)}`) } }, rr => {
			const c = []; rr.on("data", d => c.push(d));
			rr.on("end", () => { const raw = Buffer.concat(c).toString(); let j = {}; try { j = JSON.parse(raw); } catch { /* text */ } resolve({ status: rr.statusCode, j, raw }); });
		});
		// A client timeout of its own, so a custodian that never answers fails
		// a check instead of hanging the suite.
		r.setTimeout(20_000, () => r.destroy(Object.assign(new Error("client timeout"), { code: "TIMEOUT" })));
		r.on("error", reject); r.end(b);
	});
}
const get = path => req("GET", path);
function metrics() {
	return new Promise((resolve, reject) => http.get({ host: "127.0.0.1", port: 8091, path: "/metrics" }, rr => {
		const c = []; rr.on("data", d => c.push(d));
		rr.on("end", () => { const m = {}; for (const l of Buffer.concat(c).toString().split("\n")) { const x = /^(\w+) (\S+)$/.exec(l); if (x) m[x[1]] = Number(x[2]); } resolve({ status: rr.statusCode, m }); });
	}).on("error", reject));
}

// --- custodian process control
let proc = null, logs = "";
async function start(extraEnv, { expectExit = false } = {}) {
	logs = "";
	proc = spawn("setpriv", ["--reuid=1001", "--regid=1001", "--clear-groups", "node", CUST], { env: { ...BASE_ENV, ...extraEnv } });
	proc.stdout.on("data", d => { logs += d; }); proc.stderr.on("data", d => { logs += d; });
	const exited = new Promise(r => proc.on("exit", code => r(code)));
	for (let i = 0; i < 100; i++) {
		const code = await Promise.race([exited, sleep(100).then(() => "running")]);
		if (code !== "running") { proc = null; return { exitCode: code }; }
		if (expectExit) continue;
		const h = await new Promise(r => http.get({ host: "127.0.0.1", port: 8091, path: "/healthz" }, rr => { rr.resume(); r(rr.statusCode); }).on("error", () => r(0)));
		if (h === 200) return { exitCode: null };
	}
	if (expectExit) { await stop(); return { exitCode: "still running" }; } // never leave it holding the port
	return { exitCode: null, timeout: true };
}
async function stop() {
	if (!proc) return;
	const p = proc; proc = null;
	await new Promise(r => { p.on("exit", r); p.kill("SIGTERM"); });
}
async function waitExit() {
	if (!proc) return;
	const p = proc; proc = null;
	if (p.exitCode !== null || p.signalCode !== null) return;
	await new Promise(r => p.on("exit", r));
}

// --- PKI helpers
let n = 0;
function csr(cn) {
	const k = `/tmp/crl-unit-k${++n}.pem`, c = `/tmp/crl-unit-c${n}.csr`; // not /tmp/kN: custodian-unit.js reuses those
	ossl(["genpkey", "-algorithm", "ML-DSA-65", "-out", k]);
	ossl(["req", "-new", "-key", k, "-subj", `/C=BG/O=ACME/OU=M2M-Client/CN=${cn}`, "-out", c]);
	return fs.readFileSync(c, "utf8");
}
async function issue(tag) {
	const r = await req("POST", "/sign", { csrPem: csr(`crl-unit-${tag}-${Date.now() % 1e6}`) });
	if (r.status !== 201) throw new Error(`sign ${tag}: ${r.status} ${r.raw}`);
	return r.j.serialNumber;
}
const serialsIn = (file, inform = "PEM") => new Set([...ossl(["crl", "-inform", inform, "-in", file, "-noout", "-text"]).matchAll(/Serial Number: ([0-9A-F]+)/g)].map(m => m[1]));
const crlNumber = (file, inform = "PEM") => BigInt(`0x${/crlNumber=0x([0-9A-Fa-f]+)/.exec(ossl(["crl", "-inform", inform, "-in", file, "-noout", "-crlnumber"]))[1]}`);
const firstIssuer = file => ossl(["crl", "-in", file, "-noout", "-issuer"]);
const statusRow = serial => (fs.readFileSync(`${STATUS}/index.txt`, "utf8").split("\n").find(l => l.split("\t")[3] === serial) || "").charAt(0);
const mode = f => (fs.statSync(f).mode & 0o777).toString(8);
// What an OCSP responder answers from the custodian's snapshot, run as ocsp-pq
// runs (uid 1002), one request, no network (-reqin / -respout).
function ocspStatus(serial) {
	const cert = `${INT}/issued/${serial}.pem`, issuer = `${INT}/certs/intermediate-ca.crt`;
	ossl(["ocsp", "-issuer", issuer, "-cert", cert, "-no_nonce", "-reqout", "/tmp/ocsp.req"]);
	try { fs.rmSync("/tmp/ocsp.resp"); } catch { /* first call */ }
	execFileSync("setpriv", ["--reuid=1002", "--regid=1002", "--clear-groups", O, "ocsp", "-index", `${STATUS}/index.txt`,
		"-CA", `${PUB}/ca-chain.crt`, "-rsigner", `${PKI}/ocsp/ocsp-pq.crt`, "-rkey", `${PKI}/ocsp/ocsp-pq.key`,
		"-reqin", "/tmp/ocsp.req", "-respout", "/tmp/ocsp.resp"], { ...osslEnv, stdio: "pipe" });
	const out = execFileSync(O, ["ocsp", "-respin", "/tmp/ocsp.resp", "-issuer", issuer, "-CAfile", `${PUB}/ca-chain.crt`, "-cert", cert], { ...osslEnv, stdio: "pipe" }).toString();
	return (/: (good|revoked|unknown)/.exec(out) || [, out.trim().slice(0, 60)])[1];
}
const ocspSafe = serial => { try { return ocspStatus(serial); } catch (e) { return String(e.stderr || e.message).slice(0, 100); } };
function rootCrl(out, extra = []) {
	execFileSync(O, ["ca", "-config", `${ROOT}/openssl-root.cnf`, "-gencrl", "-out", out, ...extra], { stdio: "ignore" });
}
function toInbox(file) {
	const tmp = `${INBOX}/.root-ca.crl.tmp`;
	fs.copyFileSync(file, tmp); fs.chmodSync(tmp, 0o644); fs.renameSync(tmp, `${INBOX}/root-ca.crl`);
}

// The existing custodian unit test (item 4) against the running custodian.
let lastUnit = "";
function itemUnitPasses() {
	let out = "";
	try { out = execFileSync("node", ["/repo/bench/item4/custodian-unit.js"]).toString(); } catch (e) { out = String(e.stdout || e.message); }
	const m = /(\d+)\/(\d+) passed/.exec(out);
	lastUnit = m ? m[0] : out.slice(-200);
	return Boolean(m && m[1] === m[2]);
}

(async () => {
	// ---------------------------------------------------------------- flag off
	let s = await start({});
	check("flag off: custodian starts", s.exitCode === null, s.exitCode);
	let serial = await issue("off");
	let r = await req("POST", "/revoke", { serialNumber: serial });
	check("flag off: revoke answers exactly as before (200 {ok:true}, no crl field)", r.status === 200 && r.raw === '{"ok":true}', `${r.status} ${r.raw}`);
	r = await get("/metrics");
	check("flag off: no /metrics (falls through to authenticated routes, 404)", r.status === 404, r.status);
	r = await req("POST", "/crl/issue");
	check("flag off: POST /crl/issue is 404 not_crl_issuer (management-api then uses the renewer)", r.status === 404 && r.j.error === "not_crl_issuer", `${r.status} ${r.j.error}`);
	check("flag off: nothing published", fs.readdirSync(PUB).length === 0, fs.readdirSync(PUB).join(","));
	check("flag off: bench/item4/custodian-unit.js all pass", itemUnitPasses(), lastUnit);
	await stop();

	// ------------------------------------------------------ fail-closed starts
	s = await start({ ...CRL_ENV, CRL_PUBLIC_DIR: "" }, { expectExit: true });
	check("flag on without CRL_PUBLIC_DIR: exits 1", s.exitCode === 1, s.exitCode);
	fs.writeFileSync("/tmp/wrong.key", ossl(["genpkey", "-algorithm", "ML-DSA-65"])); fs.chmodSync("/tmp/wrong.key", 0o644);
	s = await start({ ...CRL_ENV, CA_KEY_URI: "file:/tmp/wrong.key" }, { expectExit: true });
	check("CA_KEY_URI naming the wrong key: start-up pass fails, exits 1", s.exitCode === 1, `${s.exitCode} ${/CRL pass.*failed: (.*)/.exec(logs)?.[1] || ""}`.slice(0, 160));
	check("  ... and published nothing", fs.readdirSync(PUB).length === 0);

	// ------------------------------------------------------------- start-up
	fs.copyFileSync(`${ROOT}/crl/root-ca.crl`, "/tmp/root-crl-initial.pem");
	toInbox("/tmp/root-crl-initial.pem");
	s = await start(CRL_ENV);
	check("flag on: starts, healthz 200 after the start-up pass", s.exitCode === null, s.exitCode);
	const expected = ["ca-chain.crt", "combined-crl.pem", "hybrid-ca-chain.crt", "hybrid-combined-crl.pem", "intermediate-ca.crl", "intermediate-ca.crt", "root-ca.crl", "root-ca.crt"];
	check("public dir holds exactly the public artefacts", JSON.stringify(fs.readdirSync(PUB).sort()) === JSON.stringify(expected), fs.readdirSync(PUB).sort().join(","));
	check("public files are 0644", expected.every(f => mode(`${PUB}/${f}`) === "644"));
	check("status dir holds index.txt and index.txt.attr, 0640", fs.readdirSync(STATUS).sort().join(",") === "index.txt,index.txt.attr" && mode(`${STATUS}/index.txt`) === "640" && mode(`${STATUS}/index.txt.attr`) === "640", fs.readdirSync(STATUS).join(","));
	check("combined CRL: intermediate FIRST", /Intermediate/.test(firstIssuer(`${PUB}/hybrid-combined-crl.pem`)), firstIssuer(`${PUB}/hybrid-combined-crl.pem`).trim());
	const combined = fs.readFileSync(`${PUB}/hybrid-combined-crl.pem`, "utf8");
	check("combined CRL holds two CRLs", (combined.match(/BEGIN X509 CRL/g) || []).length === 2);
	let derOk = true;
	try { ossl(["crl", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crl`, "-noout", "-CAfile", `${INT}/certs/intermediate-ca.crt`]); ossl(["crl", "-inform", "DER", "-in", `${PUB}/root-ca.crl`, "-noout"]); ossl(["x509", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crt`, "-noout"]); } catch { derOk = false; }
	check("files at certificate URLs are DER and parse (RFC 5280 4.2.1.13, 4.2.2.1)", derOk);
	let m = (await metrics()).m;
	check("metrics: last issued now, next update ~7 d, no failures, nothing pending", Math.abs(m.pqc_ca_crl_last_issued_timestamp_seconds - Date.now() / 1000) < 30 && Math.abs(m.pqc_ca_crl_next_update_seconds - 7 * 86400) < 120 && m.pqc_ca_crl_issue_failures_total === 0 && m.pqc_ca_crl_pending === 0, JSON.stringify(m));
	const n0 = crlNumber(`${PUB}/hybrid-combined-crl.pem`);

	// ------------------------------------------------------ sign and revoke
	serial = await issue("a");
	check("sign: OCSP snapshot carries the new certificate at once (V)", statusRow(serial) === "V", statusRow(serial));
	let t0 = Date.now();
	r = await req("POST", "/revoke", { serialNumber: serial, reason: "keyCompromise" });
	const revokeMs = Date.now() - t0;
	const n1 = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	check("revoke: 200, crl published, CRL number in the answer", r.status === 200 && r.j.crl === "published" && BigInt(r.j.crlNumber) === n1, `${r.status} ${r.raw} ${revokeMs} ms`);
	check("revoke: serial in the combined CRL's FIRST block when the call returns", serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial));
	check("revoke: serial in the DER intermediate CRL", serialsIn(`${PUB}/intermediate-ca.crl`, "DER").has(serial));
	check("revoke: OCSP snapshot shows R", statusRow(serial) === "R", statusRow(serial));
	check("CRL number went up", n1 > n0, `${n0} -> ${n1}`);
	r = await req("POST", "/revoke", { serialNumber: serial });
	check("revoke again: 409 already_revoked, as before", r.status === 409 && r.j.error === "already_revoked", r.status);
	const nm = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	r = await req("POST", "/crl/issue");
	check("POST /crl/issue: 200 with a new, higher CRL number", r.status === 200 && r.j.crl === "published" && BigInt(r.j.crlNumber) > nm && crlNumber(`${PUB}/hybrid-combined-crl.pem`) === BigInt(r.j.crlNumber), `${r.status} ${r.raw}`);

	// ------------------------------------------------------------- batching
	const batch = [];
	for (let i = 0; i < 6; i++) batch.push(await issue(`b${i}`));
	const nb = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	const answers = await Promise.all(batch.map(x => req("POST", "/revoke", { serialNumber: x })));
	const after = serialsIn(`${PUB}/hybrid-combined-crl.pem`), nAfter = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	check("burst of 6 revocations: all 200 published", answers.every(a => a.status === 200 && a.j.crl === "published"), answers.map(a => a.status).join(","));
	check("burst: all 6 serials in the CRL", batch.every(x => after.has(x)));
	check("burst: fewer CRLs than revocations (batched)", nAfter - nb < 6n && nAfter > nb, `${nAfter - nb} CRL(s) for 6`);

	// --------------------------------------------------------- root CRL inbox
	const rootNow = fs.readFileSync(`${PUB}/root-ca.crl`);
	// A CRL from an unrelated CA that copies the root's name: right subject,
	// wrong key. Its own throwaway database, so no real CA state is touched.
	fs.mkdirSync("/tmp/wca", { recursive: true }); fs.writeFileSync("/tmp/wca/index.txt", ""); fs.writeFileSync("/tmp/wca/crlnumber", "7FFFFFFF\n");
	const rootSubject = ossl(["x509", "-in", `${ROOT}/certs/root-ca.crt`, "-noout", "-subject", "-nameopt", "compat"]).replace(/^subject=/, "").trim();
	ossl(["req", "-x509", "-newkey", "ML-DSA-65", "-nodes", "-subj", rootSubject, "-days", "2", "-keyout", "/tmp/wca/ca.key", "-out", "/tmp/wca/ca.crt"]);
	fs.writeFileSync("/tmp/wca/ca.cnf", "[ca]\ndefault_ca=c\n[c]\ndir=/tmp/wca\ndatabase=$dir/index.txt\ncrlnumber=$dir/crlnumber\ncertificate=$dir/ca.crt\nprivate_key=$dir/ca.key\ndefault_md=default\ndefault_crl_days=30\n");
	ossl(["ca", "-config", "/tmp/wca/ca.cnf", "-gencrl", "-out", "/tmp/root-crl-wrong-signer.pem"]);
	toInbox("/tmp/root-crl-wrong-signer.pem");
	m = (await metrics()).m; let rej0 = m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r1") });
	m = (await metrics()).m;
	check("inbox: a CRL not signed by the root is refused, published root CRL unchanged", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(rootNow), m.pqc_ca_root_crl_rejected_total);
	rootCrl("/tmp/root-crl-expired.pem", ["-crl_lastupdate", "20200101000000Z", "-crl_nextupdate", "20200102000000Z"]);
	toInbox("/tmp/root-crl-expired.pem"); rej0 = m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r2") });
	m = (await metrics()).m;
	check("inbox: an expired root CRL is refused", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(rootNow));
	rootCrl("/tmp/root-crl-new.pem");
	toInbox("/tmp/root-crl-new.pem");
	await req("POST", "/revoke", { serialNumber: await issue("r3") });
	const newDer = execFileSync(O, ["crl", "-in", "/tmp/root-crl-new.pem", "-outform", "DER"]);
	check("inbox: a newer valid root CRL is adopted and published", fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer));
	check("  ... and the combined CRL carries it second", fs.readFileSync(`${PUB}/hybrid-combined-crl.pem`, "utf8").endsWith(fs.readFileSync("/tmp/root-crl-new.pem", "utf8")));
	// Each of the two "newer" rules on its own.
	const rootNum = fs.readFileSync(`${ROOT}/db/crlnumber`, "utf8");
	fs.writeFileSync(`${ROOT}/db/crlnumber`, "1000\n");      // number rolled back, lastUpdate now (later)
	rootCrl("/tmp/root-crl-lower-number.pem");
	fs.writeFileSync(`${ROOT}/db/crlnumber`, rootNum);
	toInbox("/tmp/root-crl-lower-number.pem"); rej0 = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r5") });
	m = (await metrics()).m;
	check("inbox: a later lastUpdate does not help a LOWER CRL number: refused", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer) && /not above/.test(logs), m.pqc_ca_root_crl_rejected_total);
	rootCrl("/tmp/root-crl-old-lastupdate.pem", ["-crl_lastupdate", "20200101000000Z", "-crl_nextupdate", "20991231000000Z"]);
	toInbox("/tmp/root-crl-old-lastupdate.pem"); rej0 = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r6") });
	m = (await metrics()).m;
	check("inbox: a higher number does not help an OLDER lastUpdate: refused", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer) && /lastUpdate \S+ is earlier/.test(logs), m.pqc_ca_root_crl_rejected_total);
	toInbox("/tmp/root-crl-initial.pem"); rej0 = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r4") });
	m = (await metrics()).m;
	check("inbox: an OLDER root CRL (lower number) is refused, the newer stays", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer));
	toInbox("/tmp/root-crl-new.pem");
	// The case that made this test flaky once: a root CRL with a higher number
	// and the SAME lastUpdate second as the published one is newer (RFC 5280
	// 5.2.3 orders CRLs by number; lastUpdate has one-second resolution).
	const pubLast = /lastUpdate=(\S+) (\S+)Z/.exec(ossl(["crl", "-inform", "DER", "-in", `${PUB}/root-ca.crl`, "-noout", "-lastupdate", "-dateopt", "iso_8601"]));
	rootCrl("/tmp/root-crl-tie.pem", ["-crl_lastupdate", `${pubLast[1].replace(/-/g, "")}${pubLast[2].replace(/:/g, "")}Z`]);
	toInbox("/tmp/root-crl-tie.pem");
	await req("POST", "/revoke", { serialNumber: await issue("r7") });
	const tieDer = execFileSync(O, ["crl", "-in", "/tmp/root-crl-tie.pem", "-outform", "DER"]);
	check("inbox: a higher number in the same lastUpdate second is adopted (CRL numbers order CRLs)", fs.readFileSync(`${PUB}/root-ca.crl`).equals(tieDer), (logs.match(/(Adopted|Refused) root CRL[^\n]*/g) || []).slice(-1)[0]);

	// -------------------------------------------- existing behaviour, flag on
	check("flag on: bench/item4/custodian-unit.js all pass", itemUnitPasses(), lastUnit);
	await stop();

	// ------------------------------------------ restart keeps numbers rising
	const beforeRestart = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	s = await start(CRL_ENV);
	check("restart: start-up pass publishes a HIGHER CRL number", s.exitCode === null && crlNumber(`${PUB}/hybrid-combined-crl.pem`) > beforeRestart, `${beforeRestart} -> ${crlNumber(`${PUB}/hybrid-combined-crl.pem`)}`);
	await stop();

	// ------------------------------------------------- 202 and the retry loop
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-fail:${FAILFLAG}` });
	serial = await issue("pending");
	fs.writeFileSync(FAILFLAG, "");
	r = await req("POST", "/revoke", { serialNumber: serial });
	m = (await metrics()).m;
	check("CRL fails after the revocation is recorded: 202, crl pending", r.status === 202 && r.j.crl === "pending" && r.j.ok === true, `${r.status} ${r.raw}`);
	check("  ... pending metric 1, failure counted", m.pqc_ca_crl_pending === 1 && m.pqc_ca_crl_issue_failures_total >= 1, JSON.stringify(m));
	check("  ... and the serial is in no published CRL yet", !serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial));
	check("  ... but the OCSP snapshot already says R and OCSP answers revoked (snapshot after every index change)", statusRow(serial) === "R" && ocspSafe(serial) === "revoked", `${statusRow(serial)} ${ocspSafe(serial)}`);
	r = await req("POST", "/crl/issue");
	check("  ... POST /crl/issue while the CRL fails: 503 crl_failed (retryable), not 500", r.status === 503 && r.j.error === "crl_failed", `${r.status} ${r.j.error}`);
	fs.rmSync(FAILFLAG);
	let published = false;
	for (let i = 0; i < 40 && !published; i++) { await sleep(250); published = serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial); }
	m = (await metrics()).m;
	check("  ... the retry publishes it once the fault clears (backoff from 1 s)", published && m.pqc_ca_crl_pending === 0, `published=${published}`);
	await stop();

	// -------------------------------------- crash between revoke and publish
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: "crash-after-revoke" });
	serial = await issue("crash");
	r = await req("POST", "/revoke", { serialNumber: serial }).catch(e => ({ status: "connection " + e.code }));
	await waitExit();
	check("crash after the revocation was recorded: no answer, serial in no CRL yet", String(r.status).startsWith("connection") && !serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial), r.status);
	s = await start(CRL_ENV);
	check("  ... after restart the start-up pass publishes it", s.exitCode === null && serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial));
	await stop();

	// ------------------------------------------------------------- schedule
	s = await start({ ...CRL_ENV, CRL_REISSUE_AFTER_S: "3" });
	const ns = crlNumber(`${PUB}/hybrid-combined-crl.pem`);
	await sleep(5500);
	check("schedule: a new CRL without any revocation once it falls due", crlNumber(`${PUB}/hybrid-combined-crl.pem`) > ns, `${ns} -> ${crlNumber(`${PUB}/hybrid-combined-crl.pem`)}`);
	await stop();

	// --------------------------------------------- revoke deadline (review 3)
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-delay:${FAILFLAG}`, REVOKE_CRL_DEADLINE_MS: "1500" });
	serial = await issue("slow");
	fs.writeFileSync(FAILFLAG, "");
	let t1 = Date.now();
	r = await req("POST", "/revoke", { serialNumber: serial });
	const took = Date.now() - t1;
	check("a CRL pass that hangs: revoke answers 202 pending at its deadline, not a timeout", r.status === 202 && r.j.crl === "pending" && took >= 1400 && took < 4000, `${r.status} ${took} ms`);
	check("  ... OCSP already answers revoked", ocspSafe(serial) === "revoked", ocspSafe(serial));
	fs.rmSync(FAILFLAG);
	let late = false;
	for (let i = 0; i < 40 && !late; i++) { await sleep(250); late = serialsIn(`${PUB}/hybrid-combined-crl.pem`).has(serial); }
	check("  ... the pass that was running publishes it once it completes", late);
	await stop();

	// ------------------------------------------ backoff cap (review 7)
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-fail:${FAILFLAG}`, CRL_RETRY_MAX_MS: "2000" });
	serial = await issue("backoff");
	fs.writeFileSync(FAILFLAG, "");
	await req("POST", "/revoke", { serialNumber: serial });
	await sleep(8000);
	const delays = [...logs.matchAll(/CRL retry in (\d+) ms/g)].map(x => Number(x[1]));
	check("retry backoff doubles from 1 s and stops at its cap (here 2 s; 60 s by default)", delays[0] === 1000 && delays.includes(2000) && Math.max(...delays) === 2000 && delays.length >= 4, delays.join(","));
	fs.rmSync(FAILFLAG);
	await stop();

	// ------------------------------------ overdue exit (review 7)
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-fail:${FAILFLAG}`, CRL_REISSUE_AFTER_S: "2", CRL_OVERDUE_EXIT_S: "2" });
	fs.writeFileSync(FAILFLAG, "");
	const exitCode = await new Promise(resolve => { const p0 = proc; p0.on("exit", code => resolve(code)); setTimeout(() => resolve("still running"), 15000); });
	proc = null;
	check("no CRL for longer than CRL_OVERDUE_EXIT_S past schedule: the custodian exits 1 (the restart policy acts)", exitCode === 1 && /exiting so the restart policy acts/.test(logs), exitCode);
	fs.rmSync(FAILFLAG);

	// ------------------------------- CRL number never goes back (review 7)
	const cn = fs.readFileSync(`${INT}/db/crlnumber`, "utf8");
	fs.writeFileSync(`${INT}/db/crlnumber`, "1000\n");   // rolled back below what was published
	s = await start(CRL_ENV, { expectExit: true });
	check("crlnumber rolled back below the published CRL: the pass refuses it, the custodian exits 1", s.exitCode === 1 && /is not above the last published/.test(logs), s.exitCode);
	fs.writeFileSync(`${INT}/db/crlnumber`, cn);

	// ------------------------------- /metrics before the first pass (LOW)
	fs.writeFileSync(FAILFLAG, "");
	proc = spawn("setpriv", ["--reuid=1001", "--regid=1001", "--clear-groups", "node", CUST], { env: { ...BASE_ENV, ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-delay:${FAILFLAG}` } });
	let early = null;
	for (let i = 0; i < 50 && !early; i++) { await sleep(100); try { const x = await metrics(); if (x.status === 200) early = x.m; } catch { /* not listening yet */ } }
	check("/metrics before the first CRL: no time gauges (never a misleading 0)", early && early.pqc_ca_crl_last_issued_timestamp_seconds === undefined && early.pqc_ca_crl_next_update_seconds === undefined && early.pqc_ca_crl_issue_failures_total === 0, JSON.stringify(early));
	fs.rmSync(FAILFLAG);
	await stop();

	// ------------------- guards from the re-review of 2026-11-03 (#9 items)
	// An openssl that hangs or fails on purpose, for the custodian only.
	fs.writeFileSync("/tmp/fake-openssl", `#!/bin/sh
case " $* " in
  *" -gencrl "*) [ -e /tmp/hang ] && exec sleep 600 ;;
  *" -updatedb "*) [ -e /tmp/updb-fail ] && { echo "forced -updatedb failure" >&2; exit 1; } ;;
esac
exec ${O} "$@"
`, { mode: 0o755 });
	const HYB2 = `${PUB}/hybrid-combined-crl.pem`;

	// a hung openssl is killed by the exec timeout; the revoke still answers
	s = await start({ ...CRL_ENV, OPENSSL_BIN: "/tmp/fake-openssl", EXEC_TIMEOUT_MS: "1500" });
	serial = await issue("hang");
	fs.writeFileSync("/tmp/hang", "");
	let th = Date.now();
	r = await req("POST", "/revoke", { serialNumber: serial });
	const hangMs = Date.now() - th;
	let sleeping = ""; try { sleeping = execFileSync("pgrep", ["-f", "sleep 600"]).toString().trim(); } catch { /* none left: pgrep exits 1 */ }
	m = (await metrics()).m;
	check("a hung openssl is SIGKILLed at EXEC_TIMEOUT_MS: revoke answers 202, no hung process is left", r.status === 202 && hangMs < 4000 && sleeping === "" && m.pqc_ca_crl_issue_failures_total >= 1, `${r.status} ${hangMs} ms, left: '${sleeping}'`);
	fs.rmSync("/tmp/hang");
	let back = false;
	for (let i = 0; i < 40 && !back; i++) { await sleep(250); back = serialsIn(HYB2).has(serial); }
	check("  ... and the retry publishes it once openssl behaves", back);

	// a failed -updatedb fails the pass (counted) instead of signing on
	fs.writeFileSync("/tmp/updb-fail", "");
	const nUpd = crlNumber(HYB2), u0 = (await metrics()).m.pqc_ca_crl_updatedb_failures_total;
	r = await req("POST", "/crl/issue");
	m = (await metrics()).m;
	check("-updatedb fails: the pass fails (503), counted, no new CRL", r.status === 503 && m.pqc_ca_crl_updatedb_failures_total > u0 && crlNumber(HYB2) === nUpd, `${r.status} ${u0}->${m.pqc_ca_crl_updatedb_failures_total}`);
	fs.rmSync("/tmp/updb-fail");

	// the inbox counts a refused file once, not on every pass
	rootCrl("/tmp/root-crl-expired2.pem", ["-crl_lastupdate", "20200101000000Z", "-crl_nextupdate", "20200102000000Z"]);
	toInbox("/tmp/root-crl-expired2.pem");
	const rj0 = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	for (let i = 0; i < 3; i++) await req("POST", "/crl/issue");
	check("inbox: one refused file is counted once over three passes", (await metrics()).m.pqc_ca_root_crl_rejected_total === rj0 + 1, `${rj0} -> ${(await metrics()).m.pqc_ca_root_crl_rejected_total}`);
	toInbox("/tmp/root-crl-tie.pem");

	// the publisher checks the order of what it publishes
	fs.writeFileSync("/tmp/root-first", "");
	await stop();
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: "combined-root-first:/tmp/root-first" }, { expectExit: true });
	check("a combined CRL that would start with the root CRL is never published (start-up pass refused)", s.exitCode === 1 && /would start with/.test(logs) && /Intermediate/.test(firstIssuer(HYB2)), s.exitCode);
	fs.rmSync("/tmp/root-first");

	// the whole request stays within its budget even behind a stalled pass
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-delay:${FAILFLAG}`, MUTEX_WAIT_MS: "1000" });
	serial = await issue("busy");
	fs.writeFileSync(FAILFLAG, "");
	const stalled = req("POST", "/crl/issue");   // a pass that holds the mutex
	await sleep(300);
	let tb = Date.now();
	r = await req("POST", "/revoke", { serialNumber: serial }).catch(e => ({ status: e.code, j: {} }));
	const busyMs = Date.now() - tb;
	check("behind a stalled pass, revoke answers 503 busy at MUTEX_WAIT_MS and records nothing", r.status === 503 && r.j.error === "busy" && busyMs < 3000 && statusRow(serial) === "V" && fs.readFileSync(`${INT}/db/index.txt`, "utf8").split("\n").some(l => l.startsWith("V") && l.split("\t")[3] === serial), `${r.status} ${r.j.error} ${busyMs} ms`);
	fs.rmSync(FAILFLAG); await stalled;
	r = await req("POST", "/revoke", { serialNumber: serial });
	check("  ... and the same revoke succeeds once the CA is free", r.status === 200, r.status);
	await stop();

	// an openssl run killed between its two renames: recovered at start
	fs.copyFileSync(`${INT}/db/index.txt`, `${INT}/db/index.txt.new`);
	fs.renameSync(`${INT}/db/index.txt`, `${INT}/db/index.txt.old`);
	const want = fs.readFileSync(`${INT}/db/index.txt.new`);
	s = await start(CRL_ENV);
	check("index.txt missing after an interrupted rename: recovered from .new at start, custodian serves", s.exitCode === null && fs.existsSync(`${INT}/db/index.txt`) && /Recovered .*index\.txt from index\.txt\.new/.test(logs) && fs.readFileSync(`${INT}/db/index.txt`).length >= want.length, s.exitCode);
	await stop();

	// ------------------------------ pre-merge review of 2026-11-03 (#7 items)
	fs.writeFileSync("/tmp/fake-openssl", `#!/bin/sh
case " $* " in
  *" -revoke "*) if [ -e /tmp/revoke-hang ]; then ${O} "$@"; exec sleep 600; fi ;;
  *" -gencrl "*) [ -e /tmp/future-crl ] && exec ${O} "$@" -crl_lastupdate 20991231000000Z -crl_nextupdate 21000107000000Z ;;
  *" -CAfile ${ROOT}/certs/root-ca.crt "*) [ -e /tmp/root-verify-fail ] && { echo "forced root CRL verify failure" >&2; exit 1; } ;;
esac
exec ${O} "$@"
`, { mode: 0o755 });
	const ROOT_CRL_FILE = `${INT}/crl/root-ca.crl`;
	s = await start({ ...CRL_ENV, OPENSSL_BIN: "/tmp/fake-openssl", EXEC_TIMEOUT_MS: "1500", INBOX_RELOG_MS: "1000", CUSTODIAN_TEST_FAULT: `crl-fail:${FAILFLAG}` });

	// 7-2: openssl killed after it recorded the revocation
	const k1 = await issue("killed");
	fs.writeFileSync("/tmp/revoke-hang", "");
	r = await req("POST", "/revoke", { serialNumber: k1 });
	fs.rmSync("/tmp/revoke-hang");
	check("7-2: revoke killed after openssl recorded it: answered as recorded (200 published), CRL and OCSP carry it", r.status === 200 && r.j.crl === "published" && serialsIn(HYB2).has(k1) && statusRow(k1) === "R", `${r.status} ${JSON.stringify(r.j)}`);
	const k2 = await issue("retry");
	fs.writeFileSync(FAILFLAG, "");
	fs.writeFileSync("/tmp/revoke-hang", "");
	r = await req("POST", "/revoke", { serialNumber: k2 });
	fs.rmSync("/tmp/revoke-hang");
	check("  ... with the CRL failing too: 202 pending, OCSP already R", r.status === 202 && r.j.crl === "pending" && statusRow(k2) === "R", `${r.status} ${JSON.stringify(r.j)}`);
	r = await req("POST", "/revoke", { serialNumber: k2 });
	check("7-2: retrying a revoke that is recorded but in no published CRL is not a bare 409: it requests the CRL (202 pending)", r.status === 202 && r.j.crl === "pending", `${r.status} ${JSON.stringify(r.j)}`);
	fs.rmSync(FAILFLAG);
	let k2pub = false;
	for (let i = 0; i < 60 && !k2pub; i++) { await sleep(250); k2pub = serialsIn(HYB2).has(k2); }
	r = await req("POST", "/revoke", { serialNumber: k2 });
	check("  ... once a CRL lists it, a retry is 409 already_revoked", k2pub && r.status === 409, `${k2pub} ${r.status}`);

	// 7-1: lastUpdate in the future, the root's and our own
	const rootBefore = fs.readFileSync(ROOT_CRL_FILE);
	let rj = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	rootCrl("/tmp/root-crl-future.pem", ["-crl_lastupdate", "20991231000000Z", "-crl_nextupdate", "21000107000000Z"]);
	toInbox("/tmp/root-crl-future.pem");
	await req("POST", "/crl/issue");
	check("7-1: a root CRL with lastUpdate in the future is not adopted, counted", fs.readFileSync(ROOT_CRL_FILE).equals(rootBefore) && (await metrics()).m.pqc_ca_root_crl_rejected_total === rj + 1 && /in the future/.test(logs), (await metrics()).m.pqc_ca_root_crl_rejected_total - rj);
	await sleep(1200);
	await req("POST", "/crl/issue");
	check("7-3: ... not cached as refused: tried again, reported again at the low rate, counted once", /still not adopted: its lastUpdate/.test(logs) && (await metrics()).m.pqc_ca_root_crl_rejected_total === rj + 1);
	rootCrl("/tmp/root-crl-fixed.pem");
	toInbox("/tmp/root-crl-fixed.pem");
	await req("POST", "/crl/issue");
	check("7-1: ... and the corrected root CRL after it is adopted (no outage until the bogus date)", fs.readFileSync(ROOT_CRL_FILE).equals(fs.readFileSync("/tmp/root-crl-fixed.pem")));
	const pubBefore = fs.readFileSync(HYB2);
	fs.writeFileSync("/tmp/future-crl", "");
	r = await req("POST", "/crl/issue");
	fs.rmSync("/tmp/future-crl");
	check("7-1: the custodian's own CRL with lastUpdate in the future is not published (503)", r.status === 503 && /in the future/.test(r.raw) && fs.readFileSync(HYB2).equals(pubBefore), `${r.status} ${r.raw.slice(0, 120)}`);

	// 7-3: a transient refusal (openssl failed) is not cached
	rootCrl("/tmp/root-crl-transient.pem");
	fs.writeFileSync("/tmp/root-verify-fail", "");
	toInbox("/tmp/root-crl-transient.pem");
	await req("POST", "/crl/issue");
	const stillOld = fs.readFileSync(ROOT_CRL_FILE).equals(fs.readFileSync("/tmp/root-crl-fixed.pem"));
	fs.rmSync("/tmp/root-verify-fail");
	await req("POST", "/crl/issue");
	check("7-3: an inbox file refused for a transient reason is adopted once it can be (not cached)", stillOld && fs.readFileSync(ROOT_CRL_FILE).equals(fs.readFileSync("/tmp/root-crl-transient.pem")));

	// 7-5: no CRL may drop a revoked serial
	const idxFile = `${INT}/db/index.txt`, idx = fs.readFileSync(idxFile, "utf8");
	fs.writeFileSync(idxFile, idx.split("\n").map(l => { const f = l.split("\t"); if (f[3] === k1) { f[0] = "V"; f[2] = ""; } return f.join("\t"); }).join("\n"));
	const pubB = fs.readFileSync(HYB2);
	r = await req("POST", "/crl/issue");
	fs.writeFileSync(idxFile, idx);
	check("7-5: an intermediate CRL that would drop a revoked serial is not published", r.status === 503 && /drops revoked serial/.test(r.raw) && fs.readFileSync(HYB2).equals(pubB), `${r.status} ${r.raw.slice(0, 140)}`);
	const rootIdx = `${ROOT}/db/index.txt`, rootIdxOrig = fs.readFileSync(rootIdx, "utf8");
	fs.writeFileSync(rootIdx, rootIdxOrig + "R\t301231000000Z\t251103000000Z\tDEADBEEF01\tunknown\t/CN=unit-fake\n");
	rootCrl("/tmp/root-crl-with.pem");
	toInbox("/tmp/root-crl-with.pem");
	await req("POST", "/crl/issue");
	const adoptedWith = fs.readFileSync(ROOT_CRL_FILE).equals(fs.readFileSync("/tmp/root-crl-with.pem"));
	fs.writeFileSync(rootIdx, rootIdxOrig);
	rootCrl("/tmp/root-crl-without.pem");
	toInbox("/tmp/root-crl-without.pem");
	await req("POST", "/crl/issue");
	check("7-5: a newer root CRL that drops a serial the published one lists is refused", adoptedWith && fs.readFileSync(ROOT_CRL_FILE).equals(fs.readFileSync("/tmp/root-crl-with.pem")) && /drops revoked serial\(s\) DEADBEEF01/.test(logs));

	// 7-6: the -updatedb metric says what happens
	r = await get("/metrics");
	check("7-6: the -updatedb failure metric's HELP says the pass fails", /pqc_ca_crl_updatedb_failures_total Runs of openssl ca -updatedb that failed; each failed its CRL pass/.test(r.raw));
	await stop();

	// 7-4: what is published is what was checked
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: "crl-tamper:/tmp/tamper" });
	fs.writeFileSync("/tmp/tamper", "");
	r = await req("POST", "/crl/issue");
	fs.rmSync("/tmp/tamper");
	check("7-4: the file replaced right after it is written: the checked CRL is still what is published (DER and combined)", r.status === 200 && /Intermediate/.test(ossl(["crl", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crl`, "-noout", "-issuer"])) && /Intermediate/.test(firstIssuer(HYB2)) && crlNumber(HYB2) === BigInt(r.j.crlNumber), `${r.status} ${r.raw.slice(0, 120)}`);
	await stop();
	s = await start(CRL_ENV);
	r = s.exitCode === null ? await req("POST", "/crl/issue") : { status: 0, raw: "" };
	check("7-5: the intermediate CRL file left replaced by 7-4 is not taken as the baseline of revoked serials (said), the pass publishes", s.exitCode === null && /not a verifiable intermediate CRL/.test(logs) && r.status === 200, `${s.exitCode} ${r.status}`);
	await stop();

	// ----------------------------------------- start-up failure fails closed
	fs.writeFileSync(FAILFLAG, "");
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-fail:${FAILFLAG}` }, { expectExit: true });
	check("start-up pass fails: exits 1 instead of serving without a CRL", s.exitCode === 1, s.exitCode);
	fs.rmSync(FAILFLAG);

	console.log(results.join("\n"));
	const pass = results.filter(x => x.startsWith("PASS")).length;
	console.log(`${pass}/${results.length} passed (revoke-to-published ${revokeMs} ms in this container)`);
	process.exit(pass === results.length ? 0 : 1);
})().catch(async e => { console.log(results.join("\n")); console.log("ERROR", e.stack); console.log(logs.slice(-2000)); await stop(); process.exit(1); });
