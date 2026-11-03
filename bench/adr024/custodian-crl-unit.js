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
	toInbox("/tmp/root-crl-initial.pem"); rej0 = (await metrics()).m.pqc_ca_root_crl_rejected_total;
	await req("POST", "/revoke", { serialNumber: await issue("r4") });
	m = (await metrics()).m;
	check("inbox: an OLDER root CRL (lower number) is refused, the newer stays", m.pqc_ca_root_crl_rejected_total > rej0 && fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer));
	toInbox("/tmp/root-crl-new.pem");

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
