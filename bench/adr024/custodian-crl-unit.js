// custodian-crl-unit.js: unit test of the custodian as the CRL issuer (ADR-024).
// Runs as root inside run-custodian-crl-unit.sh's throwaway container, against
// a throwaway PKI made by setup-pki.sh and moved into the custodian's layout by
// migrate-ca-state.sh forward. Starts custodian.js as its own uid 1003 several
// times with different settings, and acts as management-api (HMAC) and as the
// offline root-CRL operator (root key). Prints PASS/FAIL lines; exits 1 on any FAIL.
"use strict";
const http = require("http"), crypto = require("crypto"), fs = require("fs");
const { spawn, execFileSync } = require("child_process");

const O = "/opt/openssl/bin/openssl", CUST = "/repo/docker/pqc-ca-custodian/custodian.js";
const PKI = "/etc/pki/pqc-ca", ROOT = `${PKI}/root`; // host-only CAs (root key here)
const STATE = "/var/lib/pqc-ca/state", INBOX = "/var/lib/pqc-ca/inbox";
const PUB = "/var/lib/pqc-ca-public", STATUS = "/var/lib/pqc-ca-status", FAILFLAG = "/tmp/crl-fail";
const SECRET = fs.readFileSync("/t/hmac", "utf8").trim();
// Every CA path is the custodian's default (scripts/lib/ca-layout.sh).
const BASE_ENV = { PATH: process.env.PATH, HOME: "/tmp", CUSTODIAN_HMAC_SECRET_FILE: "/t/hmac", RENEWAL_ENABLED: "1", CUSTODIAN_DEMO_PROFILE: "1" };
const CRL_ENV = {};

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
	proc = spawn("setpriv", ["--reuid=1003", "--regid=1003", "--clear-groups", "node", CUST], { env: { ...BASE_ENV, ...extraEnv } });
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
// What ocsp-pq answers, run exactly as it runs: openssl ocsp as uid 1002, on the
// status snapshot, the public chain and its own key directory (one request, no
// network: -reqin / -respout).
function ocspStatus(serial) {
	const cert = `${STATE}/issued/${serial}.pem`, issuer = `${STATE}/certs/intermediate-ca.crt`;
	ossl(["ocsp", "-issuer", issuer, "-cert", cert, "-no_nonce", "-reqout", "/tmp/ocsp.req"]);
	try { fs.rmSync("/tmp/ocsp.resp"); } catch { /* first call */ }
	execFileSync("setpriv", ["--reuid=1002", "--regid=1002", "--clear-groups", O, "ocsp", "-index", `${STATUS}/index.txt`,
		"-CA", `${PUB}/ca-chain.crt`, "-rsigner", "/var/lib/pqc-ocsp/ocsp-pq.crt", "-rkey", "/var/lib/pqc-ocsp/ocsp-pq.key",
		"-reqin", "/tmp/ocsp.req", "-respout", "/tmp/ocsp.resp"], { ...osslEnv, stdio: "pipe" });
	const out = execFileSync(O, ["ocsp", "-respin", "/tmp/ocsp.resp", "-issuer", issuer, "-CAfile", `${PUB}/ca-chain.crt`, "-cert", cert], { ...osslEnv, stdio: "pipe" }).toString();
	return (/: (good|revoked|unknown)/.exec(out) || [, out.trim().slice(0, 60)])[1];
}
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
	let s, serial, r;
	// ------------------------------------------------------ fail-closed starts
	s = await start({ ...CRL_ENV, CRL_PUBLIC_DIR: "/nonexistent" }, { expectExit: true });
	check("a public directory it cannot write: the start-up pass fails, exits 1", s.exitCode === 1, s.exitCode);
	fs.writeFileSync("/tmp/wrong.key", ossl(["genpkey", "-algorithm", "ML-DSA-65"])); fs.chmodSync("/tmp/wrong.key", 0o644);
	s = await start({ ...CRL_ENV, CA_KEY_URI: "file:/tmp/wrong.key" }, { expectExit: true });
	check("CA_KEY_URI naming the wrong key: start-up pass fails, exits 1", s.exitCode === 1, `${s.exitCode} ${/CRL pass.*failed: (.*)/.exec(logs)?.[1] || ""}`.slice(0, 160));
	check("  ... and published nothing", fs.readdirSync(PUB).length === 0);

	// ------------------------------------------------------------- start-up
	fs.copyFileSync(`${ROOT}/crl/root-ca.crl`, "/tmp/root-crl-initial.pem");
	toInbox("/tmp/root-crl-initial.pem");
	s = await start(CRL_ENV);
	check("starts, healthz 200 after the start-up pass", s.exitCode === null, s.exitCode);
	const expected = ["ca-chain.crt", "combined-crl.pem", "hybrid-ca-chain.crt", "hybrid-combined-crl.pem", "intermediate-ca.crl", "intermediate-ca.crt", "root-ca.crl", "root-ca.crt"];
	check("public dir holds exactly the public artefacts", JSON.stringify(fs.readdirSync(PUB).sort()) === JSON.stringify(expected), fs.readdirSync(PUB).sort().join(","));
	check("public files are 0644", expected.every(f => mode(`${PUB}/${f}`) === "644"));
	check("status dir holds index.txt and index.txt.attr, 0640", fs.readdirSync(STATUS).sort().join(",") === "index.txt,index.txt.attr" && mode(`${STATUS}/index.txt`) === "640" && mode(`${STATUS}/index.txt.attr`) === "640", fs.readdirSync(STATUS).join(","));
	check("combined CRL: intermediate FIRST", /Intermediate/.test(firstIssuer(`${PUB}/hybrid-combined-crl.pem`)), firstIssuer(`${PUB}/hybrid-combined-crl.pem`).trim());
	const combined = fs.readFileSync(`${PUB}/hybrid-combined-crl.pem`, "utf8");
	check("combined CRL holds two CRLs", (combined.match(/BEGIN X509 CRL/g) || []).length === 2);
	let derOk = true;
	try { ossl(["crl", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crl`, "-noout", "-CAfile", `${STATE}/certs/intermediate-ca.crt`]); ossl(["crl", "-inform", "DER", "-in", `${PUB}/root-ca.crl`, "-noout"]); ossl(["x509", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crt`, "-noout"]); } catch { derOk = false; }
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
	let ocspRevoked = "", ocspGood = "", goodSerial = "";
	try { ocspRevoked = ocspStatus(serial); goodSerial = await issue("ocsp-good"); ocspGood = ocspStatus(goodSerial); } catch (e) { ocspRevoked = ocspRevoked || String(e.stderr || e.message).slice(0, 120); }
	check("OCSP, as ocsp-pq runs it (uid 1002, new paths): revoked for the revoked one", ocspRevoked === "revoked", ocspRevoked);
	check("OCSP: good for a certificate issued a moment ago (snapshot follows every sign)", ocspGood === "good", ocspGood);
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
	check("inbox: a newer valid root CRL is adopted and published", fs.readFileSync(`${PUB}/root-ca.crl`).equals(newDer), (logs.match(/(Adopted|Refused) root CRL[^\n]*/g) || []).slice(-1)[0]);
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

	// -------------------------------------------- existing behaviour
	check("bench/item4/custodian-unit.js all pass", itemUnitPasses(), lastUnit);
	let ocspAfter = ""; try { ocspAfter = ocspStatus(goodSerial); } catch (e) { ocspAfter = String(e.stderr || e.message).slice(0, 120); }
	const overlaps = fs.readFileSync(`${STATUS}/index.txt`, "utf8").split("\n").filter(l => l.startsWith("V")).map(l => l.split("\t")[5]).filter((d, i, a) => a.indexOf(d) !== i).length;
	check("OCSP still answers with renewal overlaps in the index (index.txt.attr in the snapshot)", ocspAfter === "good" && overlaps > 0, `${ocspAfter}, ${overlaps} overlapping subject(s)`);

	// ---------------------------------------------- one writer at a time
	const second = await new Promise(resolve => {
		const p2 = spawn("setpriv", ["--reuid=1003", "--regid=1003", "--clear-groups", "node", CUST], { env: { ...BASE_ENV, PORT: "8092" } });
		let out = ""; p2.stderr.on("data", d => { out += d; });
		p2.on("exit", code => resolve({ code, out }));
		setTimeout(() => p2.kill("SIGKILL"), 8000);
	});
	check("a second custodian on the same state refuses to start (writer lock)", second.code === 1 && /writer|holds/.test(second.out), `${second.code} ${second.out.trim().slice(-120)}`);
	let mig = "";
	try { execFileSync("/tmp/r/scripts/migrate-ca-state.sh", ["reverse"], { stdio: "pipe" }); mig = "ran"; } catch (e) { mig = String(e.stderr); }
	check("migrate-ca-state.sh reverse refuses while the custodian runs (writer lock)", /holds/.test(mig) && fs.existsSync(STATE), mig.trim().slice(-120));
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
	const ocspSafe = x => { try { return ocspStatus(x); } catch (e) { return String(e.stderr || e.message).slice(0, 100); } };
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

	// ---------------------------------- break-glass revocation (decision 8)
	const BG = "/tmp/r/scripts/ca-break-glass-revoke.sh", HYB = `${PUB}/hybrid-combined-crl.pem`;
	s = await start(CRL_ENV);
	const bg = await issue("breakglass");
	let bgOut = "";
	try { execFileSync(BG, [bg, "keyCompromise"], { stdio: "pipe" }); bgOut = "ran"; } catch (e) { bgOut = String(e.stderr); }
	check("break-glass refuses while the custodian runs, and changes nothing", /holds|running/.test(bgOut) && !serialsIn(HYB).has(bg), bgOut.trim().slice(-100));
	await stop();
	const nBefore = crlNumber(HYB);
	try { bgOut = execFileSync(BG, [bg, "keyCompromise"], { stdio: "pipe" }).toString(); } catch (e) { bgOut = "FAILED " + String(e.stderr); }
	check("with the custodian stopped: revoked, next CRL published with the serial, OCSP snapshot R", serialsIn(HYB).has(bg) && crlNumber(HYB) > nBefore && statusRow(bg) === "R", bgOut.trim().split("\n").slice(-3).join(" | "));
	let bgDer = true; try { ossl(["crl", "-inform", "DER", "-in", `${PUB}/intermediate-ca.crl`, "-noout"]); } catch { bgDer = false; }
	check("  ... combined CRL intermediate first, DER at the URL name parses", /Intermediate/.test(firstIssuer(HYB)) && bgDer);
	check("  ... files back to the custodian: state 1003, public 1003 0644", fs.statSync(`${STATE}/db/index.txt`).uid === 1003 && fs.statSync(HYB).uid === 1003 && mode(HYB) === "644");
	const nBg = crlNumber(HYB);
	s = await start(CRL_ENV);
	check("  ... the custodian starts on it: next CRL higher, the serial still revoked", s.exitCode === null && crlNumber(HYB) > nBg && serialsIn(HYB).has(bg), `${nBg} -> ${crlNumber(HYB)}`);
	await stop();

	// --------------------------------------------- revoke deadline (review 3)
	const ocspNow = x => { try { return ocspStatus(x); } catch (e) { return String(e.stderr || e.message).slice(0, 100); } };
	s = await start({ ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-delay:${FAILFLAG}`, REVOKE_CRL_DEADLINE_MS: "1500" });
	serial = await issue("slow");
	fs.writeFileSync(FAILFLAG, "");
	let t1 = Date.now();
	r = await req("POST", "/revoke", { serialNumber: serial });
	const took = Date.now() - t1;
	check("a CRL pass that hangs: revoke answers 202 pending at its deadline, not a timeout", r.status === 202 && r.j.crl === "pending" && took >= 1400 && took < 4000, `${r.status} ${took} ms`);
	check("  ... OCSP already answers revoked", ocspNow(serial) === "revoked", ocspNow(serial));
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
	const cn = fs.readFileSync(`${STATE}/db/crlnumber`, "utf8");
	fs.writeFileSync(`${STATE}/db/crlnumber`, "1000\n");   // rolled back below what was published
	s = await start(CRL_ENV, { expectExit: true });
	check("crlnumber rolled back below the published CRL: the pass refuses it, the custodian exits 1", s.exitCode === 1 && /is not above the last published/.test(logs), s.exitCode);
	fs.writeFileSync(`${STATE}/db/crlnumber`, cn);

	// ------------------------------- /metrics before the first pass (LOW)
	fs.writeFileSync(FAILFLAG, "");
	proc = spawn("setpriv", ["--reuid=1003", "--regid=1003", "--clear-groups", "node", CUST], { env: { ...BASE_ENV, ...CRL_ENV, CUSTODIAN_TEST_FAULT: `crl-delay:${FAILFLAG}` } });
	let early = null;
	for (let i = 0; i < 50 && !early; i++) { await sleep(100); try { const x = await metrics(); if (x.status === 200) early = x.m; } catch { /* not listening yet */ } }
	check("/metrics before the first CRL: no time gauges (never a misleading 0)", early && early.pqc_ca_crl_last_issued_timestamp_seconds === undefined && early.pqc_ca_crl_next_update_seconds === undefined && early.pqc_ca_crl_issue_failures_total === 0, JSON.stringify(early));
	fs.rmSync(FAILFLAG);
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
