# Engineering rules

These rules bind **every contributor to PQC-RA**, human or AI agent (Claude Code, Codex, Cursor,
Copilot or any other), in all three repositories: `pqc-mtls-gateway`, `pqc-mtls-management-api`
and the project vault. This file is the only copy. The other repositories point here and do not
restate it.

The owners are Rumen Doynov and Alexander Shestakov. Changing this file needs a PR approved by
both. A reviewer rejects a PR that breaks a rule, unless the break is an approved temporary step
(rule 4).

## 1. Fix the cause, not the symptom

A change that only makes something "work" or "hold together" is not a fix. Find why it fails and
change that. Not allowed:

| Workaround | Seen in this project | The fix is |
|---|---|---|
| Masking directories instead of not sharing them | `crl-renewer` mounts the whole CA tree read-write and hides `root/private`, `ocsp` and `internal-tls` behind empty mounts (`docker-compose.yml`) | mount only what the service needs, e.g. its own CRL output directory |
| Running as root or adding capabilities to get past permissions | the same service has no `user:`, drops ALL capabilities and adds `DAC_OVERRIDE` back, while it holds the intermediate CA key | a non-root uid that owns the directories it writes |
| Loosening file modes so several uids can read | `custodian-hmac` and `enroll-hmac` are bind-mounted at host mode 0644, commented as a "workaround" | each service reads a secret owned by its own uid |
| One shared secret for callers with different rights | done right once: `custodian-hmac` was split from `control-plane-hmac` so a leaked route-push secret cannot also mint or revoke certificates | one credential per caller, scoped to what that caller may do |
| `\|\| true`, `2>/dev/null`, sleeps or retries that hide failures | `crl_worker.lua` called a non-existent `/opt/openssl-3.6.0` with `2>/dev/null` and silently loaded zero revocations; a `\|\| true` in a build script swallowed exit 126 and made a base-image PR a silent no-op | capture the error and fail loud; a retry logs and reports the failure it retries (`7b39674`), a fixed sleep becomes a wait on a condition with a timeout |
| Hard-coded paths, versions or IPs | that same `3.6.0` path rotted on the 3.6.2 bump | one source of truth (`base.lock`, build args, config) that the image asserts (`4847cbc`) |
| Skipping or weakening a check or test to get green | `bench/verify-suite.sh` had no exit status, so the CI step "Negative controls" could never fail; the first response softened the poster's wording to "run by hand" instead of fixing the check (fixed in `83ead5e`) | fix the code or the check, never the expectation |

## 2. Standards first

Design from the applicable standard or recognised best practice, and name it, with the section,
in the PR description. Where the project departs from it, that is an ADR (rule 3).

| Area | Reference |
|---|---|
| TLS | RFC 9846 (TLS 1.3, obsoletes RFC 8446; cite 8446 where older text does) |
| Certificates, CRLs, OCSP | RFC 5280, RFC 6960 |
| Post-quantum algorithms | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) |
| CA operation and profiles | CA/Browser Forum Baseline Requirements, ETSI EN 319 411-1/-2 |
| Key management | NIST SP 800-57 Part 1 |
| Containers | NIST SP 800-190, CIS Docker Benchmark |
| Web and API | OWASP ASVS, OWASP API Security Top 10, RFC 8725 for JWTs |

Example: post-quantum-only client authentication rests on the `CertificateRequest`
`signature_algorithms` list (RFC 8446 §4.3.2), not on chain validation alone (RFC 5280 §6).
A chain-valid classical leaf under the ML-DSA intermediate is refused only because of
`ClientSignatureAlgorithms ML-DSA-65`.

## 3. A design change gets an ADR first

When the correct fix changes the design (a new trust boundary, mount layout, credential, protocol
or data flow), stop and write an ADR before the code. Do not ship a narrower patch and call it the
fix.

- **Where:** the vault, `70-Decisions/ADR-NNN-Title-In-Words.md`, the next free number, with the
  existing frontmatter (`type: adr`, `status`, `confidence: design`, `decided`, `updated`, `tags`)
  and the sections *Context*, *Decision*, *Alternatives considered*, *Consequences*. Without vault
  access, open an issue titled `ADR proposal: …` with the same four sections and an owner files it.
- **Example:** making `crl-renewer` non-root means moving CRL output out of the CA tree and
  re-pointing every CRL reader. That is a design change. It is written up only as an idea
  (vault `40-Security/CRL-Renewer-Writable-Output-Dir-Idea.md`), so `DAC_OVERRIDE` stays a
  workaround, not the fix, until an ADR decides it.

## 4. A temporary step needs a label, an exit and an owner's approval

A temporary step is allowed only if all three hold:

1. It is labelled where it lives (code, compose, config) with a greppable marker:
   `TEMPORARY: <why>. Exit: <condition that removes it>. Owner: <name>.`
   and listed under **Temporary steps** in the PR description.
2. It has an exit criterion someone can check and a named owner.
3. An owner (Rumen or Alexander) approves it explicitly in the PR review, naming the step.

Workarounds that predate these rules, such as those in rule 1, are not approved by default. Label
them when you next touch them, and do not copy them to new services.

## 5. Least privilege by default

Every service and every credential starts from:

- a non-root `user:`, `read_only: true` root filesystem, `cap_drop: [ALL]` with nothing added back,
  `no-new-privileges`;
- only the mounts it needs, read-only unless it writes them; never a shared tree with parts hidden;
- its own secret, owned by its uid and not world-readable;
- per-caller credentials with authorization scoped to that caller, decided on an immutable identity
  (certificate fingerprint), never on a requester-chosen field (the old `x-pqc-ou` header);
- no secret shared across trust boundaries or between environments.

Anything less is rule 4 plus, if lasting, an ADR. `management-api` is the model: non-root, no
mount of the CA tree, signing only through the custodian over its own HMAC.

## 6. Fail loud, fail closed

- Every control ships with a **negative test that proves it refuses**: a classical client
  certificate is refused at the handshake; an empty admin allowlist denies everyone; a non-ML-DSA
  CSR gets 400 before any CA-database write.
- **A check that cannot fail is a defect.** In the PR, show the new check going red on a broken
  input once.
- Errors are captured and surfaced, never discarded. "Nothing there" and "not known yet" must not
  look the same (`republishOnStartup()` once pushed an empty route set and erased live routing).
- Failing open is a design decision: ADR, never a default.

## 7. Evidence

- **Numbers** in docs, papers and talks come from raw data committed in this repository
  (`bench/`) with the method stated: which host role, date, N, stopwatch and configuration. The
  number rules in the vault's `CLAUDE.md` apply on top. A plausible number is not evidence the tool
  was right: the retracted 1.75× was a ratio of process start-up times.
- **Live systems:** no change, restart, deploy, test traffic or key operation on a live host
  without the owner's explicit approval for that action. Test on the isolated stand. On 2026-10-25
  a test aimed at the isolated stack opened handshakes to live `:8443`, because two copies of
  `issue-cert.sh` differed.
- **Report faithfully:** failures, skipped steps and what was not tested go in the PR. "Verified"
  means you ran it and saw the result.
- **Commits and publishing** follow the vault's standing rules: no AI co-author trailers, and no
  push, merge or publish unless an owner asked.

## PR checklist

Every PR description answers these, "none" where it applies:

- **Cause:** what was wrong, and why this change removes it.
- **Standard:** the reference and section followed (rule 2), or the ADR.
- **Negative test:** the test that proves the control refuses, and that it was seen to fail.
- **Temporary steps:** each one, with exit criterion and owner (rule 4).
- **Privileges:** any user, capability, mount or credential added or widened (rule 5).
- **Live systems:** touched or not; if touched, who approved.
- **Not done or not verified.**
