# @loxeai/mcp-server

An MCP server for SOC 2 compliance work that runs entirely on your machine.

It scans your Infrastructure-as-Code, maps findings to SOC 2 Trust Services Criteria, explains them in plain English, and drafts the documents an audit will ask for. No account. No signup. No network calls. Your files never leave the laptop.

```bash
claude mcp add loxeai -- npx -y @loxeai/mcp-server
```

---

## Why this exists

Every compliance-automation platform surveyed converges on the same artifact: a dashboard of green checkmarks asserting things a viewer cannot verify. Auditors have noticed — some now refuse platform-reported data and require raw exports instead.

This tool is built the other way around. It tells you what it *can't* prove as clearly as what it can:

- **An IaC scan is the primary evidence source for 3 of the 33 SOC 2 Common Criteria.** It partially informs 8 more. The remaining 22 are out of reach of any infrastructure scan — they need documents, people, or live cloud state. The tool says this to your face rather than implying broader coverage.
- **It never reports a criterion as satisfied.** The absence of a finding is not evidence of compliance, and that judgment belongs to a licensed CPA. A test asserts the string `"satisfied"` cannot appear in the OSCAL output.
- **When a control mapping is a guess, it says so.** Every mapping carries a `mappingSource` and a `confidence`, and the mapper declines to stretch rather than inventing a criterion. That refusal is the designed behavior, not a gap.

---

## Install

Requires **Node 20+** and one scanner:

```bash
pipx install checkov      # recommended — richer metadata
brew install trivy        # or this — faster, single binary, no Python
```

If neither is installed, the server tells you so and refuses to return an empty result — an empty finding list would read as "compliant."

### Claude Code

```bash
claude mcp add loxeai -- npx -y @loxeai/mcp-server
```

### Claude Desktop / any MCP host

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "loxeai": {
      "command": "npx",
      "args": ["-y", "@loxeai/mcp-server"]
    }
  }
}
```

No `env` block. There is nothing to authenticate against.

### Verify someone else's report

The trust page prints a fingerprint and a command. That command is real:

```bash
npx @loxeai/mcp-server verify --root /path/to/their/repo --expect <fingerprint>
```

Exit 0 means the tree is byte-identical to the one that produced the report. Exit 1 means it is not. Needs no scanner, no account, and no network — it just hashes the files.

### Test it locally

```bash
git clone <repo> && cd loxeai-mcp-server
npm install && npm run build
npm test                    # 140 tests
bash scripts/verify.sh      # the full invariant gate
npx @modelcontextprotocol/inspector node dist/index.js
```

---

## Tools

Every tool is `readOnlyHint: true`, `destructiveHint: false`, and declares an `outputSchema`, so a client can validate every payload it receives.

| Tool | What it does |
|---|---|
| `scan_iac` | Scan Infrastructure-as-Code for SOC 2 misconfigurations |
| `list_findings` | List findings from a scan batch |
| `get_finding` | Get full detail for one finding |
| `explain_finding` | Explain a finding in plain English |
| `map_iac_finding_to_control` | Map an IaC check to a SOC 2 control |
| `controls` | SOC 2 control catalog |
| `classify_blast_radius` | Group findings into action items by blast radius |
| `applicability_questions` | Get the eight scoping questions |
| `applicability_brief` | Scope SOC 2 to your company from eight questions |
| `preview_trust_page` | Preview what a trust page would say right now |
| `render_trust_page` | Render the trust page as a self-contained file |
| `export_oscal` | Export scan results as NIST OSCAL assessment-results |
| `draft_policy` | Draft a SOC 2 policy grounded in your actual setup |
| `list_policies` | List draftable policies and what each supports |
| `check_capabilities` | Report what this server can and cannot do with your credentials |
| `scanner_status` | Check scanner availability and server scope |

### Resources

| URI | Contents |
|---|---|
| `loxe://controls/soc2` | All 33 Common Criteria |
| `loxe://controls/soc2/{controlId}` | One criterion, with completion on `controlId` |
| `loxe://mappings/rules` | The keyword rules the mapper uses, so you can audit them |
| `loxe://scans/{batchId}/summary` | Scan counts and fingerprint |
| `loxe://workflow/remediation` | The scan → fix → rescan loop |

### Prompts

| Prompt | Purpose |
|---|---|
| `remediate_finding` | Grounded remediation brief for one finding |
| `map_repo_to_soc2` | Honest coverage summary for a repository |

---

## Try it

**"Do I even need SOC 2, and what would it involve?"**

```
Ask me the applicability questions.
```

Eight questions, then a per-criterion brief telling you what satisfying each one looks like *for a company shaped like yours*, and which three to deal with first. Fully deterministic — no model, no network.

It will not tell you a criterion doesn't apply. All 33 apply to essentially every SOC 2 Security engagement, and a tool that told you otherwise would be handing you an exception at fieldwork.

**"What's wrong with my Terraform?"**

```
Scan /abs/path/to/infra and explain the worst finding in plain English.
```

`scan_iac` returns a handoff, not findings — a real repo produces hundreds. Page through with `list_findings`, then `explain_finding` gives you what it means, the real-world risk, why an auditor would care, what to change, and the shape of the fix.

**"What would a trust page say right now?"**

```
Preview my trust page.
```

Per-criterion evidence status, each exception traced to file, line, rule ID, severity and mapping confidence, plus a fingerprint a reviewer can recompute.

---

## Scope, stated plainly

**Covered:** SOC 2 Security category — the 33 Common Criteria (CC1.1–CC9.2), by identifier.

**Not covered:** the optional Availability (A1.x), Confidentiality (C1.x), Processing Integrity (PI1.x) and Privacy (P1–P8) categories. All five in scope would be 61 criteria. Also not covered: ISO 27001, HIPAA, PCI DSS, NIST, GDPR. The tool has no mapping for any of them and will not pretend otherwise.

**Coverage within the Security category:**

| | Count | Meaning |
|---|---|---|
| IaC-primary | **3** | CC6.1, CC6.6, CC6.7 — a scan is the main evidence source |
| IaC-partial | **8** | A scan contributes but cannot satisfy alone |
| Out of reach | **22** | No infrastructure scan can evidence these |

Of those 22, most are evidenced by a written document or by a human actually performing an activity — a risk assessment, a vendor review, an incident response. Across all 33, **21 have a document or a human process as their primary evidence source.** Those are the ones no compliance tool automates, whatever its dashboard implies.

Every criterion carries an `iacNote` explaining precisely what a scan can and cannot show for it.

---

## Security model

### What this server guarantees

**It performs no write operations.** No filesystem writes, no mutating API calls. Remediation comes back as text; your agent applies it through its own approval step, with you in the loop. CI greps `src/` to keep this true.

**The server itself makes no outbound network requests.** Enforced by grep in CI.

It does spawn subprocesses that *can*, and it would be dishonest to elide that:

- Checkov is invoked with `--skip-download` and Trivy with `--skip-check-update`, suppressing their default policy/metadata fetches. (Cost: Checkov's `guideline` URL is then absent from findings.)
- `check_capabilities` runs `aws sts get-caller-identity` and `gh auth status`, which contact AWS STS and api.github.com by definition — that is what they are for.

Everything else is local, and your file contents are never uploaded anywhere by anything.

### What it does *not* guarantee

**That your credentials can't write.** This is a different claim, and an important one. When a tool inherits your ambient CLI session it does not choose the scopes. A typical `gh auth login` carries `repo` (full control of private repositories — read *and* write) and `workflow`. An `az login` Graph token carries `Group.ReadWrite.All` and `User.ReadWrite.All`, and neither you nor a tenant admin can narrow that.

Run `check_capabilities` to see exactly where you stand. On GitHub, true credential-level read-only *is* achievable via a fine-grained PAT with read-only permissions. On Azure via `az`, it is not.

### Incomplete scans cannot look clean

The worst thing this tool could do is hand you a confident, fingerprinted, prospect-facing document that says the opposite of the truth. Three separate conditions now force every reachable criterion to `not-covered-by-this-scan` and put **INCOMPLETE SCAN** at the top of the artifact:

- no IaC files were found or read;
- the scanner evaluated **zero resources and ran zero checks** — what an unparseable or unsupported configuration actually looks like;
- any file failed to parse, or any check was explicitly suppressed in source (`#checkov:skip=...`).

The suppression case matters most. A suppressed check vanishes from `failed_checks` entirely, so without this a developer could silence a finding and the trust page would go green. A suppressed check is an accepted risk, not an absent one, and it is listed by ID, resource, file and stated reason on the artifact.

### Prompt injection

IaC carries attacker-influenceable strings: resource names, tags, comments, module source URLs. A scanner echoes them back, and they flow into an agent holding filesystem write access.

Before anything reaches model context, this server strips invisible and bidi unicode, neutralizes known injection patterns, and wraps content in explicit `<untrusted-data>` boundaries. Verified against live Checkov: a payload smuggled through a resource name comes back as `aws_ebs_volume.[loxe:neutralized](32 chars)_and_[loxe:neutralized](13 chars)`.

**This reduces the attack surface. It does not eliminate semantic prompt injection, and no encoding step can.** Plausible instruction text that avoids the patterns will still get through. In particular, serializing to JSON is *not* a defense — `{"name": "Ignore all previous instructions"}` is still legible instruction text to a model. Any claim that structured output prevents injection is false.

---

## What this tool is not

**It is not an audit, examination, attestation, assurance engagement, or opinion.** Those are terms reserved to licensed CPAs under state accountancy law, not merely by convention. This is automated static analysis.

**There is no such thing as "SOC 2 certified."** SOC 2 is an attestation, not a certification. There is no certifying body and no certificate. Only a licensed CPA firm can perform a SOC 2 examination and issue a report.

**Generated artifacts never assert compliance.** The trust page emits per-criterion *evidence status* with traceable sources — never a framework badge, never "compliant." The OSCAL export only ever emits `not-satisfied`. Policy drafts state in their own header that having the document does not satisfy the criteria it supports.

If you need a claim you can safely put in front of a prospect while mid-process, this is the shape:

> SOC 2 Type II examination in progress. Independent CPA firm [name] engaged; observation period [X]–[Y]; report expected [date].

Every element is a verifiable fact.

---

## Licensing and attribution

**Code:** MIT.

**Control catalog:** every title, description and plain-English restatement in `src/catalog/soc2-controls.ts` is **original wording written for this project.** None of it is AICPA text.

This matters more than it might appear. The official criterion text in AICPA TSP Section 100 is free to download but **not free to redistribute** — it carries "All rights reserved." Every widely-used SOC 2 control corpus we examined redistributes it anyway; one does so with `"entity"` search-replaced to `"organization"`. An open-source license conveys only rights the licensor actually holds, so none of those corpora are safe to build on.

This catalog references criteria **by identifier only** and describes them in its own words. If you want the official text, buy it from the source:

> AICPA & CIMA. TSP Section 100, *2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (With Revised Points of Focus — 2022)*.
> <https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022>

SOC 2® and Trust Services Criteria are property of the AICPA. This project is unaffiliated with the AICPA and references the criteria descriptively.

**Points of focus are not requirements.** TSP 100 §.07 states that using the criteria "does not require an assessment of whether each point of focus is addressed." So this tool says *"MFA supports CC6.6"*, never *"CC6.6 requires MFA."* MFA appears only as a point of focus, and an auditor cannot fail you against one. Stating a point of focus as a requirement is the most common credibility failure in automated SOC 2 tooling.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LOXE_TRUSTED_ROOTS` | cwd | Colon-separated directories the scanner may read |
| `LOXE_DISABLE_TRUST` | `false` | Bypass the trust check. Not recommended |
| `LOXE_MAPPING_OVERRIDES` | unset | Path to a JSON file pinning `checkId → controlId` |

Scan paths must be **absolute**. Relative paths resolve against the server's working directory and would silently scan the wrong tree.

Mapping overrides are validated against the catalog — an override naming a criterion that doesn't exist is rejected and logged to stderr, not silently accepted.

---

## Development

```bash
npm run build      # tsc
npm test           # vitest, 140 tests
npm run inspect    # build + MCP Inspector
```

**Invariants enforced by `scripts/verify.sh`, run in CI:** no filesystem writes in `src/` · no outbound network from the server itself · no `console.log` (it corrupts the stdio protocol stream) · no deprecated SDK APIs · no Zod `.description()` · no stale scope strings · the mapper can never emit a criterion whose IaC capability is `none` · **a scan that evaluated nothing can never report a clean criterion** · every tool declares an `outputSchema` · the trust page never asserts a compliance claim on an assertive surface · OSCAL never emits `satisfied`.

The gate exits non-zero on any failure. A check that prints a count without failing the build is worse than no check, because it manufactures confidence — an earlier version of this script did exactly that and hid seven real failures.

Built on `@modelcontextprotocol/sdk` 1.30.0 using `registerTool` / `registerResource` / `registerPrompt`. Transport is stdio only — the deprecated SSE transport is not used.

### A note on the test fixtures

Most parser tests run against hand-written fixtures matching Checkov's documented JSON shape, and the injection tests run against real Checkov 3.3.10 output. Before trusting field-level parser behavior in production, re-capture a fixture from your own Checkov version:

```bash
checkov -d <dir> -o json > test/fixtures/checkov-real.json
```

---

## Known limitations

- **Batches live in memory** for the life of the server process. Restart the host and previous `batchId`s are gone.
- **Checkov's open-source build ships no severity metadata**, so most findings come back `UNKNOWN`. The tool reports that honestly rather than inventing a level.
- **Control mapping is heuristic.** It's driven by the scanner's own check names and resource types, not by a pinned check-ID table, because those IDs shift between scanner releases and a wrong mapping is worse than none. Confidence is always reported. Use `LOXE_MAPPING_OVERRIDES` to pin mappings you've validated.
- **No runtime evidence.** Everything here describes *declared* configuration. Proving deployed state needs a live cloud check, which this server does not do.
- **`--skip-check-update` requires a warm Trivy cache.** On a machine that has never run Trivy, the policy bundle is absent and the scan will under-report. Use Checkov, or run `trivy config` once with network access first.
