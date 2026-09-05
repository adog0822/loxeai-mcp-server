# Pre-publish checklist

Work top to bottom. Anything unchecked is a reason not to publish.

The automated gates are enforced by `scripts/verify.sh` and CI. The manual gates
are here because no script can check them.

---

## 1. Automated gates (CI must be green)

- [ ] `bash scripts/verify.sh` passes locally
- [ ] CI green on **all six matrix cells** (ubuntu + macOS × Node 20/22/24)
- [ ] `npm audit --omit=dev --audit-level=high` exits 0
- [ ] `npm run build` produces a `dist/` newer than every file in `src/`

Do not publish off a green run from a single cell. The matrix exists because the
package advertises `engines: >=20` while development happened on one OS and one
Node version.

## 2. Correctness gates specific to this package

This tool's output is used to make claims to auditors and prospects. A bug that
makes it *under-report* is worse than a crash, because nobody notices.

- [ ] A scan of a repo containing an unparseable file reports a parse error and
      **zero clean criteria**
- [ ] A scan of a repo containing `#checkov:skip=` reports a suppression and
      **zero clean criteria**
- [ ] The trust page says `INCOMPLETE SCAN` in both cases above
- [ ] `npx @loxeai/mcp-server verify --root <path> --expect <wrong-hash>` exits 1
- [ ] OSCAL export contains no `"state": "satisfied"`

Re-run these against a **real repository**, not `test/fixtures`. Both historical
under-reporting bugs passed their fixtures and failed on real Checkov output.

## 3. Manual gates

- [ ] **Legal review of the trust-page wording is complete.** Not optional
      before enabling any publish/share flow. The FTC's stated position reaches
      the tool vendor, not just the user.
- [ ] `README.md` version, test count, and tool count match reality
- [ ] `CHANGELOG` entry written for this version
- [ ] Version bumped in `package.json`; the git tag matches it
- [ ] Working tree clean; the commit being tagged is the commit being published

## 4. Publish surface

- [ ] `npm publish --dry-run` reviewed — confirm `files` ships only
      `dist`, `README.md`, `LICENSE`
- [ ] **No `.env`, no fixtures, no `.github`, no scratch files in the tarball**
- [ ] `npm whoami` confirms the right account, with publish rights on `@loxeai`
- [ ] SBOM generated and attached to the release

## 5. Publish

```bash
npm publish --access public
```

- [ ] Install the published package in a clean directory and run
      `npx @loxeai/mcp-server --help`
- [ ] Point a real MCP client at it and call `scan_iac` once

---

## Known limitations to re-confirm each release

These are currently true. If any becomes false, update the README rather than
quietly shipping.

| Limitation | Status at 0.1.0 |
|---|---|
| Trivy path is unproven against a live binary | Checkov is the supported engine |
| Largest validated scan | ~6 files, 23 findings |
| Mapping accuracy | 78% on a single small repo — not a validated rate |
| Multi-user / RBAC | Not supported; single-user stdio only |
| Persistence | None by design; batches die with the process |

## Dependency note

The package has **2 direct dependencies** but **90 transitive** ones, because
`@modelcontextprotocol/sdk` pulls in a complete HTTP stack (express, hono, cors,
jose, eventsource) for transports this server does not use. Confirmed not loaded
at runtime on the stdio path. Re-check after any SDK upgrade:

```bash
npm sbom --sbom-format cyclonedx --omit=dev | grep -c '"name"'
```
