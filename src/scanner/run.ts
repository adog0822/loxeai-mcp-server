/**
 * Scan orchestration: detect -> trust-gate -> run -> sanitize -> store.
 */

import { detectScanners, SCANNER_INSTALL_HELP, assertTrustedPath, type DetectedScanner } from "./detect.js";
import { fingerprintInputs } from "./fingerprint.js";
import { runCheckov } from "./checkov.js";
import { runTrivy } from "./trivy.js";
import { putBatch, sortFindings } from "./store.js";
import { emptyCounts, type Batch, type Finding, type IacFramework, type ScanCounts } from "./types.js";
import { sanitizeDeep } from "../security/sanitize.js";

export class ScannerUnavailableError extends Error {
  constructor() {
    super(SCANNER_INSTALL_HELP);
    this.name = "ScannerUnavailableError";
  }
}

/**
 * Cap on findings RETAINED per batch.
 *
 * Measured at ~514 bytes per finding: 20k findings is ~10 MB per batch and
 * ~100 MB across the 10 retained batches -- bounded and survivable. An uncapped
 * 200k-finding monorepo measured at 98 MB per batch, which across ten batches
 * exhausts the default Node heap mid-session.
 *
 * `counts` and `totalFindings` still describe the FULL result; only the
 * retained list is capped, and `findingsTruncated` blocks any clean claim.
 */
const MAX_FINDINGS_PER_BATCH = 20_000;

export class TrustError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "TrustError";
  }
}

function tally(findings: Finding[]): ScanCounts {
  const counts = emptyCounts();
  counts.total = findings.length;
  for (const finding of findings) {
    counts.bySeverity[finding.severity] += 1;
    const controlId = finding.mapping.controlId;
    if (controlId) {
      counts.byControl[controlId] = (counts.byControl[controlId] ?? 0) + 1;
    } else {
      counts.unmapped += 1;
    }
  }
  return counts;
}

function pickScanner(available: DetectedScanner[], preferred?: string): DetectedScanner {
  if (available.length === 0) throw new ScannerUnavailableError();
  if (preferred) {
    const match = available.find((s) => s.name === preferred);
    if (match) return match;
  }
  // Prefer Checkov for mapping depth.
  return available.find((s) => s.name === "checkov") ?? available[0]!;
}

export type ScanOptions = {
  path: string;
  frameworks?: string[];
  configPath?: string;
  scanner?: string;
};

export async function performScan(options: ScanOptions): Promise<Batch> {
  const trust = assertTrustedPath(options.path);
  if (!trust.ok) throw new TrustError(trust.reason);
  const root = trust.resolved;

  // configPath MUST go through the same gate.
  //
  // A Checkov config file can set `directory:`, `file:` and
  // `external-checks-git:` (which clones a repo and loads Python custom
  // checks). Validating `path` while passing `configPath` through untouched
  // meant the entire trust gate could be bypassed by pointing at a config that
  // redirects the scan -- the denylist never sees the redirected target.
  let configPath: string | undefined;
  if (options.configPath !== undefined) {
    const configTrust = assertTrustedPath(options.configPath);
    if (!configTrust.ok) {
      throw new TrustError(
        `Refusing the supplied configPath. ${configTrust.reason}\n\n` +
          "A scanner config file can redirect the scan to another directory or load remote custom checks, " +
          "so it is subject to the same trust check as the scan path itself.",
      );
    }
    configPath = configTrust.resolved;
  }

  const available = await detectScanners();
  const chosen = pickScanner(available, options.scanner);

  // Fingerprint BEFORE scanning so it reflects the input the scanner saw.
  const fp = fingerprintInputs(root);

  const raw =
    chosen.name === "checkov"
      ? await runCheckov({
          root,
          command: chosen.command,
          ...(options.frameworks ? { frameworks: options.frameworks } : {}),
          ...(configPath ? { configPath: configPath } : {}),
        })
      : await runTrivy({ root, command: chosen.command });

  // Sanitize scanner output before it can reach model context. Scanner text
  // echoes resource names, tags and comments from the scanned files, all of
  // which are attacker-influenceable.
  const sanitized = sanitizeDeep(raw.findings);
  const findings = sanitized.value;

  const parseErrors = sanitizeDeep(raw.parseErrors).value;
  // Suppressions carry developer-authored reason text, so they go through the
  // same sanitizer as every other scanner-sourced string.
  const suppressions = sanitizeDeep(raw.suppressions ?? []).value;

  const frameworks: IacFramework[] = raw.frameworks.length > 0 ? raw.frameworks : ["unknown"];

  // Tally the FULL set before capping, so reported counts stay true even when
  // the retained list is truncated. Sort first so the cap keeps the most severe
  // findings rather than an arbitrary slice.
  const counts = tally(findings);
  const ordered = sortFindings(findings);
  const findingsTruncated = ordered.length > MAX_FINDINGS_PER_BATCH;
  const retained = findingsTruncated ? ordered.slice(0, MAX_FINDINGS_PER_BATCH) : ordered;

  return putBatch({
    fingerprint: fp.fingerprint,
    scanner: chosen.name,
    scannerVersion: chosen.version,
    root,
    frameworks,
    createdAt: new Date().toISOString(),
    fileCount: fp.fileCount,
    fingerprintTruncated: fp.truncated,
    findings: retained,
    counts,
    findingsTruncated,
    totalFindings: findings.length,
    sanitization: {
      modified: sanitized.modified,
      invisibleCharsRemoved: sanitized.stats.invisibleCharsRemoved,
      injectionPatternsNeutralized: sanitized.stats.injectionPatternsNeutralized,
    },
    parseErrors,
    suppressions,
    evaluatedResources: raw.evaluatedResources ?? 0,
    evaluatedChecks: raw.evaluatedChecks ?? 0,
  });
}
