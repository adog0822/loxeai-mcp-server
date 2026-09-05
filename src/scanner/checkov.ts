/**
 * Checkov adapter.
 *
 * Checkov is the recommended primary scanner: it carries the richest check
 * metadata (`check_name`, `guideline`, `resource`), which is what the SOC 2
 * mapping layer keys off.
 *
 * EXIT CODE WARNING: `checkov` exits 1 when it finds failures. Treating a
 * non-zero exit as an error -- the obvious mistake -- would make every repo with
 * findings look like a scanner crash, or worse, get swallowed into an empty
 * result and reported as clean. Only a missing/unparseable stdout is a real
 * failure here.
 */

/**
 * ===========================================================================
 * READ THIS BEFORE ADDING ANY FIELD READ FROM `results.*`
 * ===========================================================================
 *
 * Checkov's DOCUMENTED JSON shape and its ACTUAL output disagree, and this has
 * now caused two separate bugs in this file, both of which caused the tool to
 * report a clean result when it should not have:
 *
 *   1. `results.parsing_errors` -- OMITTED when a file fails to parse. Only
 *      `summary.parsing_errors` carries the count. Reading the array alone
 *      meant an unparseable repo produced zero findings, zero parse errors, and
 *      11 criteria reported clean on a prospect-facing document.
 *
 *   2. `results.skipped_checks` -- OMITTED entirely, with AND without
 *      `--compact`. Only `summary.skipped` carries the count. Reading the array
 *      alone meant `#checkov:skip=CKV_AWS_3` silently removed a finding and the
 *      criterion went green.
 *
 * Both were verified empirically against Checkov 3.3.10, not inferred.
 *
 * THE RULE: `summary` is the authoritative source for COUNTS. The `results.*`
 * arrays are best-effort DETAIL that may be absent. Read the summary first,
 * then enrich from the array when it happens to be there, and reconcile the two
 * (see `reconcileSuppressions`).
 *
 * Any new field you read from `results.*` must be checked against real output
 * from a real scan before you trust it. A fixture built from the documented
 * shape will pass while production silently under-reports -- that is exactly
 * how both bugs above survived their own tests.
 */

import { execFile } from "node:child_process";
import { relative } from "node:path";
import { promisify } from "node:util";
import { mapFindingToControl } from "../catalog/control-mappings.js";
import { getRemediationMeta } from "../catalog/remediation-meta.js";
import { findingId } from "./fingerprint.js";
import type { Finding, IacFramework, Severity } from "./types.js";

const execFileAsync = promisify(execFile);

/** Checkov JSON can exceed the 1 MB default on a real repo. */
const MAX_BUFFER = 64 * 1024 * 1024;

export type Suppression = {
  checkId: string;
  checkName: string;
  resource: string;
  filePath: string;
  /** The `#checkov:skip=ID:reason` comment, or "no reason given". */
  reason: string;
};

export type CheckovRunResult = {
  findings: Finding[];
  parseErrors: string[];
  frameworks: IacFramework[];
  /** Checks a developer explicitly suppressed. Reported, never hidden. */
  suppressions: Suppression[];
  /**
   * Resources Checkov actually evaluated, summed across reports.
   *
   * The load-bearing "did the scan do anything" signal. A repo whose files all
   * fail to parse yields zero findings AND zero evaluated resources; without
   * this, the absence of findings is indistinguishable from a clean result.
   */
  evaluatedResources: number;
  /** Checks that returned a verdict (passed + failed). */
  evaluatedChecks: number;
  /**
   * Suppression count from `summary.skipped` -- authoritative even when
   * `results.skipped_checks` is absent, which is the normal case.
   */
  summarySkipped: number;
};

/** Normalize a scanner-reported path to repo-relative. Never absolute. */
function relativePath(input: string, root: string): string {
  if (!input) return "(unknown file)";
  let out = input;
  if (out.startsWith("/")) {
    const rel = relative(root, out);
    if (rel && !rel.startsWith("..")) out = rel;
  }
  return out.replace(/^\/+/, "");
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeSeverity(value: unknown): Severity {
  // Checkov open-source frequently emits null here; severity metadata ships
  // with Bridgecrew/Prisma. UNKNOWN is the honest answer, not a default of LOW.
  const raw = asString(value)?.toUpperCase();
  if (!raw) return "UNKNOWN";
  if (raw === "CRITICAL" || raw === "HIGH" || raw === "MEDIUM" || raw === "LOW" || raw === "INFO") return raw;
  return "UNKNOWN";
}

function normalizeFramework(checkType: unknown): IacFramework {
  const raw = asString(checkType)?.toLowerCase() ?? "";
  const known: Record<string, IacFramework> = {
    terraform: "terraform",
    terraform_plan: "terraform_plan",
    cloudformation: "cloudformation",
    kubernetes: "kubernetes",
    dockerfile: "dockerfile",
    helm: "helm",
    arm: "arm",
    bicep: "bicep",
    serverless: "serverless",
    github_actions: "github_actions",
  };
  return known[raw] ?? "unknown";
}

function resourceTypeOf(resource: string): string {
  // "aws_s3_bucket.data" -> "aws_s3_bucket"; also handles module addresses.
  const withoutModule = resource.replace(/^module\.[^.]+\./, "");
  const dot = withoutModule.indexOf(".");
  return dot > 0 ? withoutModule.slice(0, dot) : withoutModule;
}

function lineRangeOf(value: unknown): [number, number] | null {
  if (!Array.isArray(value) || value.length < 2) return null;
  const [start, end] = value;
  if (typeof start === "number" && typeof end === "number") return [start, end];
  return null;
}

/** Normalize a single `failed_checks` entry. */
function toFinding(raw: Record<string, unknown>, checkType: unknown, root: string): Finding | null {
  // Modern Checkov uses `check_id`; older output used `id`. Accept both rather
  // than silently dropping findings on a version change.
  const checkId = asString(raw["check_id"]) ?? asString(raw["id"]);
  if (!checkId) return null;

  const checkName = asString(raw["check_name"]) ?? "(no check name reported)";
  const resource = asString(raw["resource"]) ?? "(unknown resource)";

  // Prefer repo-relative, then relative-ize an absolute path. Never emit an
  // absolute path: it leaks the developer's directory layout into model context.
  const repoPath = asString(raw["repo_file_path"]) ?? asString(raw["file_path"]);
  const absPath = asString(raw["file_abs_path"]);
  let filePath = repoPath ?? absPath ?? "(unknown file)";
  if (absPath && (filePath === absPath || filePath.startsWith("/"))) {
    const rel = relative(root, absPath);
    if (rel && !rel.startsWith("..")) filePath = rel;
  }
  filePath = filePath.replace(/^\/+/, "");

  const resourceType = resourceTypeOf(resource);
  const severity = normalizeSeverity(raw["severity"]);

  return {
    id: findingId({ checkId, filePath, resource }),
    checkId,
    checkName,
    severity,
    resource,
    resourceType,
    filePath,
    lineRange: lineRangeOf(raw["file_line_range"]),
    framework: normalizeFramework(checkType),
    guideline: asString(raw["guideline"]),
    scanner: "checkov",
    mapping: mapFindingToControl({ checkId, checkName, resourceType }),
    blastRadius: getRemediationMeta({ title: checkName }),
  };
}

/** Parse one Checkov report object (a single `check_type`). */
function parseReport(report: Record<string, unknown>, root: string, out: CheckovRunResult): void {
  const checkType = report["check_type"];
  const framework = normalizeFramework(checkType);
  if (framework !== "unknown" && !out.frameworks.includes(framework)) out.frameworks.push(framework);

  // The `summary` block is authoritative for coverage. Checkov reports
  // `summary.parsing_errors: 1` while OMITTING `results.parsing_errors`
  // entirely when a file fails to parse -- so reading only `results` misses the
  // failure and the scan looks clean. Verified against Checkov 3.3.10.
  const summary = asRecord(report["summary"]);
  if (summary) {
    const passed = asNumber(summary["passed"]) ?? 0;
    const failedCount = asNumber(summary["failed"]) ?? 0;
    out.evaluatedResources += asNumber(summary["resource_count"]) ?? 0;
    out.evaluatedChecks += passed + failedCount;
    const summaryParseErrors = asNumber(summary["parsing_errors"]) ?? 0;
    for (let i = 0; i < summaryParseErrors; i += 1) {
      out.parseErrors.push(`(${normalizeFramework(checkType)}) unparseable file reported by scanner summary`);
    }

    // Suppressions have the SAME shape of problem as parse errors, verified
    // against Checkov 3.3.10: `summary.skipped` reports the count while
    // `results.skipped_checks` is omitted entirely -- with AND without
    // `--compact`. Reading only the detail array misses every suppression, and
    // a suppressed check then silently becomes a clean criterion.
    //
    // The count is authoritative; detail is used when present.
    out.summarySkipped += asNumber(summary["skipped"]) ?? 0;
  }

  const results = asRecord(report["results"]);
  if (!results) return;

  const failed = results["failed_checks"];
  if (Array.isArray(failed)) {
    for (const entry of failed) {
      const record = asRecord(entry);
      if (!record) continue;
      const finding = toFinding(record, checkType, root);
      if (finding) out.findings.push(finding);
    }
  }

  // Suppressions are compliance-relevant and must never be silent.
  //
  // A developer writing `#checkov:skip=CKV_AWS_19:reason` above an unencrypted
  // bucket removes the finding from `failed_checks` entirely. Without this, the
  // criterion would flip to "no exceptions found" on a prospect-facing document
  // and nothing anywhere would record that a human chose to suppress it. For a
  // compliance artifact an unreported suppression is worse than a missed
  // finding -- it is the mechanism by which the tool can be made to lie on
  // request.
  const skipped = results["skipped_checks"];
  if (Array.isArray(skipped)) {
    for (const entry of skipped) {
      const record = asRecord(entry);
      if (!record) continue;
      const checkId = asString(record["check_id"]) ?? asString(record["id"]) ?? "unknown-check";
      const resource = asString(record["resource"]) ?? "unknown-resource";
      const file = relativePath(asString(record["file_path"]) ?? "", root);
      const info = asRecord(record["check_result"]);
      const reason =
        asString(info?.["suppress_comment"]) ??
        asString(record["suppress_comment"]) ??
        "no reason given";
      out.suppressions.push({
        checkId,
        checkName: asString(record["check_name"]) ?? checkId,
        resource,
        filePath: file,
        reason,
      });
    }
  }

  // Parsing errors are a partial result, not a clean one. Surface them.
  const errors = results["parsing_errors"];
  if (Array.isArray(errors) && errors.length > 0) {
    // Named files beat placeholders: drop the summary-derived placeholders and
    // use the real filenames.
    out.parseErrors = out.parseErrors.filter((e) => !e.startsWith("("));
    for (const entry of errors) {
      const text = asString(entry);
      if (text) out.parseErrors.push(relativePath(text, root));
    }
  }
}

/**
 * Parse Checkov JSON output.
 *
 * Split out from `runCheckov` so the parse path is testable without a Checkov
 * install. The process-spawning half is thin; this half carries all the format
 * handling, and format handling is where the bugs live.
 */
/**
 * Reconcile the authoritative summary count against whatever detail arrived.
 *
 * A suppression must never go unreported just because the scanner withheld the
 * detail array: an unreported suppression is precisely how this tool could be
 * talked into showing a clean result.
 */
function reconcileSuppressions(out: CheckovRunResult): void {
  for (let i = out.suppressions.length; i < out.summarySkipped; i += 1) {
    out.suppressions.push({
      checkId: "(not reported)",
      checkName: "Check suppressed in source",
      resource: "(not reported)",
      filePath: "(not reported)",
      reason:
        "The scanner reported this suppression in its summary but did not include the detail. " +
        "Search your configuration for `checkov:skip` to identify it.",
    });
  }
}

export function parseCheckovJson(stdout: string, root: string): CheckovRunResult {
  const trimmed = stdout.trim();
  const out: CheckovRunResult = { findings: [], parseErrors: [], frameworks: [], suppressions: [], evaluatedResources: 0, evaluatedChecks: 0, summarySkipped: 0 };

  if (trimmed.length === 0) {
    // No output at all is ambiguous, and ambiguity must not read as "clean".
    throw new Error("Checkov produced no output; cannot distinguish a clean scan from a failed one");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("Checkov output was not valid JSON");
  }

  // Multi-framework runs emit an ARRAY of report objects, one per check_type.
  // Handling only the object shape is a common bug that drops most findings.
  if (Array.isArray(parsed)) {
    for (const entry of parsed) {
      const record = asRecord(entry);
      if (record) parseReport(record, root, out);
    }
  } else {
    const record = asRecord(parsed);
    if (record) parseReport(record, root, out);
  }

  reconcileSuppressions(out);
  return out;
}

export async function runCheckov(options: {
  root: string;
  command?: string;
  frameworks?: string[];
  configPath?: string;
  timeoutMs?: number;
}): Promise<CheckovRunResult> {
  const { root, command = "checkov", frameworks, configPath, timeoutMs = 300_000 } = options;

  const args = [
    "--directory",
    root,
    "--output",
    "json",
    "--compact",
    "--quiet",
    // Checkov contacts the Bridgecrew API by default to fetch guideline
    // metadata. This server advertises no outbound network, so suppress it.
    // Cost: the `guideline` field is then absent from findings.
    "--skip-download",
  ];
  if (frameworks && frameworks.length > 0) {
    args.push("--framework", ...frameworks);
  }
  if (configPath) {
    args.push("--config-file", configPath);
  }

  let stdout = "";
  try {
    const result = await execFileAsync(command, args, { timeout: timeoutMs, maxBuffer: MAX_BUFFER });
    stdout = result.stdout;
  } catch (error) {
    // Exit code 1 means "findings present" and still carries valid JSON on
    // stdout. Anything without parseable stdout is a genuine failure.
    const withOutput = error as { stdout?: string; code?: number; killed?: boolean };
    if (withOutput.killed) {
      throw new Error(`Checkov timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    if (typeof withOutput.stdout === "string" && withOutput.stdout.trim().length > 0) {
      stdout = withOutput.stdout;
    } else {
      throw error;
    }
  }

  return parseCheckovJson(stdout, root);
}
