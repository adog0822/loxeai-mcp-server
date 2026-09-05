/**
 * Trivy adapter (secondary scanner).
 *
 * Trivy is faster than Checkov and a single binary with no Python dependency,
 * but its misconfiguration metadata is thinner, so SOC 2 mapping confidence is
 * usually lower. Used when Checkov is unavailable.
 *
 * Invoked as `trivy config`, which is Trivy's IaC misconfiguration scanner
 * (Terraform, CloudFormation, Kubernetes, Dockerfile, Helm).
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mapFindingToControl } from "../catalog/control-mappings.js";
import { getRemediationMeta } from "../catalog/remediation-meta.js";
import { findingId } from "./fingerprint.js";
import type { Finding, IacFramework, Severity } from "./types.js";

const execFileAsync = promisify(execFile);
const MAX_BUFFER = 64 * 1024 * 1024;

export type TrivyRunResult = {
  findings: Finding[];
  parseErrors: string[];
  frameworks: IacFramework[];
  /** Trivy does not report suppressions in `config` output. Always empty. */
  suppressions: never[];
  evaluatedResources: number;
  evaluatedChecks: number;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeSeverity(value: unknown): Severity {
  const raw = asString(value)?.toUpperCase();
  if (!raw) return "UNKNOWN";
  if (raw === "CRITICAL" || raw === "HIGH" || raw === "MEDIUM" || raw === "LOW") return raw;
  if (raw === "UNKNOWN") return "UNKNOWN";
  return "INFO";
}

function normalizeFramework(value: unknown): IacFramework {
  const raw = asString(value)?.toLowerCase() ?? "";
  const known: Record<string, IacFramework> = {
    terraform: "terraform",
    terraformplan: "terraform_plan",
    "terraform-plan": "terraform_plan",
    cloudformation: "cloudformation",
    kubernetes: "kubernetes",
    dockerfile: "dockerfile",
    helm: "helm",
    azurearm: "arm",
    bicep: "bicep",
  };
  return known[raw] ?? "unknown";
}

function resourceTypeOf(resource: string): string {
  const withoutModule = resource.replace(/^module\.[^.]+\./, "");
  const dot = withoutModule.indexOf(".");
  return dot > 0 ? withoutModule.slice(0, dot) : withoutModule;
}

/**
 * Parse Trivy `config --format json` output.
 *
 * Split out from `runTrivy` so the parse path is testable without a Trivy
 * install.
 */
export function parseTrivyJson(stdout: string): TrivyRunResult {
  const trimmed = stdout.trim();
  if (trimmed.length === 0) {
    throw new Error("Trivy produced no output; cannot distinguish a clean scan from a failed one");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("Trivy output was not valid JSON");
  }

  const out: TrivyRunResult = { findings: [], parseErrors: [], frameworks: [] , suppressions: [], evaluatedResources: 0, evaluatedChecks: 0};
  const top = asRecord(parsed);
  const results = top?.["Results"];
  if (!Array.isArray(results)) return out;

  for (const entry of results) {
    const result = asRecord(entry);
    if (!result) continue;

    const framework = normalizeFramework(result["Type"]);
    if (framework !== "unknown" && !out.frameworks.includes(framework)) out.frameworks.push(framework);

    const target = asString(result["Target"]) ?? "(unknown file)";

    // Coverage accounting. Trivy has no `parsing_errors` field, so the only way
    // to distinguish "clean" from "evaluated nothing" is MisconfSummary. Without
    // this, every Trivy scan would look like it assessed zero resources and be
    // wrongly flagged incomplete -- and, worse, a Trivy scan that genuinely
    // parsed nothing would look clean.
    const misconfSummary = asRecord(result["MisconfSummary"]);
    if (misconfSummary) {
      const successes = typeof misconfSummary["Successes"] === "number" ? misconfSummary["Successes"] : 0;
      const failures = typeof misconfSummary["Failures"] === "number" ? misconfSummary["Failures"] : 0;
      const exceptions = typeof misconfSummary["Exceptions"] === "number" ? misconfSummary["Exceptions"] : 0;
      out.evaluatedChecks += successes + failures + exceptions;
      // Trivy reports per-target, so each target with any verdict counts as an
      // evaluated resource.
      if (successes + failures + exceptions > 0) out.evaluatedResources += 1;
    }

    // Trivy has no `parsing_errors` channel in `config` output. A target it
    // could not read simply produces no Misconfigurations and no summary --
    // indistinguishable from a clean file unless we say so explicitly.
    if (!misconfSummary && !Array.isArray(result["Misconfigurations"])) {
      out.parseErrors.push(
        `${target} produced no misconfiguration results and no summary; Trivy may not have been able to read it`,
      );
    }

    const misconfigs = result["Misconfigurations"];
    if (!Array.isArray(misconfigs)) continue;

    for (const item of misconfigs) {
      const m = asRecord(item);
      if (!m) continue;

      // Trivy reports both PASS and FAIL. Only failures are findings.
      const status = asString(m["Status"])?.toUpperCase();
      if (status && status !== "FAIL") continue;

      const checkId = asString(m["AVDID"]) ?? asString(m["ID"]);
      if (!checkId) continue;

      const title = asString(m["Title"]) ?? "";
      const message = asString(m["Message"]) ?? "";
      // Title is the rule; Message is the instance. Concatenate so the keyword
      // mapper sees both, since Trivy titles are terse.
      const checkName = [title, message].filter((s) => s.length > 0).join(" - ") || "(no title reported)";

      const cause = asRecord(m["CauseMetadata"]);
      const resource = asString(cause?.["Resource"]) ?? "(unknown resource)";
      const startLine = cause?.["StartLine"];
      const endLine = cause?.["EndLine"];
      const lineRange: [number, number] | null =
        typeof startLine === "number" && typeof endLine === "number" ? [startLine, endLine] : null;

      const filePath = target.replace(/^\/+/, "");
      const resourceType = resourceTypeOf(resource);

      out.findings.push({
        id: findingId({ checkId, filePath, resource }),
        checkId,
        checkName,
        severity: normalizeSeverity(m["Severity"]),
        resource,
        resourceType,
        filePath,
        lineRange,
        framework,
        guideline: asString(m["PrimaryURL"]),
        scanner: "trivy",
        mapping: mapFindingToControl({ checkId, checkName, resourceType }),
        blastRadius: getRemediationMeta({ title: checkName }),
      });
    }
  }

  return out;
}

export async function runTrivy(options: {
  root: string;
  command?: string;
  timeoutMs?: number;
}): Promise<TrivyRunResult> {
  const { root, command = "trivy", timeoutMs = 300_000 } = options;

  const args = [
    "config",
    "--format",
    "json",
    "--quiet",
    // `trivy config` pulls its misconfiguration policy bundle from a remote
    // registry on first use and refreshes it periodically. Suppress it so the
    // no-outbound-network claim holds. Requires a previously-populated cache.
    "--skip-check-update",
    root,
  ];

  let stdout = "";
  try {
    const result = await execFileAsync(command, args, { timeout: timeoutMs, maxBuffer: MAX_BUFFER });
    stdout = result.stdout;
  } catch (error) {
    const withOutput = error as { stdout?: string; killed?: boolean };
    if (withOutput.killed) {
      throw new Error(`Trivy timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    if (typeof withOutput.stdout === "string" && withOutput.stdout.trim().length > 0) {
      stdout = withOutput.stdout;
    } else {
      throw error;
    }
  }

  return parseTrivyJson(stdout);
}
