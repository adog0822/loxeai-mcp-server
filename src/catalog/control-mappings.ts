/**
 * IaC finding -> SOC 2 control mapping.
 *
 * This is the differentiating capability of this server. As of this writing
 * nothing on the market ships "scan Terraform -> findings mapped to SOC 2
 * control requirements" over MCP:
 *
 *   - awslabs `RunCheckovScan` was the only maintained IaC-scanning MCP tool;
 *     deprecated March 2026, and AWS's own migration guide states the successor
 *     has "No security scanning capability".
 *   - Snyk ships `snyk_iac_scan` but no compliance-framework mapping.
 *   - Prowler has a Trivy IaC engine and 70+ frameworks and exposes neither as
 *     an IaC MCP tool.
 *   - MCP registry search for `checkov`, `trivy`, `misconfiguration`: zero results.
 *
 * ---------------------------------------------------------------------------
 * DESIGN NOTE ON CORRECTNESS (read before changing this file)
 * ---------------------------------------------------------------------------
 * A wrong control mapping in a compliance product is worse than no mapping: it
 * produces confident, auditable-looking output that is false. So this file
 * deliberately does NOT hardcode a large table of scanner check IDs
 * (CKV_AWS_18 -> CC6.7, ...). Those ID-to-rule assignments change between
 * scanner releases and cannot be verified from inside this package.
 *
 * Instead, mapping is driven by the scanner's own self-describing metadata --
 * `check_name` and `resource` type -- which every Checkov and Trivy result
 * carries. That is verifiable at runtime and degrades honestly.
 *
 * Every mapping result reports `mappingSource` and `confidence` so a caller can
 * tell a pinned mapping from a heuristic one. This mirrors the platform's
 * `evidenceProof.hashSource` convention (`lib/evidence-proof.ts`), which
 * likewise refuses to hide how a value was derived.
 *
 * To pin exact check IDs, populate an overrides file and pass it via
 * LOXE_MAPPING_OVERRIDES (see `loadOverrides`). Validate first with
 * `npm run validate-mappings`, which diffs against a real `checkov --list`.
 */

import { readFileSync } from "node:fs";
import { getControl, IAC_EVIDENCE_CAPABILITY, type Soc2ControlOption } from "./soc2-controls.js";

export type MappingSource = "override" | "resource-attribute" | "keyword" | "unmapped";
export type MappingConfidence = "high" | "medium" | "low" | "none";

export type ControlMapping = {
  controlId: string | null;
  controlTitle: string | null;
  requirement: string | null;
  mappingSource: MappingSource;
  confidence: MappingConfidence;
  /** Human-readable reason this mapping was chosen. Never omit. */
  rationale: string;
  /** What an IaC scan can and cannot evidence for this control. */
  evidenceLimit: string | null;
};

/**
 * Keyword -> control rules, evaluated in order. First match wins.
 *
 * The keyword approach mirrors how the LoxeAI engine itself maps evidence to
 * controls (the `keywords` arrays on each control in
 * `core/control_catalog.py:14-87`, surfaced as `EngineControl.keywords`).
 *
 * `terms` match against the lowercased scanner check name.
 * `resourceTerms`, when present, must ALSO match the resource type -- this
 * raises confidence from `low` to `medium`.
 */
type KeywordRule = {
  controlId: string;
  terms: string[];
  resourceTerms?: string[];
  why: string;
};

const KEYWORD_RULES: KeywordRule[] = [
  // ---- CC6.7 Data Confidentiality: encryption at rest and in transit ----
  {
    controlId: "CC6.7",
    terms: ["encrypt", "encryption", "kms", "cmk", "sse", "at rest"],
    why: "Check concerns encryption of stored data, which is the CC6.7 confidentiality requirement.",
  },
  {
    controlId: "CC6.7",
    terms: ["tls", "ssl", "https", "in transit", "insecure protocol", "certificate"],
    why: "Check concerns transport protection, which CC6.7 covers alongside encryption at rest.",
  },

  // ---- CC6.6 Network Security ----
  {
    controlId: "CC6.6",
    // "0.0.0.0:0" with a COLON is not a typo: Checkov 3.3.10 renders CKV_AWS_24
    // as "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22".
    // Verified against live output. Matching only on the slash form misses it.
    terms: ["0.0.0.0/0", "0.0.0.0:0", "::/0", "public ingress", "ingress", "egress", "security group", "publicly accessible", "public ip", "internet"],
    why: "Check concerns network reachability or ingress scope, which is the CC6.6 network-restriction requirement.",
  },
  {
    controlId: "CC6.6",
    terms: ["vpc", "subnet", "nacl", "network acl", "firewall", "waf", "port"],
    why: "Check concerns network boundary configuration, covered by CC6.6.",
  },

  // ---- CC6.1 Logical Access Architecture: authentication strength ----
  // NOTE: deliberately NOT CC6.2. CC6.2 is the provisioning/deprovisioning
  // lifecycle -- approving access before granting it and revoking it on
  // termination -- which is identity-system and HR evidence, not something an
  // IaC file can show. A declared password-policy or MFA-enforcement resource
  // is part of the access *architecture*, which is CC6.1.
  {
    controlId: "CC6.1",
    terms: ["mfa", "multi-factor", "multi factor", "password policy", "password length", "password reuse", "mfa_delete"],
    why: "Check concerns declared authentication strength, part of the CC6.1 access architecture.",
  },

  // ---- CC6.3 Least Privilege ----
  {
    controlId: "CC6.3",
    terms: ["wildcard", "admin privileges", "administrator access", "full access", "star action", "privilege escalation", "assumerole", "least privilege", "iam policy allows"],
    why: "Check concerns over-broad granted permissions, which is the CC6.3 least-privilege requirement.",
  },

  // ---- CC6.1 Logical Access Security ----
  {
    controlId: "CC6.1",
    terms: ["public read", "public write", "public acl", "public access", "anonymous", "unauthenticated", "block public"],
    why: "Check concerns unauthorized access to a resource, which is the CC6.1 logical-access requirement.",
  },
  {
    controlId: "CC6.1",
    terms: ["iam", "role", "policy", "principal", "access key", "credential", "secret"],
    why: "Check concerns identity or access configuration, covered by CC6.1.",
  },

  // ---- CC7.1 Monitoring ----
  {
    controlId: "CC7.1",
    terms: ["logging", "log", "cloudtrail", "cloudwatch", "audit log", "flow log", "access logging", "monitoring", "guardduty", "security hub", "config recorder", "alarm", "retention"],
    why: "Check concerns logging or monitoring coverage, which is the CC7.1 requirement.",
  },

  // ---- CC8.1 Change Management ----
  {
    controlId: "CC8.1",
    terms: ["versioning", "deletion protection", "backup", "point in time recovery", "termination protection", "drift", "branch protection", "code review", "required reviewers"],
    why: "Check concerns change durability, reversibility or review, which CC8.1 covers.",
  },

  // ---- CC5.2 Technology Controls (deliberate low-confidence catch-all) ----
  {
    controlId: "CC5.2",
    terms: ["deprecated", "version", "latest", "unsupported"],
    why: "Check concerns technology currency. Mapped to CC5.2 as a general technology control; confirm manually.",
  },
];

/**
 * Resource-type hints. Used to raise confidence when the resource type agrees
 * with the keyword verdict, and to break ties.
 */
const RESOURCE_HINTS: Record<string, string[]> = {
  "CC6.1": ["s3", "bucket", "iam", "user", "group", "policy", "secretsmanager", "ssm_parameter"],
  "CC6.3": ["iam_policy", "iam_role", "iam_role_policy", "iam_group_policy", "iam_user_policy"],
  "CC6.6": ["security_group", "network_acl", "vpc", "subnet", "lb", "elb", "alb", "api_gateway", "cloudfront", "waf"],
  "CC6.7": ["kms", "ebs", "rds", "s3", "dynamodb", "efs", "sqs", "sns", "redshift", "elasticache", "backup"],
  "CC7.1": ["cloudtrail", "cloudwatch", "flow_log", "config", "guardduty", "securityhub", "log_group"],
  "CC8.1": ["s3_bucket_versioning", "backup", "rds_cluster", "dynamodb_table", "repository", "branch"],
};

// ---------------------------------------------------------------------------
// Overrides
// ---------------------------------------------------------------------------

export type MappingOverrides = Record<string, string>;

let cachedOverrides: MappingOverrides | null = null;

/**
 * Load pinned check-ID -> control-ID mappings.
 *
 * Format (JSON): { "CKV_AWS_19": "CC6.7", "CKV_AWS_24": "CC6.6" }
 *
 * Ships empty on purpose. Populate only with mappings you have validated
 * against a real scanner install; an unvalidated pin is worse than a heuristic
 * because it reports `confidence: "high"`.
 */
export function loadOverrides(path?: string): MappingOverrides {
  if (cachedOverrides) return cachedOverrides;
  const target = path ?? process.env["LOXE_MAPPING_OVERRIDES"];
  if (!target) {
    cachedOverrides = {};
    return cachedOverrides;
  }
  try {
    const parsed = JSON.parse(readFileSync(target, "utf8")) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const clean: MappingOverrides = {};
      for (const [checkId, controlId] of Object.entries(parsed as Record<string, unknown>)) {
        // Reject any override naming a control the catalog does not contain.
        // Silently accepting one would let a typo produce a mapping to a
        // control that does not exist.
        const control = typeof controlId === "string" ? getControl(controlId) : undefined;
        if (!control) {
          console.error(
            `[loxeai-mcp] ignoring mapping override ${checkId} -> ${String(controlId)}: not a supported control ID`,
          );
        } else if (control.iac === "none") {
          // Existence is not enough. An override to a criterion no
          // infrastructure scan can evidence -- CC1.2 board oversight, say --
          // would report `confidence: "high"` on a mapping that is definitionally
          // wrong, and would bypass the invariant that keyword rules respect.
          console.error(
            `[loxeai-mcp] ignoring mapping override ${checkId} -> ${controlId}: an IaC scan cannot evidence ` +
              `${controlId} (${control.title}). ${control.iacNote}`,
          );
        } else {
          // `control` is defined here, which narrows controlId to string.
          clean[checkId] = control.id;
        }
      }
      cachedOverrides = clean;
      return clean;
    }
  } catch (error) {
    console.error(`[loxeai-mcp] could not read mapping overrides at ${target}: ${(error as Error).message}`);
  }
  cachedOverrides = {};
  return cachedOverrides;
}

/** Test seam. */
export function __resetOverridesCache(): void {
  cachedOverrides = null;
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

function unmapped(rationale: string): ControlMapping {
  return {
    controlId: null,
    controlTitle: null,
    requirement: null,
    mappingSource: "unmapped",
    confidence: "none",
    rationale,
    evidenceLimit: null,
  };
}

function build(
  control: Soc2ControlOption,
  mappingSource: MappingSource,
  confidence: MappingConfidence,
  rationale: string,
): ControlMapping {
  const capability = IAC_EVIDENCE_CAPABILITY[control.id];
  return {
    controlId: control.id,
    controlTitle: control.title,
    requirement: control.description,
    mappingSource,
    confidence,
    rationale,
    evidenceLimit: capability?.note ?? null,
  };
}

/**
 * Map a scanner finding to a SOC 2 control.
 *
 * Precedence: validated override -> keyword rule corroborated by resource type
 * -> keyword rule alone -> unmapped. Never guesses past that.
 */
export function mapFindingToControl(input: {
  checkId?: string | null;
  checkName?: string | null;
  resourceType?: string | null;
}): ControlMapping {
  const { checkId, checkName, resourceType } = input;

  // 1. Validated override, highest confidence.
  if (checkId) {
    const overrides = loadOverrides();
    const pinned = overrides[checkId];
    if (pinned) {
      const control = getControl(pinned);
      if (control) {
        return build(control, "override", "high", `Pinned mapping for check ${checkId} from the validated overrides file.`);
      }
    }
  }

  const name = (checkName ?? "").toLowerCase();
  const resource = (resourceType ?? "").toLowerCase();

  if (!name && !resource) {
    return unmapped("No check name or resource type supplied, so no mapping could be derived.");
  }

  // 2. Keyword rules, in declaration order.
  for (const rule of KEYWORD_RULES) {
    const matchedTerm = rule.terms.find((term) => name.includes(term));
    if (!matchedTerm) continue;

    const control = getControl(rule.controlId);
    if (!control) continue;

    // Corroborate against the resource type to raise confidence.
    const hints = RESOURCE_HINTS[rule.controlId] ?? [];
    const resourceAgrees = resource.length > 0 && hints.some((hint) => resource.includes(hint));

    if (resourceAgrees) {
      return build(
        control,
        "resource-attribute",
        "medium",
        `${rule.why} Matched on check-name term "${matchedTerm}", corroborated by resource type "${resourceType}".`,
      );
    }

    return build(
      control,
      "keyword",
      "low",
      `${rule.why} Matched on check-name term "${matchedTerm}" only; resource type "${resourceType ?? "unknown"}" did not corroborate. Verify before relying on this.`,
    );
  }

  // 3. Resource type alone is too weak a signal to assert a control. Say so.
  return unmapped(
    `No keyword rule matched check name "${checkName ?? ""}". Resource type alone is not a sufficient signal to assert a control mapping. Treat this finding as security-relevant but unmapped.`,
  );
}

/** All controls an IaC scan can evidence at all — primary or partial. */
export function iacAddressableControls(): Soc2ControlOption[] {
  return Object.entries(IAC_EVIDENCE_CAPABILITY)
    .filter(([, v]) => v.capability === "primary" || v.capability === "partial")
    .map(([id]) => getControl(id))
    .filter((c): c is Soc2ControlOption => Boolean(c));
}

/**
 * Every control ID the keyword rules are capable of emitting.
 *
 * INVARIANT, enforced by test: this set must never contain a control whose
 * `iac` capability is `"none"`. Expanding the catalog from 12 to 33 criteria
 * deliberately did NOT expand what the mapper claims -- a scanner that starts
 * asserting CC1.2 (board oversight) or CC9.2 (vendor risk) because a check name
 * happened to contain a matching word would be exactly the overclaim this
 * package exists to avoid.
 */
export function mappableControlIds(): string[] {
  return [...new Set(KEYWORD_RULES.map((rule) => rule.controlId))].sort();
}
