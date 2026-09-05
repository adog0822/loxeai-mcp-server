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
import { type Soc2ControlOption } from "./soc2-controls.js";
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
export type MappingOverrides = Record<string, string>;
/**
 * Load pinned check-ID -> control-ID mappings.
 *
 * Format (JSON): { "CKV_AWS_19": "CC6.7", "CKV_AWS_24": "CC6.6" }
 *
 * Ships empty on purpose. Populate only with mappings you have validated
 * against a real scanner install; an unvalidated pin is worse than a heuristic
 * because it reports `confidence: "high"`.
 */
export declare function loadOverrides(path?: string): MappingOverrides;
/** Test seam. */
export declare function __resetOverridesCache(): void;
/**
 * Map a scanner finding to a SOC 2 control.
 *
 * Precedence: validated override -> keyword rule corroborated by resource type
 * -> keyword rule alone -> unmapped. Never guesses past that.
 */
export declare function mapFindingToControl(input: {
    checkId?: string | null;
    checkName?: string | null;
    resourceType?: string | null;
}): ControlMapping;
/** All controls an IaC scan can evidence at all — primary or partial. */
export declare function iacAddressableControls(): Soc2ControlOption[];
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
export declare function mappableControlIds(): string[];
