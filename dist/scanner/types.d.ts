import type { ControlMapping } from "../catalog/control-mappings.js";
import type { RemediationMeta } from "../catalog/remediation-meta.js";
export type ScannerName = "checkov" | "trivy";
/**
 * Severity, normalized across scanners.
 *
 * UNKNOWN is a real and common value, not a defect: Checkov's open-source
 * output frequently returns `severity: null` because severity metadata ships
 * with Bridgecrew/Prisma. We surface UNKNOWN rather than inventing a level.
 *
 * Follows the engine's honesty convention (`core/data_models.py:21-26`) where
 * missing data becomes WARN or SKIP and never silently becomes a pass.
 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export declare const SEVERITY_RANK: Record<Severity, number>;
export type IacFramework = "terraform" | "terraform_plan" | "cloudformation" | "kubernetes" | "dockerfile" | "helm" | "arm" | "bicep" | "serverless" | "github_actions" | "unknown";
/** A single normalized misconfiguration finding. */
export type Finding = {
    /** Stable within a batch. `<checkId>:<filePath>:<resource>` hashed short. */
    id: string;
    checkId: string;
    checkName: string;
    severity: Severity;
    /** Full resource address, e.g. `aws_s3_bucket.data`. */
    resource: string;
    /** Resource type only, e.g. `aws_s3_bucket`. Drives mapping corroboration. */
    resourceType: string;
    /** Relative to the scan root. Never absolute: absolute paths leak layout. */
    filePath: string;
    lineRange: [number, number] | null;
    framework: IacFramework;
    guideline: string | null;
    scanner: ScannerName;
    /** SOC 2 mapping with explicit source and confidence. */
    mapping: ControlMapping;
    /** Blast-radius classification from the platform's classifier. */
    blastRadius: RemediationMeta;
};
/** Lightweight row for `list_findings`. Two-tier list/detail, per Prowler. */
export type FindingSummary = {
    id: string;
    checkId: string;
    checkName: string;
    severity: Severity;
    resource: string;
    filePath: string;
    controlId: string | null;
    mappingConfidence: ControlMapping["confidence"];
};
export type ScanCounts = {
    total: number;
    bySeverity: Record<Severity, number>;
    byControl: Record<string, number>;
    /** Findings no rule could map. Surfaced deliberately, never hidden. */
    unmapped: number;
};
export type Batch = {
    batchId: string;
    /**
     * SHA-256 over the normalized scanned input (sorted relative paths + content
     * hashes). Identical fingerprint across two scans proves the input did not
     * change -- the cleanest way to tell whether a rescan actually saw a fix.
     * Borrowed from `trivy-mcp`'s `ScanResponse.Fingerprint`.
     */
    fingerprint: string;
    scanner: ScannerName;
    scannerVersion: string;
    root: string;
    frameworks: IacFramework[];
    createdAt: string;
    /** Number of IaC files that contributed to `fingerprint`. */
    fileCount: number;
    /** True when the fingerprint walk hit its file cap and covers a subset. */
    fingerprintTruncated: boolean;
    findings: Finding[];
    counts: ScanCounts;
    /** Set when sanitization altered scanner output. Reported to the caller. */
    sanitization: {
        modified: boolean;
        invisibleCharsRemoved: number;
        injectionPatternsNeutralized: number;
    };
    /** Files the scanner could not parse. An honest partial result, not a pass. */
    parseErrors: string[];
    /**
     * Checks a developer explicitly suppressed (e.g. `#checkov:skip=CKV_AWS_19`).
     * Surfaced, never hidden: an unreported suppression lets the tool report a
     * clean result on request, which is worse than missing a finding outright.
     */
    /**
     * True when the retained finding list was capped.
     *
     * Measured cost is ~514 bytes per finding, so an uncapped 200k-finding
     * monorepo is ~98 MB per batch; ten retained batches exhaust the default Node
     * heap mid-session.
     *
     * Truncation MUST block a clean claim: a criterion showing no exceptions may
     * simply have had its findings dropped.
     */
    findingsTruncated: boolean;
    /** Findings the scanner produced before any cap. `counts` reflects this. */
    totalFindings: number;
    /** Resources the scanner actually evaluated. 0 means the scan did nothing. */
    evaluatedResources: number;
    /** Checks that returned a verdict. 0 means the scan did nothing. */
    evaluatedChecks: number;
    suppressions: Array<{
        checkId: string;
        checkName: string;
        resource: string;
        filePath: string;
        reason: string;
    }>;
};
export declare function emptyCounts(): ScanCounts;
export declare function toSummary(finding: Finding): FindingSummary;
