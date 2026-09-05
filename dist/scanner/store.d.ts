/**
 * In-memory batch store with cursor paging.
 *
 * `scan_iac` returns a handoff -- `{ batchId, fingerprint, counts, next }` --
 * not findings. A real Terraform repo yields hundreds of findings; returning
 * them inline would blow the context window and is why every mature scanner MCP
 * (Trivy's `Next`, Prowler's two-tier list/detail, Snyk's output-to-file mode)
 * refuses to do it.
 *
 * State is process-local and deliberately not persisted: a batch is only
 * meaningful for the session that produced it, and writing scan results to disk
 * would create a new artifact to secure.
 */
import type { Batch, Finding, FindingSummary, Severity } from "./types.js";
export declare function putBatch(batch: Omit<Batch, "batchId">): Batch;
export declare function getBatch(batchId: string): Batch | undefined;
export declare function listBatchIds(): string[];
/** Test seam. */
export declare function __clearBatches(): void;
export type FindingFilter = {
    minSeverity?: Severity;
    controlId?: string;
    /** Only findings no rule could map. Useful for validating the mapping layer. */
    unmappedOnly?: boolean;
};
/**
 * Filter findings.
 *
 * UNKNOWN severity is NEVER dropped by `minSeverity`. Checkov's open-source
 * output commonly omits severity, and silently hiding those findings behind a
 * severity filter would under-report real misconfigurations -- the failure mode
 * that matters in a compliance tool. They sort last but stay visible.
 */
export declare function filterFindings(findings: Finding[], filter: FindingFilter): Finding[];
export declare function sortFindings(findings: Finding[]): Finding[];
export type Page = {
    findings: FindingSummary[];
    nextCursor: string | null;
    total: number;
    returned: number;
};
export declare class CursorMismatchError extends Error {
    constructor();
}
export declare function pageFindings(findings: Finding[], limit: number, cursor?: string, filter?: unknown): Page;
