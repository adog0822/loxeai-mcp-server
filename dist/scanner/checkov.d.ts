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
import type { Finding, IacFramework } from "./types.js";
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
export declare function parseCheckovJson(stdout: string, root: string): CheckovRunResult;
export declare function runCheckov(options: {
    root: string;
    command?: string;
    frameworks?: string[];
    configPath?: string;
    timeoutMs?: number;
}): Promise<CheckovRunResult>;
