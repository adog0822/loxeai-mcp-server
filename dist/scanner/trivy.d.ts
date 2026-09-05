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
import type { Finding, IacFramework } from "./types.js";
export type TrivyRunResult = {
    findings: Finding[];
    parseErrors: string[];
    frameworks: IacFramework[];
    /** Trivy does not report suppressions in `config` output. Always empty. */
    suppressions: never[];
    evaluatedResources: number;
    evaluatedChecks: number;
};
/**
 * Parse Trivy `config --format json` output.
 *
 * Split out from `runTrivy` so the parse path is testable without a Trivy
 * install.
 */
export declare function parseTrivyJson(stdout: string): TrivyRunResult;
export declare function runTrivy(options: {
    root: string;
    command?: string;
    timeoutMs?: number;
}): Promise<TrivyRunResult>;
