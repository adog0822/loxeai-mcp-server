/**
 * Scanner detection and path trust.
 *
 * Two responsibilities, both safety-relevant:
 *
 * 1. Detect which scanner is installed. If none is, say so with install
 *    instructions -- NEVER return an empty finding list, which a model would
 *    reasonably read as "this infrastructure is compliant".
 *
 * 2. Gate scanning on an explicitly trusted path. Scanners execute third-party
 *    toolchains and read arbitrary files. Snyk ships this as a first-class
 *    `snyk_trust` tool with the description "ONLY RUN THIS TOOL IF INSTRUCTED
 *    TO DO SO", precisely because a scan is not a neutral read.
 */
import type { ScannerName } from "./types.js";
export type DetectedScanner = {
    name: ScannerName;
    version: string;
    command: string;
};
/** Detect installed scanners, preferring Checkov for SOC 2 mapping depth. */
export declare function detectScanners(force?: boolean): Promise<DetectedScanner[]>;
/** Test seam. */
export declare function __resetScannerCache(): void;
export declare const SCANNER_INSTALL_HELP: string;
export type TrustResult = {
    ok: true;
    resolved: string;
} | {
    ok: false;
    reason: string;
};
/**
 * Validate a caller-supplied scan path.
 *
 * Requires an absolute path. Every path-taking scanner in this space does --
 * Snyk's own tool description tells the agent the path "MUST be absolute" and
 * to run `pwd` first -- because relative resolution against an MCP server's
 * working directory is ambiguous and silently scans the wrong tree.
 */
export declare function assertTrustedPath(inputPath: string): TrustResult;
