/**
 * Input fingerprinting.
 *
 * A fingerprint is a SHA-256 over the sorted set of (relative path, content
 * hash) pairs for every IaC file under the scan root. Two scans with the same
 * fingerprint provably saw identical input.
 *
 * Content is hashed in FULL, at any file size -- see `hashFile`. A fingerprint
 * that ignored part of a file would make the byte-identity claim false, which
 * is the claim `verify --expect` and the trust page footer both rest on.
 *
 * This matters because the scan -> fix -> rescan loop is otherwise unverifiable:
 * an agent can claim it applied a fix and rescanned, and a fingerprint that did
 * not change proves it did not. Borrowed from `trivy-mcp`, whose
 * `ScanResponse.Fingerprint` is documented as a "hash of normalized content".
 */
export type FingerprintResult = {
    fingerprint: string;
    fileCount: number;
    /** True when MAX_FILES was hit, so the fingerprint covers a subset. */
    truncated: boolean;
};
export declare function fingerprintInputs(root: string): FingerprintResult;
/** Short, stable per-finding id. */
export declare function findingId(parts: {
    checkId: string;
    filePath: string;
    resource: string;
}): string;
