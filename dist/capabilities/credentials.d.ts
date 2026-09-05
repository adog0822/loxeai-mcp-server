/**
 * Credential capability reporting.
 *
 * ---------------------------------------------------------------------------
 * THE PROBLEM THIS EXISTS TO SURFACE
 * ---------------------------------------------------------------------------
 * "Read-only" is two different claims, and conflating them is a
 * misrepresentation that a security reviewer will find:
 *
 *   (a) THIS SERVER PERFORMS NO WRITE OPERATIONS.
 *       Provable by code inspection. CI greps `src/` for filesystem writes and
 *       for any mutating API call. This is true and we can defend it.
 *
 *   (b) THE CREDENTIAL CANNOT WRITE.
 *       A property of the token, NOT of our code. When a tool inherits a
 *       developer's ambient CLI session, it does not get to choose the scopes.
 *
 * Concrete cases, both verified:
 *
 *   - GitHub: a typical `gh auth login` yields scopes including `repo` (full
 *     control of private repositories -- read AND write) and `workflow` (modify
 *     GitHub Actions workflow files). Write-capable.
 *
 *   - Azure: `az login` requests Microsoft Graph with `/.default`, so the token
 *     carries whatever Microsoft pre-authorised for the Azure CLI's client ID.
 *     That set includes `Group.ReadWrite.All` and `User.ReadWrite.All`. You
 *     cannot narrow it, and no tenant admin can either.
 *
 * So on GitHub, true credential-level read-only IS achievable, via a
 * fine-grained PAT with read-only repository permissions. On Azure via `az`, it
 * is NOT. This module reports which situation the user is actually in rather
 * than letting the README imply a guarantee that does not hold.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS MODULE DOES NOT DO
 * ---------------------------------------------------------------------------
 * It never authenticates, never refreshes a token, never reads a token value,
 * and never transmits anything. It shells out to already-installed CLIs to ask
 * them what they are already logged in as. If a CLI is absent or logged out,
 * that is reported as-is -- never as "no risk".
 */
export type WriteCapability = "read-only" | "write-capable" | "unknown";
export type CredentialReport = {
    tool: string;
    installed: boolean;
    authenticated: boolean;
    /** Non-secret identity string, e.g. a username or an ARN. Never a token. */
    identity: string | null;
    /** Scopes/permissions as reported by the CLI, when it will say. */
    scopes: string[];
    writeCapability: WriteCapability;
    /** Which specific scopes make it write-capable. Empty when read-only. */
    writeCapableVia: string[];
    /** Plain-English explanation of the situation. Always populated. */
    assessment: string;
    /** How to obtain a genuinely read-only credential, when one is possible. */
    narrowerAlternative: string | null;
};
export type CapabilityReport = {
    serverGuarantee: string;
    credentials: CredentialReport[];
    summary: {
        anyWriteCapable: boolean;
        anyUnknown: boolean;
        headline: string;
    };
    caveats: string[];
};
export declare function classifyGithubScopes(scopes: string[]): {
    capability: WriteCapability;
    writeCapableVia: string[];
};
export declare function buildCapabilityReport(): Promise<CapabilityReport>;
