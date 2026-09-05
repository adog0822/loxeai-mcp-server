/**
 * Sanitization of untrusted scanner output before it enters model context.
 *
 * WHY THIS EXISTS
 * ---------------
 * IaC files carry attacker-influenceable strings: resource names, tags,
 * comments, `description` fields, and `source = "git::..."` module URLs. A
 * scanner echoes those back inside finding messages and resource identifiers.
 * That text then flows into an agent that holds filesystem write access.
 *
 * GitHub's own MCP server reaches the same conclusion in source
 * (`pkg/github/code_scanning.go`):
 *
 *   // Code scanning alerts are access-restricted regardless of repo
 *   // visibility and embed attacker-influenceable code snippets, so the
 *   // label is always private-untrusted.
 *
 * Modelled on `awslabs/aws_iac_mcp_server/sanitizer.py`, which filters unicode
 * tag characters, detects injection patterns, and wraps content in XML tags for
 * clear boundaries.
 *
 * WHAT THIS DOES NOT DO
 * ---------------------
 * This reduces the attack surface. It does NOT eliminate semantic prompt
 * injection, and no encoding step can. Plausible-looking instruction text that
 * avoids the patterns below will still reach the model. Do not describe this
 * module -- in docs, in marketing, or in a security matrix -- as preventing
 * prompt injection.
 *
 * In particular: serializing to JSON is not a defence. `{"name": "Ignore all
 * previous instructions"}` is still legible instruction text to a model.
 * Serialization defeats parser confusion, not semantic injection.
 */
export type SanitizeResult = {
    text: string;
    /** True when anything was altered. Surface this to the caller; do not swallow it. */
    modified: boolean;
    invisibleCharsRemoved: number;
    injectionPatternsNeutralized: number;
};
/**
 * Sanitize a single untrusted string.
 *
 * Order matters: invisible characters are stripped FIRST, so that
 * `ign​ore all previous instructions` cannot evade the pattern pass by
 * hiding a zero-width space inside a keyword.
 */
export declare function sanitizeText(input: string): SanitizeResult;
/** Recursively sanitize every string in a JSON-ish value. */
export declare function sanitizeDeep<T>(value: T): {
    value: T;
    modified: boolean;
    stats: {
        invisibleCharsRemoved: number;
        injectionPatternsNeutralized: number;
    };
};
/**
 * Wrap untrusted content in an explicit boundary so the model can tell data
 * from instruction.
 *
 * The label follows GitHub's information-flow-control convention: scanner
 * output derives from repository file contents and is always untrusted,
 * regardless of who owns the repo.
 */
export declare function wrapUntrusted(content: string, kind: string): string;
/**
 * Redact a message before it reaches the model.
 *
 * Scanner invocations shell out to third-party toolchains whose stack traces can
 * embed absolute paths, environment values and argv. Prowler sets
 * `mask_error_details=True` on every sub-server for this reason: a debug
 * traceback must not be replayable into a model's context.
 */
export declare function safeErrorMessage(error: unknown, fallback: string): string;
