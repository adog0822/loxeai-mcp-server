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

import { execFile } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { promisify } from "node:util";
import type { ScannerName } from "./types.js";

const execFileAsync = promisify(execFile);

export type DetectedScanner = { name: ScannerName; version: string; command: string };

let cache: DetectedScanner[] | null = null;

async function probe(command: string, args: string[]): Promise<string | null> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout: 15_000 });
    const out = `${stdout}${stderr}`.trim();
    return out.length > 0 ? out.split("\n")[0]!.trim() : null;
  } catch {
    return null;
  }
}

/** Detect installed scanners, preferring Checkov for SOC 2 mapping depth. */
export async function detectScanners(force = false): Promise<DetectedScanner[]> {
  if (cache && !force) return cache;

  const found: DetectedScanner[] = [];

  const checkov = await probe("checkov", ["--version"]);
  if (checkov) found.push({ name: "checkov", version: checkov, command: "checkov" });

  const trivy = await probe("trivy", ["--version"]);
  if (trivy) {
    // `trivy --version` prints e.g. "Version: 0.55.0"; keep the whole first line.
    found.push({ name: "trivy", version: trivy, command: "trivy" });
  }

  cache = found;
  return found;
}

/** Test seam. */
export function __resetScannerCache(): void {
  cache = null;
}

export const SCANNER_INSTALL_HELP = [
  "No supported IaC scanner was found on PATH. This server wraps an existing",
  "scanner rather than reimplementing one, so one must be installed.",
  "",
  "Install ONE of the following, then retry:",
  "",
  "  Checkov (recommended -- deepest compliance metadata):",
  "    pipx install checkov       # or: pip install checkov",
  "",
  "  Trivy (faster, single binary, no Python):",
  "    brew install trivy         # or see https://trivy.dev/latest/getting-started/installation/",
  "",
  "Verify with `checkov --version` or `trivy --version`.",
  "",
  "IMPORTANT: no scan was performed. This is NOT a clean result. Do not report",
  "this infrastructure as compliant.",
].join("\n");

// ---------------------------------------------------------------------------
// Path trust
// ---------------------------------------------------------------------------

export type TrustResult = { ok: true; resolved: string } | { ok: false; reason: string };

/**
 * Directories that are never in scope. Scanning these reads credential
 * material into a model's context with no compliance benefit.
 */
const DENIED_SEGMENTS = [
  `${sep}.ssh${sep}`,
  `${sep}.aws${sep}`,
  `${sep}.gnupg${sep}`,
  `${sep}.kube${sep}`,
  `${sep}.config${sep}gcloud${sep}`,
  `${sep}Library${sep}Keychains${sep}`,
];

function trustedRoots(): string[] {
  const configured = process.env["LOXE_TRUSTED_ROOTS"];
  if (configured && configured.trim().length > 0) {
    return configured
      .split(":")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => resolve(entry));
  }
  // Default to the process working directory, which for a stdio MCP server is
  // the project the client launched it from.
  return [resolve(process.cwd())];
}

/**
 * Validate a caller-supplied scan path.
 *
 * Requires an absolute path. Every path-taking scanner in this space does --
 * Snyk's own tool description tells the agent the path "MUST be absolute" and
 * to run `pwd` first -- because relative resolution against an MCP server's
 * working directory is ambiguous and silently scans the wrong tree.
 */
export function assertTrustedPath(inputPath: string): TrustResult {
  if (!inputPath || inputPath.trim().length === 0) {
    return { ok: false, reason: "No path supplied." };
  }

  if (!isAbsolute(inputPath)) {
    return {
      ok: false,
      reason:
        `Path "${inputPath}" is relative. Supply an absolute path -- run \`pwd\` in the ` +
        "target directory and pass the full path. Relative paths resolve against this " +
        "server's working directory and would scan the wrong tree.",
    };
  }

  const lexical = resolve(inputPath);

  if (!existsSync(lexical)) {
    return { ok: false, reason: `Path does not exist: ${lexical}` };
  }

  // CRITICAL: resolve symlinks before ANY check below.
  //
  // `path.resolve` is pure string arithmetic -- it does not touch the
  // filesystem. Without realpath, a symlink committed inside a trusted repo
  // (`ln -s ~/.aws ./terraform`) passes both the credential denylist and the
  // trusted-root prefix check, because both only ever see the link path. The
  // scanner then follows the link and reads the target into model context.
  let resolved: string;
  try {
    resolved = realpathSync(lexical);
  } catch (error) {
    return { ok: false, reason: `Path could not be resolved: ${(error as Error).message}` };
  }

  if (resolved !== lexical) {
    // Not an error -- symlinks are legitimate -- but every check below now runs
    // against the real target, and the caller is told what it actually got.
    console.error(`[loxeai-mcp] resolved symlink ${lexical} -> ${resolved}`);
  }

  const withTrailing = statSync(resolved).isDirectory() ? `${resolved}${sep}` : resolved;
  // Lowercase both sides: macOS and Windows default to case-insensitive
  // filesystems, so `/Users/me/.AWS` and `/Users/me/.aws` are the same
  // directory but only one matched a case-sensitive denylist.
  const haystack = withTrailing.toLowerCase();
  for (const denied of DENIED_SEGMENTS) {
    if (haystack.includes(denied.toLowerCase())) {
      return {
        ok: false,
        reason:
          `Refusing to scan ${resolved}: the path is inside a credential directory ` +
          `(${denied.replaceAll(sep, "")}). Scanning it would read secret material into model context.`,
      };
    }
  }

  if (process.env["LOXE_DISABLE_TRUST"] === "true") {
    // Explicit opt-out, logged to stderr so it is visible in client logs.
    console.error(`[loxeai-mcp] trust check bypassed via LOXE_DISABLE_TRUST for ${resolved}`);
    return { ok: true, resolved };
  }

  // Roots are realpath'd too: if the root itself is reached through a symlink
  // (common with /tmp on macOS, which is a link to /private/tmp), a realpath'd
  // target would never match a lexical root.
  const roots = trustedRoots().map((root) => {
    try {
      return realpathSync(root);
    } catch {
      return root;
    }
  });
  const inRoot = roots.some((root) => resolved === root || resolved.startsWith(`${root}${sep}`));
  if (!inRoot) {
    return {
      ok: false,
      reason:
        `Refusing to scan ${resolved}: it is outside every trusted root.\n\n` +
        `Trusted roots: ${roots.join(", ")}\n\n` +
        "To allow it, set LOXE_TRUSTED_ROOTS to a colon-separated list of directories, " +
        "or set LOXE_DISABLE_TRUST=true to disable the check entirely (not recommended).",
    };
  }

  return { ok: true, resolved };
}
