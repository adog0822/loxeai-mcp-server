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

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

// ---------------------------------------------------------------------------
// GitHub scope classification
// ---------------------------------------------------------------------------

/**
 * Classic OAuth scopes that grant only read.
 *
 * Deliberately an ALLOW-LIST: anything not on it is treated as write-capable or
 * unknown. Failing open here would defeat the whole point of the tool.
 */
const GITHUB_READ_ONLY_SCOPES = new Set([
  "read:org",
  "read:user",
  "read:public_key",
  "read:repo_hook",
  "read:packages",
  "read:discussion",
  "read:enterprise",
  "read:gpg_key",
  "read:ssh_signing_key",
  "read:project",
  "read:audit_log",
  "user:email",
  "user:follow",
]);

/** Scopes whose write capability is worth naming explicitly to the user. */
const GITHUB_SCOPE_NOTES: Record<string, string> = {
  repo: "full control of private repositories — read AND write, including code, issues and settings",
  public_repo: "write access to public repositories",
  workflow: "create and modify GitHub Actions workflow files",
  gist: "create and modify gists",
  "write:org": "write access to organisation membership and teams",
  "admin:org": "full administrative access to the organisation",
  delete_repo: "DELETE repositories",
  "admin:repo_hook": "full control of repository webhooks",
  "write:packages": "publish packages",
  "delete:packages": "delete packages",
  user: "read and write access to the user profile",
  notifications: "read and mark notifications",
  security_events: "read and write security events, including dismissing code-scanning alerts",
  "repo:status": "read and write commit statuses",
  "admin:public_key": "full control of public keys",
  "admin:gpg_key": "full control of GPG keys",
};

export function classifyGithubScopes(scopes: string[]): {
  capability: WriteCapability;
  writeCapableVia: string[];
} {
  if (scopes.length === 0) return { capability: "unknown", writeCapableVia: [] };

  const writeCapableVia = scopes.filter((s) => !GITHUB_READ_ONLY_SCOPES.has(s));
  if (writeCapableVia.length === 0) return { capability: "read-only", writeCapableVia: [] };
  return { capability: "write-capable", writeCapableVia };
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

async function run(cmd: string, args: string[], timeoutMs = 15_000): Promise<{ ok: boolean; out: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, { timeout: timeoutMs });
    return { ok: true, out: `${stdout}${stderr}` };
  } catch (error) {
    const e = error as { stdout?: string; stderr?: string; code?: string };
    if (e.code === "ENOENT") return { ok: false, out: "__NOT_INSTALLED__" };
    return { ok: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

async function probeGithub(): Promise<CredentialReport> {
  const base: CredentialReport = {
    tool: "gh (GitHub CLI)",
    installed: false,
    authenticated: false,
    identity: null,
    scopes: [],
    writeCapability: "unknown",
    writeCapableVia: [],
    assessment: "",
    narrowerAlternative: null,
  };

  const { ok, out } = await run("gh", ["auth", "status"]);
  if (out === "__NOT_INSTALLED__") {
    return { ...base, assessment: "The GitHub CLI is not installed. No GitHub credential is available to this machine." };
  }
  base.installed = true;

  if (!ok && /not logged/i.test(out)) {
    return { ...base, assessment: "The GitHub CLI is installed but not logged in. No GitHub credential is available." };
  }

  const account = out.match(/Logged in to \S+ account (\S+)/);
  if (account?.[1]) {
    base.authenticated = true;
    base.identity = account[1];
  }

  const scopeLine = out.match(/Token scopes:\s*(.+)/);
  if (scopeLine?.[1]) {
    base.scopes = scopeLine[1]
      .split(",")
      .map((s) => s.trim().replace(/^'|'$/g, ""))
      .filter(Boolean);
  }

  const { capability, writeCapableVia } = classifyGithubScopes(base.scopes);
  base.writeCapability = capability;
  base.writeCapableVia = writeCapableVia;

  if (capability === "write-capable") {
    const detail = writeCapableVia
      .map((s) => (GITHUB_SCOPE_NOTES[s] ? `${s} (${GITHUB_SCOPE_NOTES[s]})` : s))
      .join("; ");
    base.assessment =
      `Your GitHub token carries write-capable scopes: ${detail}. ` +
      `This server never calls a write endpoint, so nothing will be modified — but the credential itself ` +
      `could write. That distinction matters if someone asks you to prove read-only access.`;
    base.narrowerAlternative =
      "For a credential that cannot write at all, create a fine-grained personal access token with " +
      "read-only repository permissions (Contents: Read, Metadata: Read, Pull requests: Read) and expose it " +
      "as GH_TOKEN. GitHub fine-grained PATs support genuine read-only scoping, so on GitHub this is achievable.";
  } else if (capability === "read-only") {
    base.assessment =
      `Your GitHub token carries only read scopes (${base.scopes.join(", ")}). ` +
      `Credential-level read-only is satisfied here, not just enforced by this server's code.`;
  } else {
    base.assessment =
      base.authenticated
        ? "Logged in, but the CLI did not report token scopes. Capability cannot be determined — treat as write-capable until confirmed."
        : "Could not determine GitHub authentication state.";
  }

  return base;
}

async function probeAws(): Promise<CredentialReport> {
  const base: CredentialReport = {
    tool: "aws (AWS CLI)",
    installed: false,
    authenticated: false,
    identity: null,
    scopes: [],
    writeCapability: "unknown",
    writeCapableVia: [],
    assessment: "",
    narrowerAlternative: null,
  };

  const version = await run("aws", ["--version"]);
  if (version.out === "__NOT_INSTALLED__") {
    return { ...base, assessment: "The AWS CLI is not installed. No AWS credential is available to this machine." };
  }
  base.installed = true;

  const ident = await run("aws", ["sts", "get-caller-identity", "--output", "json"], 20_000);
  if (!ident.ok) {
    return {
      ...base,
      assessment:
        "The AWS CLI is installed but no valid credentials resolved (expired SSO session, or no profile configured).",
    };
  }

  try {
    const parsed = JSON.parse(ident.out) as { Arn?: string; Account?: string };
    base.authenticated = true;
    // The ARN identifies the principal. The account ID is masked to last four --
    // it is not a secret, but it does not belong in a transcript in full.
    const arn = parsed.Arn ?? null;
    base.identity = arn ? arn.replace(/\d{12}/, (m) => `****${m.slice(-4)}`) : null;
  } catch {
    return { ...base, assessment: "AWS credentials resolved but the identity response could not be parsed." };
  }

  // IAM does not expose "what may this principal do" without either simulating
  // a specific action or reading attached policies. Guessing would be worse
  // than saying so.
  base.writeCapability = "unknown";
  base.assessment =
    `AWS credentials are present for ${base.identity}. AWS does not expose an enumerable scope list the way ` +
    `OAuth does — a principal's effective permissions come from attached policies, SCPs and session policies, ` +
    `and determining them requires either reading those policies or simulating specific actions. ` +
    `This server therefore cannot certify your AWS credential as read-only, and does not try. ` +
    `It never calls a mutating AWS API.`;
  base.narrowerAlternative =
    "For a credential that provably cannot write, use a dedicated profile assuming a role with only the " +
    "AWS-managed ReadOnlyAccess or SecurityAudit policy attached, and select it with AWS_PROFILE.";

  return base;
}

async function probeGcloud(): Promise<CredentialReport> {
  const base: CredentialReport = {
    tool: "gcloud (Google Cloud CLI)",
    installed: false,
    authenticated: false,
    identity: null,
    scopes: [],
    writeCapability: "unknown",
    writeCapableVia: [],
    assessment: "",
    narrowerAlternative: null,
  };

  const version = await run("gcloud", ["--version"]);
  if (version.out === "__NOT_INSTALLED__") {
    return {
      ...base,
      // NOT "read-only". An absent CLI has no capability at all; reporting it
      // as read-only would let it count toward a clean headline.
      writeCapability: "unknown",
      assessment: "The gcloud CLI is not installed. No Google Cloud credential is available to this machine.",
    };
  }
  base.installed = true;

  // Does it actually hold an active account? An installed-but-logged-out CLI is
  // harmless; an installed-and-authenticated one is the case that matters, and
  // the previous implementation never checked.
  const acct = await run("gcloud", ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"], 20_000);
  const active = acct.ok ? acct.out.trim().split("\n")[0]?.trim() : "";
  if (!active) {
    return { ...base, assessment: "The gcloud CLI is installed but has no active account. No credential is available." };
  }

  base.authenticated = true;
  base.identity = active.replace(/^([^@]{1,3})[^@]*@/, "$1***@");
  base.assessment =
    `gcloud is authenticated as ${base.identity}. Google Cloud scopes access by IAM role rather than by an ` +
    `enumerable OAuth scope list, so this server cannot determine whether the credential can write — and a ` +
    `default user credential very often can. Treat it as write-capable unless you have confirmed otherwise. ` +
    `This server never calls a mutating Google Cloud API.`;
  base.narrowerAlternative =
    "For a credential that provably cannot write, impersonate a service account granted only roles/viewer " +
    "and select it with CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT.";
  return base;
}

async function probeAzure(): Promise<CredentialReport> {
  const base: CredentialReport = {
    tool: "az (Azure CLI)",
    installed: false,
    authenticated: false,
    identity: null,
    scopes: [],
    writeCapability: "unknown",
    writeCapableVia: [],
    assessment: "",
    narrowerAlternative: null,
  };

  const version = await run("az", ["--version"]);
  if (version.out === "__NOT_INSTALLED__") {
    return { ...base, assessment: "The Azure CLI is not installed. No Azure credential is available to this machine." };
  }
  base.installed = true;

  const acct = await run("az", ["account", "show", "--query", "user.name", "-o", "tsv"], 25_000);
  const who = acct.ok ? acct.out.trim().split("\n")[0]?.trim() : "";
  if (!who) {
    return { ...base, assessment: "The Azure CLI is installed but not logged in. No credential is available." };
  }

  base.authenticated = true;
  base.identity = who.replace(/^([^@]{1,3})[^@]*@/, "$1***@");
  // This one IS knowable, and it is knowably bad.
  base.writeCapability = "write-capable";
  base.writeCapableVia = ["Group.ReadWrite.All", "User.ReadWrite.All"];
  base.assessment =
    `az is logged in as ${base.identity}. Its Microsoft Graph token is requested with /.default, so it carries ` +
    `exactly the scopes Microsoft pre-authorised for the Azure CLI client — a set that includes ` +
    `Group.ReadWrite.All and User.ReadWrite.All. Those are WRITE scopes, and neither you nor a tenant admin ` +
    `can narrow them. Credential-level read-only is therefore NOT achievable through \`az\`. ` +
    `This server never calls a mutating Azure or Graph API. ` +
    `(The pre-authorised set is not officially documented; verify for your tenant by decoding the scp claim of ` +
    `\`az account get-access-token --resource-type ms-graph\`.)`;
  base.narrowerAlternative =
    "For a credential that provably cannot write, register a dedicated app with read-only application " +
    "permissions (admin consent required) and authenticate as that service principal instead of using `az login`.";
  return base;
}


// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const CAVEATS = [
  "This server performs no write operations. That is a property of its code and is verified in CI, which greps for filesystem writes and mutating API calls.",
  "Whether a CREDENTIAL can write is a separate question, and not one this server controls when it inherits an ambient CLI session. That is what this report is for.",
  "Nothing here reads, stores, or transmits a token value. These probes ask each CLI what it is already logged in as.",
  "An absent or logged-out CLI is reported as absent. It is never reported as safe.",
];

export async function buildCapabilityReport(): Promise<CapabilityReport> {
  const credentials = await Promise.all([
    probeGithub(),
    probeAws(),
    probeGcloud(),
    probeAzure(),
  ]);

  const anyWriteCapable = credentials.some((c) => c.writeCapability === "write-capable");
  const anyUnknown = credentials.some((c) => c.authenticated && c.writeCapability === "unknown");

  let headline: string;
  if (anyWriteCapable) {
    const names = credentials.filter((c) => c.writeCapability === "write-capable").map((c) => c.tool);
    headline =
      `At least one available credential is write-capable (${names.join(", ")}). ` +
      `This server will not write anything, but the credential could. See narrowerAlternative for how to fix that if you need a provable guarantee.`;
  } else if (anyUnknown) {
    const names = credentials.filter((c) => c.authenticated && c.writeCapability === "unknown").map((c) => c.tool);
    headline =
      `No credential could be certified read-only. ${names.join(", ")} ${names.length === 1 ? "is" : "are"} ` +
      `authenticated but ${names.length === 1 ? "does" : "do"} not expose an enumerable scope list, so write ` +
      `capability is UNKNOWN — assume it can write until you have confirmed otherwise. This server never calls a mutating API.`;
  } else {
    const authed = credentials.filter((c) => c.authenticated);
    headline =
      authed.length === 0
        ? "No authenticated cloud or VCS credential was found on this machine."
        : "No write-capable credential was detected among the authenticated CLIs on this machine.";
  }

  return {
    serverGuarantee:
      "This server performs no write operations of any kind: no filesystem writes, no mutating API calls. Remediation is returned as text for your agent to apply through its own approval step.",
    credentials,
    summary: { anyWriteCapable, anyUnknown, headline },
    caveats: CAVEATS,
  };
}
