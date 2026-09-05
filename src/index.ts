#!/usr/bin/env node
/**
 * @loxeai/mcp-server -- entry point.
 *
 * Compliance automation over MCP. Scans Infrastructure-as-Code locally and maps
 * findings to SOC 2 Trust Services Criteria.
 *
 * ARCHITECTURE: local-first by design. The scan runs on this machine via an
 * installed Checkov or Trivy. File contents are never transmitted anywhere; this
 * process makes no outbound network requests at all. That is a stronger
 * guarantee than a hosted scanner can offer, because IaC routinely contains
 * .tfvars secrets, account IDs, internal hostnames and CIDR ranges.
 *
 * STDOUT DISCIPLINE: this is a stdio server. The MCP spec is unambiguous --
 * "The server MUST NOT write anything to its stdout that is not a valid MCP
 * message." Every diagnostic in this package goes to stderr via console.error.
 * A single stray console.log corrupts the protocol stream, and the failure looks
 * like a mysterious client-side parse error rather than an obvious bug.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerPrompts } from "./prompts/index.js";
import { registerResources } from "./resources/index.js";
import { registerTools } from "./tools/index.js";
import { detectScanners } from "./scanner/detect.js";

const SERVER_NAME = "loxeai-compliance";
const SERVER_VERSION = "0.1.0";

/**
 * `verify` subcommand.
 *
 * The trust page footer tells a viewer to run this to recompute the input
 * fingerprint themselves. It therefore has to exist -- a verification
 * instruction that does nothing is worse than omitting it, because the whole
 * differentiator of the artifact is that its claims are checkable.
 *
 * Runs entirely locally, needs no scanner, and prints nothing to stdout that is
 * not the answer. Exit 0 on match, 1 on mismatch, 2 on usage error.
 */
async function runVerify(argv: string[]): Promise<number> {
  const arg = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const root = arg("--root");
  const expected = arg("--expect");

  if (!root) {
    process.stderr.write("usage: loxeai-mcp-server verify --root <absolute-path> [--expect <sha256>]\n");
    return 2;
  }

  // Scope the trusted root to the path the human explicitly asked about.
  //
  // The trusted-root check exists to stop an AGENT from wandering outside the
  // project. `verify` has no agent in the loop: a person typed the path, and the
  // only output is a hash -- no file content reaches anyone. Requiring the path
  // to sit under cwd would just break the documented use case, which is a
  // third-party reviewer checking someone else's repo.
  //
  // The credential denylist still applies, so this cannot be used to fingerprint
  // ~/.ssh, and symlinks are still resolved before every check.
  process.env["LOXE_TRUSTED_ROOTS"] = root;
  const { assertTrustedPath } = await import("./scanner/detect.js");
  const trust = assertTrustedPath(root);
  if (!trust.ok) {
    process.stderr.write(`${trust.reason}\n`);
    return 2;
  }

  const { fingerprintInputs } = await import("./scanner/fingerprint.js");
  const fp = fingerprintInputs(trust.resolved);

  process.stdout.write(`${fp.fingerprint}\n`);
  process.stderr.write(
    `files fingerprinted: ${fp.fileCount}${fp.truncated ? " (TRUNCATED -- covers a subset)" : ""}\n`,
  );

  if (!expected) return 0;

  if (expected === fp.fingerprint) {
    process.stderr.write("MATCH: this tree is byte-identical to the one that produced that report.\n");
    return 0;
  }
  process.stderr.write(
    "MISMATCH: this tree is NOT the one that produced that report. The files changed, " +
      "the scan root differed, or the report does not describe this code.\n",
  );
  return 1;
}

async function main(): Promise<void> {
  // Subcommand dispatch before any MCP wiring. Nothing may reach stdout in
  // server mode except protocol messages, so this branch must return first.
  const argv = process.argv.slice(2);
  if (argv[0] === "verify") {
    process.exit(await runVerify(argv.slice(1)));
  }
  if (argv[0] === "--help" || argv[0] === "-h") {
    process.stderr.write(
      [
        "loxeai-mcp-server -- SOC 2 compliance MCP server (local, read-only)",
        "",
        "  (no args)                         run as an MCP server over stdio",
        "  verify --root <path> [--expect <sha256>]",
        "                                    recompute a scan input fingerprint",
        "",
        "Env: LOXE_TRUSTED_ROOTS, LOXE_DISABLE_TRUST, LOXE_MAPPING_OVERRIDES",
        "",
      ].join("\n"),
    );
    process.exit(0);
  }

  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    {
      instructions: [
        "LoxeAI compliance server. Scans Infrastructure-as-Code locally and maps findings to",
        "SOC 2 Trust Services Criteria.",
        "",
        "Workflow: scan_iac -> list_findings -> classify_blast_radius -> get_finding -> propose a",
        "diff for human approval -> rescan and compare the fingerprint. Read the",
        "loxe://workflow/remediation resource for the full loop and its guardrails.",
        "",
        "Every tool is read-only. This server never writes, edits, or moves a file; it returns",
        "findings and remediation text, and the host's approval UI is the write path.",
        "",
        "Scope: SOC 2 Security category, all 33 Common Criteria. An IaC scan is the primary",
        "evidence source for only 3 of them and partially informs 8; the other 22 need documents,",
        "people or live cloud state. There is no ISO 27001, HIPAA, PCI, NIST or GDPR mapping --",
        "do not claim coverage that does not exist.",
        "",
        "An IaC scan evidences INTENDED configuration, never deployed state. Never report a",
        "control as satisfied on the basis of a clean scan alone.",
      ].join("\n"),
    },
  );

  registerTools(server);
  registerResources(server);
  registerPrompts(server);

  // Probe scanners at startup purely so the diagnostic lands in the client's
  // stderr log. Never fatal: the user may install a scanner mid-session, and
  // `scanner_status` re-probes on demand.
  detectScanners()
    .then((found) => {
      if (found.length === 0) {
        console.error(
          `[${SERVER_NAME}] no IaC scanner found on PATH. Install checkov or trivy; ` +
            "scan_iac will return install instructions until then.",
        );
      } else {
        console.error(
          `[${SERVER_NAME}] scanners available: ${found.map((s) => `${s.name} (${s.version})`).join(", ")}`,
        );
      }
    })
    .catch((error: unknown) => {
      console.error(`[${SERVER_NAME}] scanner probe failed: ${String(error)}`);
    });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(`[${SERVER_NAME}] v${SERVER_VERSION} ready on stdio`);
}

// Diagnostics to stderr only. Writing these to stdout would corrupt the stream.
process.on("uncaughtException", (error) => {
  console.error(`[${SERVER_NAME}] uncaught exception: ${error.stack ?? error.message}`);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error(`[${SERVER_NAME}] unhandled rejection: ${String(reason)}`);
});

main().catch((error: unknown) => {
  console.error(`[${SERVER_NAME}] fatal: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
  process.exit(1);
});
