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
export {};
