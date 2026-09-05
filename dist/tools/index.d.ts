/**
 * Tool registry.
 *
 * Single-file registry, following Snyk's pattern of one declarative source of
 * truth for the tool surface (`internal/mcp/snyk_tools.json`). For a compliance
 * product this matters: the entire capability surface is auditable in one place
 * rather than scattered across modules.
 *
 * Every tool is READ-ONLY. This server never writes, edits, or moves a file.
 * Remediation is returned as text and diffs; the host's approval UI is the write
 * path and the human gate. That is the MCP spec's stated model -- "there SHOULD
 * always be a human in the loop with the ability to deny tool invocations".
 *
 * API NOTE: uses `registerTool`, not the deprecated `tool()`. Zod descriptions
 * use `.describe()`; `.description()` is not a method and throws.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export declare function registerTools(server: McpServer): void;
