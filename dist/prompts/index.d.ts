/**
 * Prompt registry.
 *
 * These are this server's equivalent of Vanta's `getAgentRemediationPrompt` --
 * a tool/prompt that returns per-finding remediation intelligence rather than a
 * generic instruction. Vanta's own skill puts it bluntly:
 *
 *   "Always call getAgentRemediationPrompt before suggesting a fix. Never rely
 *    on general LLM knowledge for remediation."
 *
 * The difference: ours is computed locally, so nothing about the repository
 * leaves the machine.
 *
 * API NOTE: `registerPrompt` takes `argsSchema`, NOT `inputSchema`.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export declare function registerPrompts(server: McpServer): void;
