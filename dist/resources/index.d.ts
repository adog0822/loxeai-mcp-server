/**
 * Resource registry.
 *
 * API NOTE: uses `registerResource`, not the deprecated `resource()`. The
 * `ResourceTemplate` constructor requires a `list` key even when undefined --
 * omitting it is a common error.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export declare function registerResources(server: McpServer): void;
