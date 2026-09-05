/**
 * The remediation guardrails.
 *
 * Lives here, not in the tool registry, because the workflow document below
 * renders from this same array. Previously the doc restated all six rules in
 * different words -- two sources of truth that could drift apart, in a package
 * whose entire premise is that its output matches reality.
 */
export declare const REMEDIATION_GUARDRAILS: string[];
/**
 * The scan -> fix -> rescan loop, exposed as an MCP resource.
 *
 * Kept as a TS module rather than a .md file so `tsc` ships it without a copy
 * step. Pattern borrowed from awslabs' deprecated terraform-mcp-server, which
 * exposed `terraform://development_workflow` as a resource and put the ordering
 * constraints there instead of scattering them across tool descriptions.
 */
export declare const REMEDIATION_WORKFLOW_MD: string;
