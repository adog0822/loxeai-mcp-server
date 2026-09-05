/**
 * The remediation guardrails.
 *
 * Lives here, not in the tool registry, because the workflow document below
 * renders from this same array. Previously the doc restated all six rules in
 * different words -- two sources of truth that could drift apart, in a package
 * whose entire premise is that its output matches reality.
 */
export const REMEDIATION_GUARDRAILS: string[] = [
  "Never weaken a security configuration. Do not disable encryption, remove access controls, open a security group to 0.0.0.0/0, or trade security for convenience.",
  "State cost implications. Any fix that enables a paid service (CloudTrail data events, GuardDuty, KMS, Config) must say so before it is applied.",
  "An IaC fix evidences INTENDED configuration only. It is not evidence of deployed state. Never report a SOC 2 control as satisfied because the Terraform looks correct.",
  "Check the mapping confidence before citing a control. A 'low' confidence mapping is an unverified keyword match.",
  "Prefer the smallest change that fixes the finding. Show only the properties that need to change, not whole resources.",
  "Never apply a fix without showing the diff for human approval first.",
];

/**
 * The scan -> fix -> rescan loop, exposed as an MCP resource.
 *
 * Kept as a TS module rather than a .md file so `tsc` ships it without a copy
 * step. Pattern borrowed from awslabs' deprecated terraform-mcp-server, which
 * exposed `terraform://development_workflow` as a resource and put the ordering
 * constraints there instead of scattering them across tool descriptions.
 */

export const REMEDIATION_WORKFLOW_MD = `# IaC Compliance Remediation Workflow

## The loop

\`\`\`
scan_iac(path)
   |
   v
list_findings(batchId)          <- page; do not try to load everything
   |
   v
classify_blast_radius(batchId)  <- collapse N findings into M action items
   |
   v
   for each action item, worst severity first:
       get_finding(batchId, findingId)
       |
       v
       propose a diff  --->  HUMAN APPROVES  --->  host writes the file
   |
   v
scan_iac(path) again
   |
   v
compare \`fingerprint\`:
   changed   -> the input really changed; compare counts to verify the fix
   unchanged -> nothing was actually written. Do not claim a fix was applied.
\`\`\`

## Ordering rules

1. Always \`scan_iac\` before proposing any fix. Never remediate from memory of a
   previous scan.
2. Always \`classify_blast_radius\` before working through findings individually.
   One account-wide fix can close hundreds of findings; fixing them
   resource-by-resource wastes effort and produces a needlessly large diff.
3. Work worst severity first, but treat \`UNKNOWN\` severity as significant.
   Checkov's open-source build often omits severity metadata; unknown is not low.
4. Always \`get_finding\` before writing a fix. The finding carries the control
   mapping, its confidence, and the blast-radius classification.
5. Always rescan after fixes and compare the fingerprint.

## Guardrails

${REMEDIATION_GUARDRAILS.map((rule, i) => `${i + 1}. ${rule}`).join("\n")}

These are rendered from the single definition above, not restated. If you are
changing them, change \`REMEDIATION_GUARDRAILS\` and both this document and the
\`remediate_finding\` prompt follow.


## The honesty rule

An IaC scan evidences **intended** configuration. It is not evidence of
**deployed** state.

Passing every check in a Terraform directory does not mean the SOC 2 control is
satisfied. The code may not be applied. Drift may exist. Resources may have been
created outside IaC entirely. Deployed-state evidence requires a runtime scan
against the live cloud account.

Never write "CC6.7 is satisfied" on the basis of a clean IaC scan. Write "the
declared configuration for these resources satisfies CC6.7; deployed-state
evidence is still required."

Several criteria cannot be evidenced by any IaC scan at all. CC7.3 (Security
Event Evaluation), CC7.4 (Incident Response), CC7.5 (Incident Recovery) and
CC9.2 (Vendor Risk) are process criteria -- they are evidenced by a human having
performed an activity, not by configuration.

Note CC7.2 (Anomaly Monitoring) is NOT in that list: a scan can partially inform
it, because alarm and log-destination resources are declarable in IaC. What a
scan cannot show is whether anything ever fired or whether a human looked.

Call \`controls\` for the per-criterion capability and its \`iacNote\`, which is
the authoritative statement of what a scan can and cannot show.
`;
