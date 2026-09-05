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
import * as z from "zod/v4";
import { iacAddressableControls, mapFindingToControl } from "../catalog/control-mappings.js";
import { groupRemediationItems } from "../catalog/remediation-meta.js";
import { IAC_EVIDENCE_CAPABILITY, SOC2_CONTROL_OPTIONS, SUPPORTED_CONTROL_IDS, coverageSummary, getControl, } from "../catalog/soc2-controls.js";
import { QUESTIONS, buildApplicabilityBrief } from "../applicability/questionnaire.js";
import { explainFinding } from "../explain/explain.js";
import { buildTrustPage, renderTrustPageHtml, renderTrustPageMarkdown } from "../trust/trust-page.js";
import { buildCapabilityReport } from "../capabilities/credentials.js";
import { REMEDIATION_GUARDRAILS } from "../workflow/remediation.js";
import { OSCAL_VERSION, buildOscalAssessmentResults } from "../oscal/assessment-results.js";
import { POLICY_CATALOG, draftPolicy } from "../policy/draft.js";
import { detectScanners } from "../scanner/detect.js";
import { performScan, ScannerUnavailableError, TrustError } from "../scanner/run.js";
import { CursorMismatchError, filterFindings, getBatch, listBatchIds, pageFindings, sortFindings } from "../scanner/store.js";
import { SEVERITY_RANK } from "../scanner/types.js";
import { safeErrorMessage, wrapUntrusted } from "../security/sanitize.js";
// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------
const severityEnum = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]);
const READ_ONLY = {
    readOnlyHint: true,
    destructiveHint: false,
};
/** Text + structured content, the shape the SDK validates against outputSchema. */
function ok(structured, text) {
    return {
        content: [{ type: "text", text: text ?? JSON.stringify(structured, null, 2) }],
        structuredContent: structured,
    };
}
function fail(message) {
    // isError:true skips outputSchema validation, so no structuredContent needed.
    return { content: [{ type: "text", text: message }], isError: true };
}
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
function severityPriority(severity) {
    return SEVERITY_RANK[severity];
}
// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
export function registerTools(server) {
    // -------------------------------------------------------------------------
    // scan_iac
    // -------------------------------------------------------------------------
    server.registerTool("scan_iac", {
        title: "Scan Infrastructure-as-Code for SOC 2 misconfigurations",
        description: [
            "Scans Infrastructure-as-Code for security misconfigurations and maps each finding",
            "to a SOC 2 Trust Services Criterion. Supports Terraform, CloudFormation, Kubernetes,",
            "Dockerfile, Helm, ARM and Bicep via a locally installed Checkov or Trivy.",
            "",
            "The scan runs entirely on this machine. File contents are never transmitted anywhere.",
            "",
            "Returns a SUMMARY AND A HANDOFF, not the findings themselves -- a real repository",
            "produces hundreds of findings. Call `list_findings` with the returned batchId to page",
            "through them, then `get_finding` for detail on a specific one.",
            "",
            "The `path` MUST be absolute. Run `pwd` in the target directory if you need it.",
            "",
            "Scope: SOC 2 Security category only. All 33 Common Criteria are catalogued, but an IaC",
            "scan is the primary evidence source for just 3 of them and partially informs 8 more --",
            "the remaining 22 are out of reach of any infrastructure scan and need documents, people,",
            "or live cloud state. This server does not support ISO 27001, HIPAA, PCI, NIST or GDPR.",
            "Do not claim coverage it does not have.",
        ].join("\n"),
        inputSchema: {
            path: z
                .string()
                .describe("Absolute path to the directory or file to scan. Must be absolute, not relative."),
            frameworks: z
                .array(z.enum([
                "terraform",
                "terraform_plan",
                "cloudformation",
                "kubernetes",
                "dockerfile",
                "helm",
                "arm",
                "bicep",
                "serverless",
                "github_actions",
            ]))
                .optional()
                .describe("Restrict the scan to these IaC frameworks. Omit to let the scanner auto-detect."),
            scanner: z
                .enum(["checkov", "trivy"])
                .optional()
                .describe("Force a specific scanner. Omit to prefer Checkov, which has richer control metadata."),
            configPath: z
                .string()
                .optional()
                .describe("Optional absolute path to a scanner config file (Checkov only)."),
        },
        outputSchema: {
            batchId: z.string().describe("Pass this to list_findings and get_finding."),
            fingerprint: z
                .string()
                .describe("SHA-256 over the scanned input. An identical fingerprint across two scans proves the input did not change."),
            scanner: z.string(),
            scannerVersion: z.string(),
            frameworksDetected: z.array(z.string()),
            scannedAt: z.string(),
            filesFingerprinted: z.number(),
            fingerprintTruncated: z
                .boolean()
                .describe("True when the fingerprint walk hit its file cap and covers only a subset of the tree."),
            findingsTruncated: z
                .boolean()
                .describe("True when the retained finding list was capped. A criterion with no findings may simply have had them dropped."),
            totalFindings: z.number().describe("Findings produced before any cap. `counts` reflects this, not the retained list."),
            counts: z.object({
                total: z.number(),
                bySeverity: z.record(z.string(), z.number()),
                byControl: z.record(z.string(), z.number()),
                unmapped: z.number().describe("Findings no rule could map to a control. Not hidden."),
            }),
            parseErrors: z
                .array(z.string())
                .describe("Files the scanner could not parse. A partial result, NOT a clean one."),
            suppressions: z
                .array(z.object({
                checkId: z.string(),
                checkName: z.string(),
                resource: z.string(),
                filePath: z.string(),
                reason: z.string(),
            }))
                .describe("Checks a developer explicitly suppressed in source. These do NOT appear as findings; a suppressed check is an accepted risk, not an absent one."),
            sanitization: z.object({
                modified: z.boolean(),
                invisibleCharsRemoved: z.number(),
                injectionPatternsNeutralized: z.number(),
            }),
            next: z.object({ tool: z.string(), args: z.record(z.string(), z.unknown()), why: z.string() }),
            caveat: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ path, frameworks, scanner, configPath }) => {
        try {
            const batch = await performScan({
                path,
                ...(frameworks ? { frameworks } : {}),
                ...(scanner ? { scanner } : {}),
                ...(configPath ? { configPath } : {}),
            });
            const structured = {
                batchId: batch.batchId,
                fingerprint: batch.fingerprint,
                scanner: batch.scanner,
                scannerVersion: batch.scannerVersion,
                frameworksDetected: batch.frameworks,
                scannedAt: batch.createdAt,
                filesFingerprinted: batch.fileCount,
                fingerprintTruncated: batch.fingerprintTruncated,
                findingsTruncated: batch.findingsTruncated,
                totalFindings: batch.totalFindings,
                counts: batch.counts,
                parseErrors: batch.parseErrors,
                suppressions: batch.suppressions,
                sanitization: batch.sanitization,
                next: {
                    tool: "list_findings",
                    args: { batchId: batch.batchId, minSeverity: "HIGH" },
                    why: "Findings are not included here. Page through them with list_findings.",
                },
                caveat: "An IaC scan evidences INTENDED configuration. It is not evidence of deployed state. " +
                    "Do not report a control as satisfied on the basis of this scan alone.",
            };
            const summaryLines = [
                `Scanned ${batch.root} with ${batch.scanner} (${batch.scannerVersion}).`,
                `Fingerprint: ${batch.fingerprint.slice(0, 16)}...`,
                `${batch.counts.total} findings.`,
                ...SEVERITY_ORDER.filter((s) => batch.counts.bySeverity[s] > 0).map((s) => `  ${s}: ${batch.counts.bySeverity[s]}`),
                batch.counts.unmapped > 0 ? `${batch.counts.unmapped} findings could not be mapped to a control.` : "",
                batch.parseErrors.length > 0
                    ? `WARNING: ${batch.parseErrors.length} file(s) failed to parse. This is a PARTIAL result, not a clean one.`
                    : "",
                batch.sanitization.modified
                    ? `NOTE: sanitization altered scanner output (${batch.sanitization.invisibleCharsRemoved} invisible chars removed, ${batch.sanitization.injectionPatternsNeutralized} injection patterns neutralized). The scanned files contain text that attempts to influence model behaviour.`
                    : "",
                "",
                `Next: list_findings({ batchId: "${batch.batchId}" })`,
            ].filter((line) => line.length > 0);
            return ok(structured, summaryLines.join("\n"));
        }
        catch (error) {
            if (error instanceof ScannerUnavailableError)
                return fail(error.message);
            if (error instanceof TrustError)
                return fail(error.message);
            return fail(`Scan failed: ${safeErrorMessage(error, "unknown scanner error")}\n\n` +
                "IMPORTANT: no results were produced. This is NOT a clean scan. Do not report this " +
                "infrastructure as compliant.");
        }
    });
    // -------------------------------------------------------------------------
    // list_findings
    // -------------------------------------------------------------------------
    server.registerTool("list_findings", {
        title: "List findings from a scan batch",
        description: [
            "Pages through findings from a previous `scan_iac` call. Returns lightweight rows;",
            "call `get_finding` for full detail on one.",
            "",
            "Findings with UNKNOWN severity are never filtered out by minSeverity. Checkov's",
            "open-source build often omits severity metadata, and dropping those findings would",
            "under-report real misconfigurations.",
        ].join("\n"),
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac."),
            minSeverity: severityEnum.optional().describe("Only findings at or above this severity (UNKNOWN always included)."),
            controlId: z
                .enum(SUPPORTED_CONTROL_IDS)
                .optional()
                .describe("Only findings mapped to this SOC 2 control."),
            unmappedOnly: z.boolean().optional().describe("Only findings no rule could map to a control."),
            limit: z.number().int().min(1).max(200).optional().describe("Max rows to return. Default 50."),
            cursor: z.string().optional().describe("Opaque cursor from a previous call's nextCursor."),
        },
        outputSchema: {
            batchId: z.string(),
            findings: z.array(z.object({
                id: z.string(),
                checkId: z.string(),
                checkName: z.string(),
                severity: z.string(),
                resource: z.string(),
                filePath: z.string(),
                controlId: z.string().nullable(),
                mappingConfidence: z.string(),
            })),
            total: z.number(),
            returned: z.number(),
            nextCursor: z.string().nullable(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId, minSeverity, controlId, unmappedOnly, limit, cursor }) => {
        const batch = getBatch(batchId);
        if (!batch) {
            // Always end on an action. Listing known batches without saying what to
            // do leaves the agent guessing.
            const known = listBatchIds();
            return fail(`Unknown batchId "${batchId}". ` +
                (known.length > 0
                    ? `Known batches in this session: ${known.join(", ")}. Retry with one of those, or call scan_iac to create a new batch.`
                    : "No scans have been run in this session. Call scan_iac first.") +
                " Batches are held in memory and do not survive a server restart.");
        }
        const activeFilter = {
            ...(minSeverity ? { minSeverity } : {}),
            ...(controlId ? { controlId } : {}),
            ...(unmappedOnly ? { unmappedOnly } : {}),
        };
        const filtered = filterFindings(batch.findings, activeFilter);
        let page;
        try {
            // The filter is passed so the cursor can be bound to it. Changing the
            // filter mid-paging is refused rather than silently skipping rows.
            page = pageFindings(sortFindings(filtered), limit ?? 50, cursor, activeFilter);
        }
        catch (error) {
            if (error instanceof CursorMismatchError)
                return fail(error.message);
            throw error;
        }
        const structured = { batchId, ...page };
        const rows = page.findings.map((f) => `${f.severity.padEnd(8)} ${(f.controlId ?? "UNMAPPED").padEnd(9)} ${f.checkId}  ${f.filePath}  ${f.resource}`);
        const text = wrapUntrusted([
            `${page.returned} of ${page.total} findings (batch ${batchId}).`,
            "",
            "SEVERITY CONTROL   CHECK  FILE  RESOURCE",
            ...rows,
            "",
            page.nextCursor ? `More available. nextCursor: ${page.nextCursor}` : "End of results.",
        ].join("\n"), "iac-scanner-findings");
        return ok(structured, text);
    });
    // -------------------------------------------------------------------------
    // get_finding
    // -------------------------------------------------------------------------
    server.registerTool("get_finding", {
        title: "Get full detail for one finding",
        description: "Returns a single finding with its SOC 2 control mapping (including how the mapping " +
            "was derived and how confident it is), blast-radius classification, and remediation guidance.",
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac."),
            findingId: z.string().describe("Finding ID from list_findings."),
        },
        outputSchema: {
            finding: z.object({
                id: z.string(),
                checkId: z.string(),
                checkName: z.string(),
                severity: z.string(),
                resource: z.string(),
                resourceType: z.string(),
                filePath: z.string(),
                lineRange: z.array(z.number()).nullable(),
                framework: z.string(),
                guideline: z.string().nullable(),
                scanner: z.string(),
            }),
            mapping: z.object({
                controlId: z.string().nullable(),
                controlTitle: z.string().nullable(),
                requirement: z.string().nullable(),
                mappingSource: z.string(),
                confidence: z.string(),
                rationale: z.string(),
                evidenceLimit: z.string().nullable(),
            }),
            blastRadius: z.object({
                scope: z.string(),
                actionVerb: z.string(),
                scopeLabel: z.string(),
                explanation: z.string(),
            }),
            remediationGuardrails: z.array(z.string()),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId, findingId }) => {
        const batch = getBatch(batchId);
        if (!batch)
            return fail(`Unknown batchId "${batchId}". Call scan_iac first.`);
        const finding = batch.findings.find((f) => f.id === findingId);
        if (!finding) {
            return fail(`No finding "${findingId}" in batch ${batchId}. Use list_findings to get valid finding IDs.`);
        }
        const { mapping, blastRadius, ...rest } = finding;
        const structured = {
            finding: {
                id: rest.id,
                checkId: rest.checkId,
                checkName: rest.checkName,
                severity: rest.severity,
                resource: rest.resource,
                resourceType: rest.resourceType,
                filePath: rest.filePath,
                lineRange: rest.lineRange,
                framework: rest.framework,
                guideline: rest.guideline,
                scanner: rest.scanner,
            },
            mapping,
            blastRadius,
            remediationGuardrails: REMEDIATION_GUARDRAILS,
        };
        return ok(structured, wrapUntrusted(JSON.stringify(structured, null, 2), "iac-scanner-finding"));
    });
    // -------------------------------------------------------------------------
    // map_iac_finding_to_control
    // -------------------------------------------------------------------------
    server.registerTool("map_iac_finding_to_control", {
        title: "Map an IaC check to a SOC 2 control",
        description: [
            "Maps a scanner check to a SOC 2 Trust Services Criterion without running a scan.",
            "Useful for checks surfaced by another tool, CI output, or a scanner this server does",
            "not wrap.",
            "",
            "Always returns `mappingSource` and `confidence`. A `low` confidence mapping is a",
            "keyword match that the resource type did not corroborate -- verify it before relying",
            "on it. `unmapped` means no rule matched; that is a real answer, not a failure.",
        ].join("\n"),
        inputSchema: {
            checkName: z
                .string()
                .describe("The scanner's check name or title, e.g. 'Ensure S3 bucket has encryption enabled'."),
            checkId: z.string().optional().describe("Scanner check ID, e.g. CKV_AWS_19 or AVD-AWS-0088."),
            resourceType: z
                .string()
                .optional()
                .describe("Resource type, e.g. aws_s3_bucket. Raises mapping confidence when it corroborates."),
        },
        outputSchema: {
            controlId: z.string().nullable(),
            controlTitle: z.string().nullable(),
            requirement: z.string().nullable(),
            mappingSource: z.string(),
            confidence: z.string(),
            rationale: z.string(),
            evidenceLimit: z.string().nullable(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ checkName, checkId, resourceType }) => {
        const mapping = mapFindingToControl({
            checkName,
            checkId: checkId ?? null,
            resourceType: resourceType ?? null,
        });
        return ok({ ...mapping });
    });
    // -------------------------------------------------------------------------
    // controls  (bare plural = consolidated get-or-list, per Vanta's convention)
    // -------------------------------------------------------------------------
    server.registerTool("controls", {
        title: "SOC 2 control catalog",
        description: [
            "Returns the SOC 2 control catalog this server evaluates against. Pass `controlId` for",
            "one control; omit it for all.",
            "",
            "Scope is the SOC 2 Security category, which is all 33 Common Criteria (CC1.1-CC9.2).",
            "The optional A / C / PI / P categories are NOT covered.",
            "",
            "An IaC scan is the primary evidence source for only 3 of the 33 and partially informs 8;",
            "the remaining 22 need documents, people or live cloud state. Each control reports what a",
            "scan can and cannot evidence for it via its `iac` capability and `iacNote`.",
        ].join("\n"),
        inputSchema: {
            controlId: z
                .enum(SUPPORTED_CONTROL_IDS)
                .optional()
                .describe("A single control to return. Omit for the full catalog."),
        },
        outputSchema: {
            controls: z.array(z.object({
                id: z.string(),
                title: z.string(),
                description: z.string(),
                iacEvidenceCapability: z.string(),
                iacEvidenceNote: z.string(),
            })),
            supportedControlIds: z.array(z.string()),
            frameworkScope: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ controlId }) => {
        const source = controlId ? [getControl(controlId)].filter((c) => c !== undefined) : SOC2_CONTROL_OPTIONS;
        if (controlId && source.length === 0) {
            return fail(`Unknown control "${controlId}". Supported: ${SUPPORTED_CONTROL_IDS.join(", ")}`);
        }
        const controls = source.map((control) => {
            const capability = IAC_EVIDENCE_CAPABILITY[control.id];
            return {
                id: control.id,
                title: control.title,
                description: control.description,
                iacEvidenceCapability: capability?.capability ?? "none",
                iacEvidenceNote: capability?.note ?? "No IaC evidence capability recorded for this control.",
            };
        });
        return ok({
            controls,
            supportedControlIds: SUPPORTED_CONTROL_IDS,
            frameworkScope: "SOC 2 Trust Services Criteria, Security category — all 33 Common Criteria. An IaC scan is the primary evidence source for only 3 of them and partially informs 8; the remaining 22 need documents, people or live cloud state.",
        });
    });
    // -------------------------------------------------------------------------
    // classify_blast_radius
    // -------------------------------------------------------------------------
    server.registerTool("classify_blast_radius", {
        title: "Group findings into action items by blast radius",
        description: [
            "Collapses a list of findings into deduplicated action items and classifies each by",
            "how widely the fix applies: account-wide (fix once), per-region (rollout),",
            "per-resource (each resource), or per-person (human coordination).",
            "",
            "This is what turns '400 findings' into '9 action items across 400 resources'. Pass a",
            "batchId to classify a whole scan, or pass findings inline to classify results from",
            "elsewhere.",
            "",
            "Pure and offline: no scan, no network.",
        ].join("\n"),
        inputSchema: {
            batchId: z.string().optional().describe("Classify every finding in this batch."),
            findings: z
                .array(z.object({
                controlId: z.string().describe("SOC 2 control ID, or any label if unmapped."),
                title: z.string().describe("Finding title or check name."),
                severity: severityEnum.optional(),
            }))
                .optional()
                .describe("Classify these findings instead of a batch. Ignored when batchId is given."),
        },
        outputSchema: {
            groups: z.array(z.object({
                controlId: z.string(),
                title: z.string(),
                severity: z.string(),
                count: z.number(),
                scope: z.string(),
                actionVerb: z.string(),
                scopeLabel: z.string(),
                explanation: z.string(),
            })),
            totalFindings: z.number(),
            totalActionItems: z.number(),
            byScope: z.record(z.string(), z.number()),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId, findings }) => {
        let items;
        if (batchId) {
            const batch = getBatch(batchId);
            if (!batch)
                return fail(`Unknown batchId "${batchId}". Call scan_iac first.`);
            items = batch.findings.map((f) => ({
                controlId: f.mapping.controlId ?? "UNMAPPED",
                title: f.checkName,
                severity: f.severity,
                priority: severityPriority(f.severity),
            }));
        }
        else if (findings && findings.length > 0) {
            items = findings.map((f) => ({
                controlId: f.controlId,
                title: f.title,
                severity: f.severity ?? "UNKNOWN",
                priority: severityPriority((f.severity ?? "UNKNOWN")),
            }));
        }
        else {
            return fail("Supply either a batchId or a non-empty findings array.");
        }
        const groups = groupRemediationItems(items);
        const byScope = {};
        for (const group of groups) {
            byScope[group.meta.scope] = (byScope[group.meta.scope] ?? 0) + 1;
        }
        const structured = {
            groups: groups.map((group) => ({
                controlId: group.controlId,
                title: group.title,
                severity: group.severity,
                count: group.items.length,
                scope: group.meta.scope,
                actionVerb: group.meta.actionVerb,
                scopeLabel: group.meta.scopeLabel,
                explanation: group.meta.explanation,
            })),
            totalFindings: items.length,
            totalActionItems: groups.length,
            byScope,
        };
        const text = [
            `${items.length} findings collapse into ${groups.length} action items.`,
            "",
            ...structured.groups.map((g) => `[${g.severity}] ${g.scopeLabel} - ${g.actionVerb}: ${g.title} (${g.count} affected, ${g.controlId})`),
        ].join("\n");
        return ok(structured, text);
    });
    // -------------------------------------------------------------------------
    // scanner_status
    // -------------------------------------------------------------------------
    server.registerTool("scanner_status", {
        title: "Check scanner availability and server scope",
        description: "Reports which IaC scanners are installed, which control framework is supported, and " +
            "which trusted roots this server will scan. Call this first when a scan fails.",
        inputSchema: {},
        outputSchema: {
            scanners: z.array(z.object({ name: z.string(), version: z.string() })),
            anyAvailable: z.boolean(),
            frameworkScope: z.string(),
            criteriaCatalogued: z.number(),
            supportedControlIds: z.array(z.string()),
            iacAddressableControlIds: z.array(z.string()),
            coverage: z.object({
                iacPrimary: z.number(),
                iacPartial: z.number(),
                iacNone: z.number(),
                notAutomatable: z.number(),
            }),
            trustedRoots: z.array(z.string()),
            networkEgress: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async () => {
        const scanners = await detectScanners(true);
        const roots = (process.env["LOXE_TRUSTED_ROOTS"] ?? process.cwd()).split(":");
        const cov = coverageSummary();
        return ok({
            scanners: scanners.map((s) => ({ name: s.name, version: s.version })),
            anyAvailable: scanners.length > 0,
            frameworkScope: `SOC 2 Trust Services Criteria, Security category only — all ${cov.total} Common Criteria are catalogued. ` +
                `An IaC scan is the primary evidence source for ${cov.iac.primary} of them and partially informs ` +
                `${cov.iac.partial}; the remaining ${cov.iac.none} are out of reach of any infrastructure scan. ` +
                `Separately, ${cov.notAutomatable} of the ${cov.total} have a document or a human activity as their primary evidence source. ` +
                `The optional Availability, Confidentiality, Processing Integrity and Privacy categories are NOT covered.`,
            criteriaCatalogued: cov.total,
            supportedControlIds: SUPPORTED_CONTROL_IDS,
            iacAddressableControlIds: iacAddressableControls().map((c) => c.id),
            coverage: {
                iacPrimary: cov.iac.primary,
                iacPartial: cov.iac.partial,
                iacNone: cov.iac.none,
                notAutomatable: cov.notAutomatable,
            },
            trustedRoots: roots,
            networkEgress: "This server itself makes no outbound network requests. It does spawn subprocesses that can: " +
                "Checkov and Trivy are invoked with --skip-download / --skip-check-update to suppress their " +
                "policy and metadata fetches, and check_capabilities runs `aws sts get-caller-identity` and " +
                "`gh auth status`, which contact AWS STS and api.github.com by definition. Everything else is local.",
        });
    });
    // -------------------------------------------------------------------------
    // applicability_brief
    // -------------------------------------------------------------------------
    server.registerTool("applicability_brief", {
        title: "Scope SOC 2 to your company from eight questions",
        description: "Answer eight questions about how your company is set up and get back, for each of the 33 SOC 2 " +
            "Common Criteria, what satisfying it actually looks like for a company shaped like yours and which " +
            "ones to deal with first. Fully local and deterministic; no account, no network call, no model. " +
            "Call `applicability_questions` first to get the question list. " +
            "IMPORTANT: this does not remove criteria from scope — all 33 apply to essentially every SOC 2 " +
            "Security engagement. It tells you what each one means for you and what to prioritise.",
        inputSchema: {
            workforce: z.enum(["employees", "contractors-only", "both"]).describe("Who does the work"),
            premises: z
                .enum(["fully-remote", "office", "own-hardware"])
                .describe("Physical premises or company-owned hardware"),
            customerData: z
                .enum(["none", "business-data", "personal-data", "regulated-data"])
                .describe("What kind of customer data is handled"),
            cloud: z
                .enum(["single-cloud", "multi-cloud", "on-prem", "no-infrastructure"])
                .describe("Where infrastructure runs"),
            iacCoverage: z
                .enum(["all", "partial", "none"])
                .describe("How much infrastructure is defined as code"),
            productionAccess: z
                .enum(["solo", "small-team", "larger-team"])
                .describe("How many people can change production"),
            changeProcess: z
                .enum(["pr-required", "pr-usually", "direct-push"])
                .describe("Whether every production change goes through a reviewed pull request"),
            timeline: z
                .enum(["exploring", "type1-soon", "type2-window-open", "in-audit"])
                .describe("Where the company is in the SOC 2 process"),
        },
        outputSchema: {
            answers: z.object({
                workforce: z.string(),
                premises: z.string(),
                customerData: z.string(),
                cloud: z.string(),
                iacCoverage: z.string(),
                productionAccess: z.string(),
                changeProcess: z.string(),
                timeline: z.string(),
            }),
            summary: z.object({
                total: z.number().describe("Always 33. All Common Criteria remain in scope."),
                applies: z.number(),
                inheritedViaCarveOut: z.number().describe("In scope, satisfied by citing the cloud provider's report."),
                elevatedRisk: z.number(),
                thisToolCanHelpWith: z.number(),
            }),
            controls: z.array(z.object({
                id: z.string(),
                title: z.string(),
                group: z.string(),
                applicability: z.enum(["applies", "inherited-via-carve-out", "applies-elevated-risk"]),
                rationale: z.string(),
                whatYouNeed: z.string(),
                thisToolHelps: z.enum(["primary", "partial", "no"]),
                priority: z.number().describe("0-100, deterministic from the answers. Not a score of your posture."),
            })),
            startHere: z.array(z.object({ id: z.string(), title: z.string(), why: z.string() })),
            scopeNotes: z.array(z.string()),
            caveats: z.array(z.string()),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async (args) => {
        const brief = buildApplicabilityBrief(args);
        const text = [
            `Scoped ${brief.summary.total} SOC 2 Common Criteria to your answers.`,
            "",
            `  ${brief.summary.applies} apply normally`,
            `  ${brief.summary.elevatedRisk} apply and look harder than baseline for you`,
            `  ${brief.summary.inheritedViaCarveOut} addressed by inheriting your cloud provider's report (still in scope; satisfied by inheritance, not omission)`,
            `  ${brief.summary.thisToolCanHelpWith} this tool can help with at all`,
            "",
            "START HERE:",
            ...brief.startHere.map((s) => `  ${s.id} ${s.title}\n    ${s.why}`),
            ...(brief.scopeNotes.length > 0 ? ["", "SCOPE NOTES:", ...brief.scopeNotes.map((n) => `  - ${n}`)] : []),
            "",
            "CAVEATS:",
            ...brief.caveats.map((c) => `  - ${c}`),
        ].join("\n");
        return ok(brief, text);
    });
    // -------------------------------------------------------------------------
    // applicability_questions
    // -------------------------------------------------------------------------
    server.registerTool("applicability_questions", {
        title: "Get the eight scoping questions",
        description: "Returns the eight questions used by `applicability_brief`, with the allowed values for each and " +
            "why each question is asked. Ask the user these conversationally, then call `applicability_brief`.",
        inputSchema: {},
        outputSchema: {
            questions: z.array(z.object({
                id: z.string(),
                question: z.string(),
                why: z.string().describe("Why this question is asked and what it changes."),
                options: z.array(z.object({ value: z.string(), label: z.string() })),
            })),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async () => ok({ questions: QUESTIONS }));
    // -------------------------------------------------------------------------
    // explain_finding
    // -------------------------------------------------------------------------
    server.registerTool("explain_finding", {
        title: "Explain a finding in plain English",
        description: "Takes a finding from a scan and explains it without jargon: what it actually means, the real-world " +
            "risk of ignoring it, why an auditor would care, what to change, and roughly what shape of work the " +
            "fix is. Everything returned is derived from the finding itself — severity, control mapping and its " +
            "confidence, blast radius — so it never invents a risk claim. Where the data is missing or the " +
            "mapping is weak, it says so.",
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac"),
            findingId: z.string().describe("Finding ID from list_findings or get_finding"),
        },
        outputSchema: {
            findingId: z.string(),
            headline: z.string(),
            whatThisMeans: z.string(),
            realWorldRisk: z.string().describe("Hedged when the scanner assigned no severity."),
            whyAnAuditorWouldCare: z.string(),
            whatToFix: z.string(),
            effort: z.object({
                shape: z.enum(["one-change", "per-region", "per-resource", "per-person", "unknown"]),
                description: z.string(),
                affectedInThisScan: z.number(),
            }),
            strengths: z.array(z.string()),
            weaknesses: z.array(z.string()),
            caveats: z.array(z.string()).describe("Populated when the explanation rests on a weak mapping."),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId, findingId }) => {
        const batch = getBatch(batchId);
        if (!batch) {
            return fail(`No scan batch "${batchId}". Batches are held in memory for this server process only. ` +
                `Available: ${listBatchIds().join(", ") || "none"}. Run scan_iac again.`);
        }
        const finding = batch.findings.find((f) => f.id === findingId);
        if (!finding) {
            return fail(`No finding "${findingId}" in batch "${batchId}". Use list_findings to see valid IDs.`);
        }
        // How many findings in this batch share the same fix?
        const affected = batch.findings.filter((f) => f.checkId === finding.checkId).length;
        const explanation = explainFinding(finding, affected);
        const text = wrapUntrusted([
            explanation.headline,
            "",
            `WHAT THIS MEANS`,
            explanation.whatThisMeans,
            "",
            `REAL-WORLD RISK`,
            explanation.realWorldRisk,
            "",
            `WHY AN AUDITOR WOULD CARE`,
            explanation.whyAnAuditorWouldCare,
            "",
            `WHAT TO FIX`,
            explanation.whatToFix,
            "",
            `EFFORT: ${explanation.effort.description} (${explanation.effort.affectedInThisScan} finding(s) in this scan share this fix)`,
            ...(explanation.strengths.length > 0
                ? ["", "STRENGTHS", ...explanation.strengths.map((s) => `  + ${s}`)]
                : []),
            ...(explanation.weaknesses.length > 0
                ? ["", "WEAKNESSES", ...explanation.weaknesses.map((w) => `  - ${w}`)]
                : []),
            ...(explanation.caveats.length > 0 ? ["", "CAVEATS", ...explanation.caveats.map((c) => `  ! ${c}`)] : []),
        ].join("\n"), "iac-scan-finding");
        return ok(explanation, text);
    });
    // -------------------------------------------------------------------------
    // preview_trust_page
    // -------------------------------------------------------------------------
    server.registerTool("preview_trust_page", {
        title: "Preview what a trust page would say right now",
        description: "Builds a per-criterion evidence summary from a scan, suitable for showing a prospect's security " +
            "team. Every row traces to the file, line, rule ID, mapping confidence and timestamp behind it, and " +
            "the document carries a fingerprint the viewer can recompute. " +
            "This returns DATA ONLY — nothing is published and no file is written. " +
            "It never emits a compliance badge or the words 'compliant' or 'certified': SOC 2 is an attestation " +
            "that only a licensed CPA firm can issue, and this is an automated scan.",
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac"),
        },
        outputSchema: {
            documentTitle: z.string().describe("Deliberately not an audit/attestation title. Reserved terms."),
            statusLine: z.string().describe("Prefixed INCOMPLETE SCAN when coverage cannot support a clean result."),
            generatedAt: z.string(),
            scan: z.object({
                batchId: z.string(),
                fingerprint: z.string().describe("SHA-256 over scanned input. Identical fingerprint = identical input."),
                scanner: z.string(),
                scannerVersion: z.string(),
                fileCount: z.number(),
                fingerprintTruncated: z.boolean(),
                recomputeCommand: z.string(),
                parseErrors: z.array(z.string()),
                suppressions: z.array(z.object({
                    checkId: z.string(),
                    checkName: z.string(),
                    resource: z.string(),
                    filePath: z.string(),
                    reason: z.string(),
                })),
                findingsTruncated: z.boolean(),
                totalFindings: z.number(),
                coverageUsable: z.boolean().describe("False when parse errors, suppressions or truncation block a clean claim."),
            }),
            scope: z.object({
                framework: z.string(),
                criteriaTotal: z.number(),
                iacPrimary: z.number(),
                iacPartial: z.number(),
                notAutomatable: z.number(),
            }),
            summary: z.object({
                noExceptionsFound: z.number(),
                exceptionsFound: z.number(),
                notEvidenceableByScan: z.number(),
                notCoveredByThisScan: z.number(),
                totalOpenFindings: z.number(),
            }),
            controls: z.array(z.object({
                id: z.string(),
                title: z.string(),
                group: z.string(),
                status: z.enum([
                    "no-exceptions-found",
                    "exceptions-found",
                    "not-evidenceable-by-scan",
                    "not-covered-by-this-scan",
                ]),
                statusReason: z.string(),
                evidenceSource: z.string(),
                openFindings: z.number(),
                traces: z.array(z.object({
                    findingId: z.string(),
                    checkId: z.string(),
                    filePath: z.string(),
                    line: z.number().nullable(),
                    severity: z.string(),
                    mappingSource: z.string(),
                    mappingConfidence: z.string(),
                })),
            })),
            notCovered: z.array(z.string()),
            disclaimers: z.array(z.string()),
            documentFingerprint: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId }) => {
        const batch = getBatch(batchId);
        if (!batch) {
            return fail(`No scan batch "${batchId}". Available: ${listBatchIds().join(", ") || "none"}. Run scan_iac first.`);
        }
        const page = buildTrustPage(batch);
        const text = [
            page.documentTitle,
            "",
            page.statusLine,
            "",
            `  ${page.summary.noExceptionsFound} criteria - no exceptions found`,
            `  ${page.summary.exceptionsFound} criteria - exceptions found (${page.summary.totalOpenFindings} findings)`,
            `  ${page.summary.notEvidenceableByScan} criteria - not evidenceable by any infrastructure scan`,
            "",
            "NOT COVERED:",
            ...page.notCovered.map((n) => `  - ${n}`),
            "",
            `Input fingerprint:    ${page.scan.fingerprint}`,
            `Document fingerprint: ${page.documentFingerprint}`,
            `Recompute:            ${page.scan.recomputeCommand}`,
        ].join("\n");
        return ok(page, text);
    });
    // -------------------------------------------------------------------------
    // render_trust_page
    // -------------------------------------------------------------------------
    server.registerTool("render_trust_page", {
        title: "Render the trust page as a self-contained file",
        description: "Returns the trust page as a complete HTML or Markdown document, as a STRING. This server never " +
            "writes files — save it yourself, or ask your agent to write it so the diff goes through your normal " +
            "approval step. The HTML is fully self-contained: no CDN, no webfont, no analytics, no script, no " +
            "external request of any kind, because a trust page that phones home would be flagged in exactly the " +
            "security review it exists to serve.",
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac"),
            format: z.enum(["html", "markdown"]).default("html").describe("Output format"),
        },
        outputSchema: {
            format: z.enum(["html", "markdown"]),
            documentFingerprint: z.string(),
            suggestedFilename: z.string(),
            bytes: z.number().describe("Size of the document, which is returned in `content`, not here."),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId, format }) => {
        const batch = getBatch(batchId);
        if (!batch) {
            return fail(`No scan batch "${batchId}". Available: ${listBatchIds().join(", ") || "none"}. Run scan_iac first.`);
        }
        const page = buildTrustPage(batch);
        const body = format === "markdown" ? renderTrustPageMarkdown(page) : renderTrustPageHtml(page);
        return {
            content: [{ type: "text", text: body }],
            structuredContent: {
                format,
                documentFingerprint: page.documentFingerprint,
                suggestedFilename: format === "markdown" ? "trust-page.md" : "trust-page.html",
                bytes: Buffer.byteLength(body, "utf8"),
            },
        };
    });
    // -------------------------------------------------------------------------
    // check_capabilities
    // -------------------------------------------------------------------------
    server.registerTool("check_capabilities", {
        title: "Report what this server can and cannot do with your credentials",
        description: "Reports which cloud/VCS CLIs are authenticated on this machine and whether those credentials are " +
            "WRITE-CAPABLE. This matters because 'read-only' is two separate claims: that this server performs no " +
            "write operations (true, and verifiable by code inspection), and that the credential itself cannot " +
            "write (a property of the token, which this server does not control when it inherits your ambient CLI " +
            "session). Use this before telling anyone the integration is read-only. " +
            "Never reads, stores, or transmits a token value — it asks each CLI what it is already logged in as.",
        inputSchema: {},
        outputSchema: {
            serverGuarantee: z.string(),
            credentials: z.array(z.object({
                tool: z.string(),
                installed: z.boolean(),
                authenticated: z.boolean(),
                identity: z.string().nullable().describe("Non-secret identity. Never a token value."),
                scopes: z.array(z.string()),
                writeCapability: z.enum(["read-only", "write-capable", "unknown"]),
                writeCapableVia: z.array(z.string()),
                assessment: z.string(),
                narrowerAlternative: z.string().nullable(),
            })),
            summary: z.object({
                anyWriteCapable: z.boolean(),
                anyUnknown: z.boolean(),
                headline: z.string(),
            }),
            caveats: z.array(z.string()),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async () => {
        const report = await buildCapabilityReport();
        const lines = [report.summary.headline, "", report.serverGuarantee, ""];
        for (const c of report.credentials) {
            if (!c.installed)
                continue;
            lines.push(`${c.tool}`);
            lines.push(`  authenticated: ${c.authenticated}${c.identity ? ` (${c.identity})` : ""}`);
            if (c.scopes.length > 0)
                lines.push(`  scopes: ${c.scopes.join(", ")}`);
            lines.push(`  write capability: ${c.writeCapability}`);
            lines.push(`  ${c.assessment}`);
            if (c.narrowerAlternative)
                lines.push(`  NARROWER OPTION: ${c.narrowerAlternative}`);
            lines.push("");
        }
        lines.push("CAVEATS:");
        for (const c of report.caveats)
            lines.push(`  - ${c}`);
        return ok(report, lines.join("\n"));
    });
    // -------------------------------------------------------------------------
    // export_oscal
    // -------------------------------------------------------------------------
    server.registerTool("export_oscal", {
        title: "Export scan results as NIST OSCAL assessment-results",
        description: "Emits the scan as a NIST OSCAL assessment-results document (JSON), the machine-readable format used " +
            "by GRC platforms and assessment tooling. Returned as a STRING; this server writes no files. " +
            "Two deliberate limitations are stated inside the document itself: no official OSCAL catalog for " +
            "SOC 2 exists, so criterion IDs are used descriptively; and only 'not-satisfied' findings are ever " +
            "emitted \u2014 this tool never asserts 'satisfied', because the absence of a scanner finding is not " +
            "evidence that a criterion is met.",
        inputSchema: {
            batchId: z.string().describe("Batch ID returned by scan_iac"),
        },
        outputSchema: {
            oscalVersion: z.string(),
            suggestedFilename: z.string(),
            bytes: z.number().describe("Size of the OSCAL JSON, which is returned in `content`, not here."),
            findingsEmitted: z.number().describe("Only ever not-satisfied findings. 'satisfied' is never emitted."),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async ({ batchId }) => {
        const batch = getBatch(batchId);
        if (!batch) {
            return fail(`No scan batch "${batchId}". Available: ${listBatchIds().join(", ") || "none"}. Run scan_iac first.`);
        }
        const doc = buildOscalAssessmentResults(batch);
        const json = JSON.stringify(doc, null, 2);
        const results = doc["assessment-results"]["results"];
        const emitted = results[0]?.["findings"]?.length ?? 0;
        return {
            content: [{ type: "text", text: json }],
            structuredContent: {
                oscalVersion: OSCAL_VERSION,
                suggestedFilename: `oscal-assessment-results-${batch.fingerprint.slice(0, 12)}.json`,
                bytes: Buffer.byteLength(json, "utf8"),
                findingsEmitted: emitted,
            },
        };
    });
    // -------------------------------------------------------------------------
    // draft_policy
    // -------------------------------------------------------------------------
    server.registerTool("draft_policy", {
        title: "Draft a SOC 2 policy grounded in your actual setup",
        description: "Produces a policy DRAFT in Markdown, grounded in the answers you gave to applicability_brief and, " +
            "optionally, a real scan. Returned as a string; this server writes no files. " +
            "Every judgment call is left as an explicit {{PLACEHOLDER}}, counted and returned separately rather " +
            "than silently filled with a plausible default — because a policy describing controls you do not " +
            "actually operate is worse than no policy, and becomes an audit exception. " +
            "The draft states in its own header that having the document does not satisfy the criteria it " +
            "supports; SOC 2 also wants evidence it was approved, communicated, acknowledged and followed.",
        inputSchema: {
            kind: z
                .enum([
                "information-security",
                "access-control",
                "change-management",
                "incident-response",
                "risk-assessment",
                "vendor-management",
                "business-continuity",
                "data-classification",
            ])
                .describe("Which policy to draft"),
            companyName: z.string().optional().describe("Company name. Omitted leaves a placeholder."),
            batchId: z.string().optional().describe("Optional scan batch to ground the draft in"),
            workforce: z.enum(["employees", "contractors-only", "both"]).optional(),
            premises: z.enum(["fully-remote", "office", "own-hardware"]).optional(),
            customerData: z.enum(["none", "business-data", "personal-data", "regulated-data"]).optional(),
            cloud: z.enum(["single-cloud", "multi-cloud", "on-prem", "no-infrastructure"]).optional(),
            iacCoverage: z.enum(["all", "partial", "none"]).optional(),
            productionAccess: z.enum(["solo", "small-team", "larger-team"]).optional(),
            changeProcess: z.enum(["pr-required", "pr-usually", "direct-push"]).optional(),
            timeline: z.enum(["exploring", "type1-soon", "type2-window-open", "in-audit"]).optional(),
        },
        outputSchema: {
            kind: z.string(),
            title: z.string(),
            supportsCriteria: z
                .array(z.object({ id: z.string(), title: z.string() }))
                .describe("Criteria this CONTRIBUTES toward. A policy never satisfies one on its own."),
            alsoRequires: z.array(z.string()).describe("What else you must produce beyond the document."),
            placeholders: z.array(z.string()).describe("Every {{PLACEHOLDER}} a human must resolve before use."),
            placeholderCount: z.number(),
            groundedIn: z.array(z.string()).describe("Facts from your answers and scan that shaped this draft."),
            warnings: z.array(z.string()).describe("Set when the draft would describe a control you do not operate."),
            suggestedFilename: z.string(),
            markdown: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async (args) => {
        const { kind, companyName, batchId, ...rest } = args;
        const batch = batchId ? getBatch(batchId) : undefined;
        if (batchId && !batch) {
            return fail(`No scan batch "${batchId}". Available: ${listBatchIds().join(", ") || "none"}.`);
        }
        const answered = Object.values(rest).filter(Boolean).length > 0;
        const draft = draftPolicy({
            kind,
            ...(companyName ? { companyName } : {}),
            ...(answered ? { answers: rest } : {}),
            ...(batch ? { batch } : {}),
        });
        const notice = [
            `${draft.title} — DRAFT`,
            "",
            `${draft.placeholders.length} placeholder(s) require a human decision before this is usable:`,
            ...draft.placeholders.slice(0, 12).map((p) => `  {{${p}}}`),
            ...(draft.placeholders.length > 12 ? [`  ...and ${draft.placeholders.length - 12} more`] : []),
            "",
            ...(draft.warnings.length > 0 ? ["WARNINGS:", ...draft.warnings.map((w) => `  ! ${w}`), ""] : []),
            ...(draft.groundedIn.length > 0 ? ["Grounded in:", ...draft.groundedIn.map((g) => `  - ${g}`), ""] : []),
            "--- DRAFT BEGINS ---",
            "",
            draft.markdown,
        ].join("\n");
        return {
            content: [{ type: "text", text: notice }],
            structuredContent: {
                kind: draft.kind,
                title: draft.title,
                supportsCriteria: draft.supportsCriteria,
                alsoRequires: draft.alsoRequires,
                placeholders: draft.placeholders,
                placeholderCount: draft.placeholders.length,
                groundedIn: draft.groundedIn,
                warnings: draft.warnings,
                suggestedFilename: `${draft.kind}-policy.md`,
                markdown: draft.markdown,
            },
        };
    });
    // -------------------------------------------------------------------------
    // list_policies
    // -------------------------------------------------------------------------
    server.registerTool("list_policies", {
        title: "List draftable policies and what each supports",
        description: "Returns the policies this server can draft, the SOC 2 criteria each contributes toward, and what " +
            "else you must produce beyond the document itself for those criteria to actually be addressed.",
        inputSchema: {},
        outputSchema: {
            policies: z.array(z.object({
                kind: z.string(),
                title: z.string(),
                supportsCriteria: z.array(z.string()),
                alsoRequires: z.array(z.string()),
            })),
            note: z.string(),
        },
        annotations: { ...READ_ONLY, idempotentHint: true, openWorldHint: false },
    }, async () => ok({
        policies: Object.values(POLICY_CATALOG).map((p) => ({
            kind: p.kind,
            title: p.title,
            supportsCriteria: p.supportsCriteria,
            alsoRequires: p.alsoRequires,
        })),
        note: "A policy document contributes toward a criterion; it never satisfies one on its own. SOC 2 wants evidence the policy was approved, communicated, acknowledged and followed.",
    }));
}
//# sourceMappingURL=index.js.map