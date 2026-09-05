/**
 * Resource registry.
 *
 * API NOTE: uses `registerResource`, not the deprecated `resource()`. The
 * `ResourceTemplate` constructor requires a `list` key even when undefined --
 * omitting it is a common error.
 */
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { mapFindingToControl } from "../catalog/control-mappings.js";
import { IAC_EVIDENCE_CAPABILITY, SOC2_CONTROL_OPTIONS, SUPPORTED_CONTROL_IDS, getControl, } from "../catalog/soc2-controls.js";
import { getBatch, listBatchIds } from "../scanner/store.js";
import { REMEDIATION_WORKFLOW_MD } from "../workflow/remediation.js";
function json(uri, value) {
    return {
        contents: [{ uri, mimeType: "application/json", text: JSON.stringify(value, null, 2) }],
    };
}
export function registerResources(server) {
    // -------------------------------------------------------------------------
    // Full control catalog
    // -------------------------------------------------------------------------
    server.registerResource("soc2-controls", "loxe://controls/soc2", {
        title: "SOC 2 control catalog",
        description: "All 33 SOC 2 Common Criteria (Security category) this server catalogues, " +
            "each annotated with what an IaC scan can and cannot evidence.",
        mimeType: "application/json",
    }, async (uri) => json(uri.href, {
        frameworkScope: "SOC 2 Trust Services Criteria, Security category only",
        controlCount: SOC2_CONTROL_OPTIONS.length,
        notCovered: "The optional Availability (A1.x), Confidentiality (C1.x), Processing Integrity (PI1.x) " +
            "and Privacy (P1-P8) categories are not covered; this is the Security category only. " +
            "Within it, all 33 Common Criteria are catalogued -- but an IaC scan is the primary " +
            "evidence source for only 3 (CC6.1, CC6.6, CC6.7) and partially informs 8. The other 22 " +
            "are catalogued so you can see the whole framework, NOT because a scan can evidence them; " +
            "check each control's `iac` capability and `iacNote`.",
        controls: SOC2_CONTROL_OPTIONS.map((control) => ({
            ...control,
            iacEvidence: IAC_EVIDENCE_CAPABILITY[control.id] ?? null,
        })),
    }));
    // -------------------------------------------------------------------------
    // Single control, templated with completion
    // -------------------------------------------------------------------------
    server.registerResource("soc2-control", new ResourceTemplate("loxe://controls/soc2/{controlId}", {
        list: undefined, // required key, even as undefined
        complete: {
            controlId: (value) => SUPPORTED_CONTROL_IDS.filter((id) => id.toLowerCase().startsWith(value.toLowerCase())),
        },
    }), {
        title: "SOC 2 control detail",
        description: "One SOC 2 criterion with its IaC evidence capability.",
        mimeType: "application/json",
    }, async (uri, variables) => {
        const raw = variables["controlId"];
        const controlId = Array.isArray(raw) ? raw[0] : raw;
        const control = controlId ? getControl(controlId) : undefined;
        if (!control) {
            return json(uri.href, {
                error: `Unknown control "${String(controlId)}"`,
                supportedControlIds: SUPPORTED_CONTROL_IDS,
            });
        }
        return json(uri.href, {
            ...control,
            iacEvidence: IAC_EVIDENCE_CAPABILITY[control.id] ?? null,
        });
    });
    // -------------------------------------------------------------------------
    // Mapping rule documentation
    // -------------------------------------------------------------------------
    server.registerResource("mapping-rules", "loxe://mappings/rules", {
        title: "IaC-to-control mapping method",
        description: "How this server derives SOC 2 control mappings from scanner findings, and how to read " +
            "the confidence levels.",
        mimeType: "application/json",
    }, async (uri) => json(uri.href, {
        precedence: [
            "override: a check ID pinned in a validated overrides file. confidence=high",
            "resource-attribute: keyword match on check name, corroborated by resource type. confidence=medium",
            "keyword: keyword match on check name alone. confidence=low, verify before relying on it",
            "unmapped: no rule matched. This is a real answer, not a failure",
        ],
        whyNoHardcodedCheckIdTable: "Scanner check IDs change between releases and cannot be verified from inside this " +
            "package. A wrong control mapping in a compliance product is worse than no mapping, " +
            "because it produces confident output that is false. Mapping is therefore driven by " +
            "the scanner's own self-describing check_name and resource metadata.",
        overridesFile: "Set LOXE_MAPPING_OVERRIDES to a JSON file of { \"CKV_AWS_19\": \"CC6.7\" }. Validate " +
            "against a real scanner install before pinning; an unvalidated pin reports high confidence.",
        example: mapFindingToControl({
            checkName: "Ensure all data stored in the S3 bucket is securely encrypted at rest",
            resourceType: "aws_s3_bucket",
        }),
    }));
    // -------------------------------------------------------------------------
    // Scan summary, templated
    // -------------------------------------------------------------------------
    server.registerResource("scan-summary", new ResourceTemplate("loxe://scans/{batchId}/summary", {
        list: undefined,
        complete: {
            batchId: (value) => listBatchIds().filter((id) => id.startsWith(value)),
        },
    }), {
        title: "Scan batch summary",
        description: "Counts and fingerprint for a scan batch. Never includes the findings themselves.",
        mimeType: "application/json",
    }, async (uri, variables) => {
        const raw = variables["batchId"];
        const batchId = Array.isArray(raw) ? raw[0] : raw;
        const batch = batchId ? getBatch(batchId) : undefined;
        if (!batch) {
            return json(uri.href, {
                error: `Unknown batch "${String(batchId)}"`,
                knownBatches: listBatchIds(),
                note: "Batches are in-memory and do not survive a server restart.",
            });
        }
        return json(uri.href, {
            batchId: batch.batchId,
            fingerprint: batch.fingerprint,
            scanner: batch.scanner,
            scannerVersion: batch.scannerVersion,
            frameworks: batch.frameworks,
            createdAt: batch.createdAt,
            filesFingerprinted: batch.fileCount,
            fingerprintTruncated: batch.fingerprintTruncated,
            counts: batch.counts,
            parseErrors: batch.parseErrors,
            sanitization: batch.sanitization,
            caveat: "An IaC scan evidences intended configuration, not deployed state. Do not report a " +
                "control as satisfied on the basis of this scan alone.",
        });
    });
    // -------------------------------------------------------------------------
    // The workflow, as a resource
    // -------------------------------------------------------------------------
    server.registerResource("remediation-workflow", "loxe://workflow/remediation", {
        title: "IaC remediation workflow",
        description: "The scan -> fix -> rescan loop, its ordering rules, guardrails, and the intended-vs-deployed honesty rule.",
        mimeType: "text/markdown",
    }, async (uri) => ({
        contents: [{ uri: uri.href, mimeType: "text/markdown", text: REMEDIATION_WORKFLOW_MD }],
    }));
}
//# sourceMappingURL=index.js.map