/**
 * NIST OSCAL `assessment-results` export.
 *
 * ---------------------------------------------------------------------------
 * WHY
 * ---------------------------------------------------------------------------
 * OSCAL is NIST's machine-readable format for controls, assessments and
 * results. Its licence is the cleanest available in this space: NIST OSCAL is
 * public domain / CC0, so the schemas can be used without restriction --
 * unlike the AICPA criterion text, and unlike every third-party SOC 2 control
 * corpus, all of which redistribute AICPA text they have no standing to
 * sublicense.
 *
 * Emitting OSCAL buys three things:
 *   - a real standard rather than a bespoke JSON shape
 *   - interoperability with GRC platforms and assessment tooling
 *   - a credible answer to "why should an auditor care about your output"
 *
 * No incumbent trust center or compliance-automation vendor surveyed emits
 * OSCAL. FedRAMP's move to machine-readable packages gives the format tailwind.
 *
 * ---------------------------------------------------------------------------
 * SCOPE HONESTY -- THE PART THAT MATTERS
 * ---------------------------------------------------------------------------
 * OSCAL is FedRAMP-shaped in practice. NIST's own `oscal-content` ships NIST
 * 800-53 catalogs and NO SOC 2 content, and there is no authoritative SOC 2
 * OSCAL catalog anywhere. So the control IDs emitted here reference a catalog
 * that does not officially exist. That is stated in the document itself rather
 * than papered over.
 *
 * This is an EXPORT FORMAT, not an internal model. OSCAL is verbose and
 * FedRAMP-oriented; organising the whole tool around it would distort a
 * codebase whose actual job is mapping scanner findings to CC6.x.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT EMITTED
 * ---------------------------------------------------------------------------
 * OSCAL findings carry a target status of `satisfied` or `not-satisfied`.
 * This module ONLY ever emits `not-satisfied`, and only for criteria where the
 * scan actually found an exception.
 *
 * It never emits `satisfied`. An IaC scan cannot establish that a criterion is
 * satisfied -- the absence of a finding is the absence of evidence, not
 * evidence of absence, and satisfaction of a SOC 2 criterion is a judgment
 * reserved to a licensed CPA. Emitting `satisfied` would be exactly the
 * overclaim this package exists to avoid, laundered through a NIST schema.
 */
import { createHash } from "node:crypto";
import { getControl } from "../catalog/soc2-controls.js";
/** OSCAL version the emitted document conforms to. */
export const OSCAL_VERSION = "1.1.2";
/**
 * Deterministic UUID derived from a seed.
 *
 * OSCAL requires UUIDs everywhere. Random ones would make every export differ,
 * defeating the reproducibility property the rest of this tool is built on --
 * two scans of identical input must produce an identical document. So UUIDs are
 * derived from a SHA-256 of the seed, formatted as a v4-shaped UUID.
 */
export function deterministicUuid(seed) {
    const h = createHash("sha256").update(seed).digest("hex");
    const variant = ((parseInt(h.slice(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, "0");
    return [h.slice(0, 8), h.slice(8, 12), `4${h.slice(13, 16)}`, `${variant}${h.slice(18, 20)}`, h.slice(20, 32)].join("-");
}
const NS = "https://loxe.ai/ns/oscal";
function observationFor(finding, batch) {
    return {
        uuid: deterministicUuid(`${batch.fingerprint}:obs:${finding.id}`),
        title: finding.checkName,
        description: `Static analysis of infrastructure-as-code found that ${finding.resource} in ${finding.filePath}${finding.lineRange ? ` (lines ${finding.lineRange[0]}-${finding.lineRange[1]})` : ""} does not meet the expected configuration for check ${finding.checkId}.`,
        methods: ["TEST"],
        types: ["control-objective"],
        props: [
            { name: "check-id", value: finding.checkId, ns: NS },
            { name: "severity", value: finding.severity, ns: NS },
            { name: "scanner", value: finding.scanner, ns: NS },
            { name: "framework", value: finding.framework, ns: NS },
            { name: "file-path", value: finding.filePath, ns: NS },
            ...(finding.lineRange ? [{ name: "line", value: String(finding.lineRange[0]), ns: NS }] : []),
            { name: "mapping-source", value: finding.mapping.mappingSource, ns: NS },
            { name: "mapping-confidence", value: finding.mapping.confidence, ns: NS },
            { name: "remediation-scope", value: finding.blastRadius.scope, ns: NS },
        ],
        subjects: [
            {
                "subject-uuid": deterministicUuid(`${batch.fingerprint}:subj:${finding.resource}`),
                type: "component",
                title: finding.resource,
            },
        ],
        collected: batch.createdAt,
    };
}
function findingFor(controlId, findings, batch) {
    const control = getControl(controlId);
    return {
        uuid: deterministicUuid(`${batch.fingerprint}:finding:${controlId}`),
        title: `${controlId}${control ? ` — ${control.title}` : ""}: ${findings.length} exception(s) found in scanned infrastructure-as-code`,
        description: `An automated infrastructure-as-code scan surfaced ${findings.length} exception(s) that map to ${controlId}. ` +
            `Mapping confidence varies per observation and is recorded on each. ` +
            `This reflects DECLARED configuration only; it is not evidence of deployed runtime state.`,
        target: {
            type: "objective-id",
            "target-id": controlId,
            status: {
                // Only ever "not-satisfied". See the module header for why "satisfied"
                // is never emitted.
                state: "not-satisfied",
            },
        },
        "related-observations": findings.map((f) => ({
            "observation-uuid": deterministicUuid(`${batch.fingerprint}:obs:${f.id}`),
        })),
    };
}
export function buildOscalAssessmentResults(batch) {
    const byControl = new Map();
    for (const finding of batch.findings) {
        const id = finding.mapping.controlId;
        if (!id)
            continue;
        if (!byControl.has(id))
            byControl.set(id, []);
        byControl.get(id).push(finding);
    }
    const reviewedControlIds = [...byControl.keys()].sort();
    return {
        "assessment-results": {
            uuid: deterministicUuid(`${batch.fingerprint}:assessment-results`),
            metadata: {
                title: "Security Control Evidence Report — automated infrastructure-as-code scan",
                "last-modified": batch.createdAt,
                version: batch.fingerprint.slice(0, 12),
                "oscal-version": OSCAL_VERSION,
                roles: [
                    {
                        id: "tool",
                        title: "Automated static analysis tool",
                        description: "Generated by @loxeai/mcp-server running locally. Not an audit, examination, attestation or opinion, and not prepared or reviewed by a licensed CPA firm.",
                    },
                ],
                props: [
                    { name: "scan-fingerprint", value: batch.fingerprint, ns: NS },
                    { name: "scanner", value: `${batch.scanner} ${batch.scannerVersion}`, ns: NS },
                    { name: "files-fingerprinted", value: String(batch.fileCount), ns: NS },
                    { name: "parse-error-count", value: String(batch.parseErrors.length), ns: NS },
                    {
                        name: "coverage-complete",
                        value: String(batch.parseErrors.length === 0 && batch.fileCount > 0),
                        ns: NS,
                    },
                    ...(batch.parseErrors.length > 0 || batch.fileCount === 0
                        ? [
                            {
                                name: "incomplete-scan-warning",
                                value: batch.fileCount === 0
                                    ? "No infrastructure-as-code files were found or read. This result supports no conclusion about any criterion."
                                    : `The scanner could not parse ${batch.parseErrors.length} file(s). The absence of a finding for any criterion cannot be relied upon; an unparsed file could contain the exception.`,
                                ns: NS,
                            },
                        ]
                        : []),
                    { name: "fingerprint-truncated", value: String(batch.fingerprintTruncated), ns: NS },
                    {
                        name: "control-catalog-note",
                        value: "Control IDs reference the AICPA SOC 2 Trust Services Criteria (Common Criteria). No official OSCAL catalog for SOC 2 exists; these identifiers are used descriptively. SOC 2 and Trust Services Criteria are property of the AICPA; this tool is unaffiliated.",
                        ns: NS,
                    },
                    {
                        name: "status-semantics",
                        value: "Only 'not-satisfied' findings are emitted. This tool never asserts 'satisfied': the absence of a scanner finding is not evidence that a criterion is met, and that determination is reserved to a licensed CPA firm.",
                        ns: NS,
                    },
                    {
                        name: "evidence-limitation",
                        value: "Derived from declared infrastructure-as-code. Not evidence of deployed runtime state, and not evidence of operating effectiveness over time.",
                        ns: NS,
                    },
                ],
            },
            // OSCAL requires import-ap. No formal assessment plan exists for an
            // ad-hoc local scan, so this is stated rather than fabricated.
            "import-ap": {
                href: "#no-assessment-plan",
                remarks: "No formal OSCAL assessment plan governs this scan. It was produced ad hoc by a local static-analysis tool. This field is present because the OSCAL schema requires it.",
            },
            results: [
                {
                    uuid: deterministicUuid(`${batch.fingerprint}:result`),
                    title: "Infrastructure-as-code static analysis",
                    description: `Automated scan of ${batch.fileCount} infrastructure-as-code file(s) using ` +
                        `${batch.scanner} ${batch.scannerVersion}. Findings mapped to SOC 2 Common Criteria by rule and ` +
                        `keyword heuristic, with per-mapping confidence recorded.` +
                        (batch.parseErrors.length > 0
                            ? ` INCOMPLETE: the scanner could not parse ${batch.parseErrors.length} file(s), so the input was ` +
                                `read only in part and the absence of a finding for any criterion cannot be relied upon.`
                            : "") +
                        (batch.fileCount === 0
                            ? ` INCOMPLETE: no infrastructure-as-code files were found or read, so this result supports no conclusion.`
                            : ""),
                    start: batch.createdAt,
                    end: batch.createdAt,
                    "reviewed-controls": {
                        description: "Only criteria to which at least one scanner finding mapped are listed. Criteria not listed were either unreachable by an infrastructure scan or produced no findings; neither case implies satisfaction.",
                        "control-selections": [
                            { "include-controls": reviewedControlIds.map((id) => ({ "control-id": id })) },
                        ],
                    },
                    observations: batch.findings
                        .filter((f) => f.mapping.controlId)
                        .map((f) => observationFor(f, batch)),
                    findings: reviewedControlIds.map((id) => findingFor(id, byControl.get(id), batch)),
                },
            ],
        },
    };
}
//# sourceMappingURL=assessment-results.js.map