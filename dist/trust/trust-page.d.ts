/**
 * Trust page generation.
 *
 * ---------------------------------------------------------------------------
 * WHY THE VOCABULARY IN THIS FILE IS SO CAREFUL
 * ---------------------------------------------------------------------------
 * Three constraints, all researched, all load-bearing:
 *
 * 1. RESERVED TERMS HAVE STATUTORY TEETH. "Audit", "attestation", "assurance",
 *    "examination" and "opinion" are reserved to licensed CPAs under state
 *    accountancy acts (Uniform Accountancy Act and state adoptions) -- not
 *    merely by AICPA convention. A document titled "Attestation" or carrying an
 *    opinion block invites an unlicensed-practice problem. A document titled
 *    "Security Control Evidence Report", describing itself as automated static
 *    analysis, does not. This risk is almost entirely controlled by naming.
 *
 * 2. THE FTC HAS ALREADY PENALISED THE TOOL VENDOR, NOT JUST THE CUSTOMER.
 *    January 2025: a $1M order against a marketer for deceptive claims that its
 *    AI product could make websites compliant with accessibility guidelines.
 *    The claim shape "our tool makes you compliant with <standard>" is the
 *    penalised one. Separately, the FTC's Privacy Shield enforcement line
 *    prohibits misrepresenting participation in "any privacy or data security
 *    program sponsored by ... any other self-regulatory or standard-setting
 *    organization" -- which is exactly what the AICPA is.
 *
 * 3. SOC 2 IS AN ATTESTATION, NOT A CERTIFICATION. There is no certifying body,
 *    no certificate, and no pass/fail badge. Only a licensed CPA firm can issue
 *    a report. SOC 2 reports are RESTRICTED-USE; SOC 3 is the general-use
 *    report and is the intended artifact for a public page.
 *
 * Consequently this module NEVER emits, and must never be changed to emit:
 *   - "compliant", "certified", "verified", "passed", "audit", "attestation"
 *   - a framework-level green badge
 *   - the AICPA SOC logo (its licence runs to the registered service
 *     organisation, not to this tool)
 *
 * It emits PER-CRITERION EVIDENCE STATUS with a traceable source for each, plus
 * an explicit statement of what is not covered. That is the differentiator:
 * across every incumbent trust center surveyed, essentially nothing on the page
 * is verifiable by the viewer. Here, every line traces to a file, a line number,
 * a rule ID, a confidence level and a timestamp -- and the whole document
 * carries a fingerprint the viewer can recompute.
 *
 * NO WRITES. This module returns strings. The host writes the file with the
 * human in the loop, consistent with the rest of the server.
 */
import type { Batch } from "../scanner/types.js";
/**
 * Per-criterion status.
 *
 * Deliberately NOT "pass"/"fail"/"compliant". "Pass" implies an assessor's
 * judgment; these are observations about scanned files.
 */
export type EvidenceStatus = 
/** Scanned, and no exception was found against this criterion. */
"no-exceptions-found"
/** Scanned, and one or more findings are open. */
 | "exceptions-found"
/** An IaC scan cannot evidence this criterion. Needs another source. */
 | "not-evidenceable-by-scan"
/** Evidenceable in principle, but nothing in the scanned files covered it. */
 | "not-covered-by-this-scan";
export type TrustControlRow = {
    id: string;
    title: string;
    group: string;
    status: EvidenceStatus;
    /** Plain-English reason for the status. Always populated. */
    statusReason: string;
    /** What evidence source this criterion actually needs. */
    evidenceSource: string;
    openFindings: number;
    /** Traceability: where each finding came from. Empty unless exceptions found. */
    traces: Array<{
        findingId: string;
        checkId: string;
        filePath: string;
        line: number | null;
        severity: string;
        mappingSource: string;
        mappingConfidence: string;
    }>;
};
export type TrustPageData = {
    /** Deliberately not "Compliance Report". */
    documentTitle: string;
    /** A true sentence, safe to put in front of a prospect. Never a badge. */
    statusLine: string;
    generatedAt: string;
    scan: {
        batchId: string;
        fingerprint: string;
        scanner: string;
        scannerVersion: string;
        fileCount: number;
        fingerprintTruncated: boolean;
        recomputeCommand: string;
        /** Files the scanner could not read. Never hidden -- see scanCoverage. */
        parseErrors: string[];
        /** Explicit in-source suppressions. Disclosed on the artifact. */
        suppressions: Batch["suppressions"];
        /** True when findings were capped; blocks any clean claim. */
        findingsTruncated: boolean;
        totalFindings: number;
        /** False when parse errors, suppressions or an empty scan make "no exceptions" unclaimable. */
        coverageUsable: boolean;
    };
    scope: {
        framework: string;
        criteriaTotal: number;
        iacPrimary: number;
        iacPartial: number;
        notAutomatable: number;
    };
    summary: {
        noExceptionsFound: number;
        exceptionsFound: number;
        notEvidenceableByScan: number;
        notCoveredByThisScan: number;
        totalOpenFindings: number;
    };
    controls: TrustControlRow[];
    notCovered: string[];
    disclaimers: string[];
    /** SHA-256 over the canonicalised document, excluding this field. */
    documentFingerprint: string;
};
/** Deterministic serialisation: sorted keys, so the hash is reproducible. */
export declare function canonicalize(value: unknown): string;
export declare function fingerprintDocument(data: Omit<TrustPageData, "documentFingerprint">): string;
export declare function buildTrustPage(batch: Batch, now?: Date): TrustPageData;
/**
 * Self-contained HTML. No CDN, no webfont, no analytics, no external image, no
 * script. A trust page that phones home would be flagged in exactly the
 * security review it exists to serve.
 */
export declare function renderTrustPageHtml(data: TrustPageData): string;
/** Markdown, for a README or a questionnaire response. */
export declare function renderTrustPageMarkdown(data: TrustPageData): string;
/** Wording that must never appear in generated output. Enforced by test. */
export declare const FORBIDDEN_CLAIM_WORDS: string[];
