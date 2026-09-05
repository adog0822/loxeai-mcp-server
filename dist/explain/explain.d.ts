/**
 * Plain-English explanation of a finding.
 *
 * Closes the gap between what a scanner emits (`CKV_AWS_19`, `CC6.7`,
 * `confidence: medium`) and what a founder who has never done an audit
 * actually needs to know.
 *
 * ---------------------------------------------------------------------------
 * HONESTY RULES FOR THIS MODULE
 * ---------------------------------------------------------------------------
 * Everything returned here is DERIVED from data already in the finding: the
 * control mapping and its confidence, the severity the scanner assigned, the
 * blast-radius classification, the resource type, and the file location.
 *
 * Nothing is invented. Specifically:
 *
 *   - Where severity is UNKNOWN (common with open-source Checkov, which ships
 *     no severity metadata), the risk language says so rather than guessing.
 *   - Where the control mapping confidence is low, the auditor framing is
 *     hedged, because the mapping itself might be wrong.
 *   - Effort estimates are expressed as a SHAPE of work ("one account-level
 *     change" vs "one change per resource, 12 resources") derived from the
 *     blast-radius classifier, never as hours. Hours would be fabrication.
 *   - "Why an auditor would care" is written against the CRITERION, which is
 *     stable, not against a guess at a specific auditor's behaviour.
 *
 * WORDING CONSTRAINT: never state a point of focus as a requirement. Say "MFA
 * supports CC6.6", never "CC6.6 requires MFA". Points of focus are illustrative
 * under TSP 100 §.07 and an auditor cannot fail an entity against one.
 */
import type { Finding } from "../scanner/types.js";
export type EffortShape = "one-change" | "per-region" | "per-resource" | "per-person" | "unknown";
export type FindingExplanation = {
    findingId: string;
    headline: string;
    /** What the check actually looked at and what it found. */
    whatThisMeans: string;
    /** Consequence if left alone. Hedged when severity is UNKNOWN. */
    realWorldRisk: string;
    /** Framed against the criterion, which is stable. Hedged on low confidence. */
    whyAnAuditorWouldCare: string;
    /** Concrete next action. */
    whatToFix: string;
    effort: {
        shape: EffortShape;
        /** Human phrasing of the shape, e.g. "one account-level change". */
        description: string;
        /** How many resources share this fix in the current batch. */
        affectedInThisScan: number;
    };
    strengths: string[];
    weaknesses: string[];
    /** Set when this explanation is standing on a weak mapping. */
    caveats: string[];
};
export declare function explainFinding(finding: Finding, affectedInThisScan: number): FindingExplanation;
