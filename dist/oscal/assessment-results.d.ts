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
import type { Batch } from "../scanner/types.js";
/** OSCAL version the emitted document conforms to. */
export declare const OSCAL_VERSION = "1.1.2";
/**
 * Deterministic UUID derived from a seed.
 *
 * OSCAL requires UUIDs everywhere. Random ones would make every export differ,
 * defeating the reproducibility property the rest of this tool is built on --
 * two scans of identical input must produce an identical document. So UUIDs are
 * derived from a SHA-256 of the seed, formatted as a v4-shaped UUID.
 */
export declare function deterministicUuid(seed: string): string;
export declare function buildOscalAssessmentResults(batch: Batch): Record<string, unknown>;
