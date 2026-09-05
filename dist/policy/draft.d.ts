/**
 * Policy drafting.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS LEGITIMATE WHEN MOST OF THE TOOL REFUSES TO GENERATE THINGS
 * ---------------------------------------------------------------------------
 * Everywhere else this package refuses to assert what it cannot evidence.
 * Policy drafting is different in kind: it is GENERATION, not evidence
 * collection. Nobody is claiming the document proves anything. A policy is an
 * artifact the company authors, and the honest failure mode is a bad draft, not
 * a false claim.
 *
 * That said, two real hazards, both designed around:
 *
 * 1. BOILERPLATE IS AN AUDIT LIABILITY. Auditors recognise templated policies
 *    on sight, and a policy describing controls the company does not operate is
 *    worse than no policy -- it becomes an exception, because the stated control
 *    and the observed reality disagree. So every draft here is grounded in the
 *    caller's actual answers and actual scan findings, and every spot requiring
 *    human judgment is an explicit {{PLACEHOLDER}} that is counted and reported
 *    back rather than silently filled with a plausible default.
 *
 * 2. A POLICY DOES NOT SATISFY A CRITERION. Having the document is necessary
 *    and nowhere near sufficient: SOC 2 wants evidence it was approved,
 *    communicated, acknowledged, and followed. Every draft says so in its own
 *    header, so the founder cannot mistake "I generated the policy" for "I
 *    addressed the criterion".
 *
 * ---------------------------------------------------------------------------
 * LICENSING
 * ---------------------------------------------------------------------------
 * All prose here is original to this project. It is NOT derived from
 * strongdm/comply, JupiterOne's templates, Comp AI, or any other corpus.
 *
 * That is deliberate. Every widely-used SOC 2 policy/control corpus surveyed
 * turned out to redistribute AICPA Trust Services Criteria text -- in one case
 * with "entity" search-replaced to "organization" -- and an open-source licence
 * conveys only rights the licensor actually holds. Rather than inherit that
 * problem, this is written from scratch.
 */
import type { Answers } from "../applicability/questionnaire.js";
import type { Batch } from "../scanner/types.js";
export type PolicyKind = "information-security" | "access-control" | "change-management" | "incident-response" | "risk-assessment" | "vendor-management" | "business-continuity" | "data-classification";
export type PolicyMeta = {
    kind: PolicyKind;
    title: string;
    /** Criteria this policy contributes evidence toward. Never "satisfies". */
    supportsCriteria: string[];
    /** What else you must produce beyond the document itself. */
    alsoRequires: string[];
};
export declare const POLICY_CATALOG: Record<PolicyKind, PolicyMeta>;
export type PolicyDraft = {
    kind: PolicyKind;
    title: string;
    markdown: string;
    supportsCriteria: Array<{
        id: string;
        title: string;
    }>;
    alsoRequires: string[];
    /** Every {{PLACEHOLDER}} a human must resolve. Counted, never auto-filled. */
    placeholders: string[];
    /** Facts pulled from the caller's answers/scan that grounded this draft. */
    groundedIn: string[];
    warnings: string[];
};
export type DraftInput = {
    kind: PolicyKind;
    companyName?: string;
    answers?: Answers;
    batch?: Batch;
};
export declare function draftPolicy(input: DraftInput): PolicyDraft;
