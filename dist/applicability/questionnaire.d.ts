/**
 * Applicability brief — an eight-question scoping interview, run locally.
 *
 * ---------------------------------------------------------------------------
 * AN HONEST REFRAME, READ THIS FIRST
 * ---------------------------------------------------------------------------
 * The obvious version of this feature is "answer 8 questions, learn which of the
 * 33 criteria apply to you." That version would be WRONG, and shipping it would
 * do real damage to a first-time founder.
 *
 * The Common Criteria are not a menu. All 33 are in scope for essentially every
 * SOC 2 Security engagement. TSP 100 §.11 does permit a criterion to be treated
 * as genuinely inapplicable, but the allowance is narrow and every scope-out
 * must be justified to the auditor. A tool that told someone "you can skip
 * CC1.2 because you have no board" would be handing them an exception at
 * fieldwork.
 *
 * So this module answers a different and more useful question:
 *
 *     Not "which criteria apply to me?" (almost all of them)
 *     But  "what does satisfying each one LOOK LIKE for a company shaped
 *           like mine, and which ones should I go deal with first?"
 *
 * That is what a founder actually needs before an audit, and it is answerable
 * deterministically without a network call, an account, or a model.
 *
 * The only true scope-outs this will assert are the physical-security pair
 * (CC6.4/CC6.5) for a cloud-only company with no office and no hardware, and
 * even those are reported as "inherited via subservice carve-out" rather than
 * "does not apply" -- because that is what actually happens in the report.
 */
export type AnswerOption = {
    value: string;
    label: string;
};
export type Question = {
    id: keyof Answers;
    question: string;
    why: string;
    options: AnswerOption[];
};
export type Answers = {
    workforce: "employees" | "contractors-only" | "both";
    premises: "fully-remote" | "office" | "own-hardware";
    customerData: "none" | "business-data" | "personal-data" | "regulated-data";
    cloud: "single-cloud" | "multi-cloud" | "on-prem" | "no-infrastructure";
    iacCoverage: "all" | "partial" | "none";
    productionAccess: "solo" | "small-team" | "larger-team";
    changeProcess: "pr-required" | "pr-usually" | "direct-push";
    timeline: "exploring" | "type1-soon" | "type2-window-open" | "in-audit";
};
export declare const QUESTIONS: Question[];
export type Applicability = 
/** Applies, and you must produce evidence for it. The default for all 33. */
"applies"
/** Applies, but satisfied by citing your cloud provider's own report. */
 | "inherited-via-carve-out"
/** Applies, and your answers suggest this one will be unusually hard. */
 | "applies-elevated-risk";
export type ControlBrief = {
    id: string;
    title: string;
    group: string;
    applicability: Applicability;
    /** Why this classification, given these specific answers. Always populated. */
    rationale: string;
    /** What satisfying this looks like for a company shaped like theirs. */
    whatYouNeed: string;
    /** Can this tool help? Mirrors the catalog's iac capability. */
    thisToolHelps: "primary" | "partial" | "no";
    /** 0-100. Higher = deal with it sooner. Deterministic, not a score of you. */
    priority: number;
};
export type ApplicabilityBrief = {
    answers: Answers;
    /** Never a compliance score. A count of what needs attention first. */
    summary: {
        total: number;
        applies: number;
        inheritedViaCarveOut: number;
        elevatedRisk: number;
        thisToolCanHelpWith: number;
    };
    /** Sorted by priority descending. */
    controls: ControlBrief[];
    /** The handful to deal with first, with the reason. */
    startHere: Array<{
        id: string;
        title: string;
        why: string;
    }>;
    /** Scope guidance beyond the Security category. */
    scopeNotes: string[];
    /** Things that are true regardless of answers, worth saying once. */
    caveats: string[];
};
export declare function buildApplicabilityBrief(answers: Answers): ApplicabilityBrief;
