/**
 * SOC 2 Common Criteria catalog — all 33.
 *
 * ---------------------------------------------------------------------------
 * COPYRIGHT — READ BEFORE EDITING
 * ---------------------------------------------------------------------------
 * The official criterion text in AICPA TSP Section 100 is
 * "© 2022 Association of International Certified Professional Accountants.
 * All rights reserved." The document is free to download but NOT free to
 * redistribute.
 *
 * Therefore: every `title`, `description` and `plainEnglish` string below is
 * ORIGINAL WORDING written for this project. None of it is AICPA text, and
 * none of it may be replaced with AICPA text. The criterion IDs themselves are
 * facts and are not copyrightable.
 *
 * If you want the official wording, read the source:
 *   AICPA & CIMA. TSP Section 100, "2017 Trust Services Criteria for Security,
 *   Availability, Processing Integrity, Confidentiality, and Privacy
 *   (With Revised Points of Focus — 2022)."
 *   https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
 *
 * ---------------------------------------------------------------------------
 * POINTS OF FOCUS ARE NOT REQUIREMENTS
 * ---------------------------------------------------------------------------
 * TSP 100 §.07 states that using the criteria "does not require an assessment
 * of whether each point of focus is addressed." Points of focus are
 * illustrative; management may customize, omit, or add them.
 *
 * Practical rule for all wording in this package: say "MFA supports CC6.6" or
 * "MFA is a common way entities address CC6.6". NEVER say "CC6.6 requires MFA".
 * MFA appears only as a point of focus. Stating a point of focus as a
 * requirement is the most common credibility failure in automated SOC 2
 * tooling, and an auditor cannot fail an entity against a point of focus.
 *
 * ---------------------------------------------------------------------------
 * SCOPE
 * ---------------------------------------------------------------------------
 * These 33 are the Common Criteria, which ARE the Security category — Security
 * has no additional category-specific criteria. The optional categories are
 * additive on top of these 33:
 *   Availability A1.1-A1.3 (3), Confidentiality C1.1-C1.2 (2),
 *   Processing Integrity PI1.1-PI1.5 (5), Privacy P1-P8 (18).
 * All five categories in scope = 61 criteria. This package covers Security only.
 *
 * SOC 2 is an ATTESTATION, not a certification. There is no "SOC 2 certified",
 * no pass/fail badge, and no AICPA list of required controls. Controls are the
 * entity's own, mapped to criteria by management.
 */
/** Where the evidence for a criterion primarily comes from. */
export type EvidenceSource = 
/** Static analysis of Infrastructure-as-Code. What THIS scanner does. */
"iac"
/** Live cloud API state: IAM listings, CloudTrail, config, scan results. */
 | "cloud-runtime"
/** Identity provider / directory: Workspace, Okta, Entra, GitHub org. */
 | "identity"
/** Version-control process data: PR approvals, branch protection, merges. */
 | "code-process"
/** HR/people data: hires, terminations, training, background checks. */
 | "hr-process"
/** A written artifact: policy, plan, risk register, org chart, certificate. */
 | "document"
/** Only evidenceable by a human having actually performed an activity. */
 | "human-process";
/** How much this IaC scanner can contribute to a criterion. */
export type IacCapability = 
/** IaC is the primary evidence source. */
"primary"
/** IaC contributes, but cannot satisfy the criterion alone. */
 | "partial"
/** No IaC scan can evidence this. Saying otherwise would be false. */
 | "none";
export type Soc2Control = {
    id: string;
    /** COSO/AICPA group name. CC2 uses the 2022 ordering (see note below). */
    group: string;
    /** Original short title. Not AICPA wording. */
    title: string;
    /** Original one-line restatement. Not AICPA wording. */
    description: string;
    /** Founder-facing plain English. Not AICPA wording. */
    plainEnglish: string;
    primarySource: EvidenceSource;
    /** Other sources that partially evidence this criterion. */
    alsoPartial: EvidenceSource[];
    iac: IacCapability;
    /** What an IaC scan can and cannot show here. Always populated. */
    iacNote: string;
};
/**
 * NOTE ON CC2's NAME: the 2022 revision renamed this group to "Information and
 * Communication" (the pre-2022 edition said "Communication and Information").
 * Most secondary sources — including Vanta, Drata and Secureframe — still
 * publish the old ordering. This catalog uses the current one.
 */
export declare const SOC2_CONTROLS: Soc2Control[];
export declare const SUPPORTED_CONTROL_IDS: string[];
export declare function getControl(controlId: string): Soc2Control | undefined;
export declare function controlsByGroup(): Array<{
    group: string;
    controls: Soc2Control[];
}>;
/** Controls this IaC scanner can serve as PRIMARY evidence for. Exactly 3. */
export declare function iacPrimaryControls(): Soc2Control[];
/**
 * Coverage counts, computed rather than hardcoded so they cannot drift as the
 * catalog is edited. Any number quoted in docs or tool output should come from
 * here.
 */
export declare function coverageSummary(): {
    total: number;
    byPrimarySource: Record<EvidenceSource, number>;
    iac: Record<IacCapability, number>;
    /** Criteria whose primary evidence is a document or a human activity. */
    notAutomatable: number;
};
/** @deprecated Use `Soc2Control`. Retained so existing imports keep compiling. */
export type Soc2ControlOption = Soc2Control;
/** @deprecated Use `SOC2_CONTROLS`. */
export declare const SOC2_CONTROL_OPTIONS: Soc2Control[];
export type IacEvidenceCapability = IacCapability;
/** @deprecated Read `iac` and `iacNote` off the control directly. */
export declare const IAC_EVIDENCE_CAPABILITY: Record<string, {
    capability: IacCapability;
    note: string;
}>;
