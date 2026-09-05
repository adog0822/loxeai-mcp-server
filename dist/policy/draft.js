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
import { getControl } from "../catalog/soc2-controls.js";
export const POLICY_CATALOG = {
    "information-security": {
        kind: "information-security",
        title: "Information Security Policy",
        supportsCriteria: ["CC1.1", "CC1.3", "CC1.5", "CC5.1", "CC5.3", "CC2.2"],
        alsoRequires: [
            "Evidence of management approval, with a date and an approver",
            "Evidence every person acknowledged it, with dates",
            "Evidence of at least annual review",
        ],
    },
    "access-control": {
        kind: "access-control",
        title: "Access Control Policy",
        supportsCriteria: ["CC6.1", "CC6.2", "CC6.3"],
        alsoRequires: [
            "Access request and approval records for the audit window",
            "Deprovisioning records showing revocation within your stated SLA",
            "At least one completed periodic access review, with reviewer and per-person decisions",
        ],
    },
    "change-management": {
        kind: "change-management",
        title: "Change Management Policy",
        supportsCriteria: ["CC8.1", "CC3.4"],
        alsoRequires: [
            "The COMPLETE population of production changes for the window",
            "Evidence each change was reviewed and approved before release",
            "Evidence of testing prior to production",
        ],
    },
    "incident-response": {
        kind: "incident-response",
        title: "Incident Response Plan",
        supportsCriteria: ["CC7.3", "CC7.4", "CC7.5"],
        alsoRequires: [
            "Evidence the plan was exercised — a real incident post-mortem or a documented tabletop",
            "Escalation contact list kept current",
        ],
    },
    "risk-assessment": {
        kind: "risk-assessment",
        title: "Risk Assessment Policy",
        supportsCriteria: ["CC3.1", "CC3.2", "CC3.3", "CC3.4"],
        alsoRequires: [
            "A completed risk register with scored risks and treatment decisions",
            "Evidence the assessment was actually performed, with participants and a date",
            "Explicit consideration of fraud risk",
        ],
    },
    "vendor-management": {
        kind: "vendor-management",
        title: "Vendor Management Policy",
        supportsCriteria: ["CC9.2"],
        alsoRequires: [
            "A vendor inventory with risk tiering",
            "Completed reviews for material vendors — usually their SOC 2 report",
            "Evidence of review at the stated cadence",
        ],
    },
    "business-continuity": {
        kind: "business-continuity",
        title: "Business Continuity and Disaster Recovery Plan",
        supportsCriteria: ["CC9.1", "CC7.5"],
        alsoRequires: [
            "Evidence of a restore or failover test, with results",
            "Documented RTO and RPO targets that match what you can actually achieve",
        ],
    },
    "data-classification": {
        kind: "data-classification",
        title: "Data Classification and Handling Policy",
        supportsCriteria: ["CC6.5", "CC6.7", "CC3.1"],
        alsoRequires: [
            "A data inventory mapped to classification levels",
            "Media destruction records for retired hardware",
        ],
    },
};
const HEADER_NOTE = (title, criteria) => [
    `> **This is a draft, not a finished policy.**`,
    `> It was generated by an automated tool from the answers and scan results supplied. Every`,
    `> \`{{PLACEHOLDER}}\` below requires a human decision — do not ship this document with any of them`,
    `> remaining. Read it end to end and change anything that does not describe what your company`,
    `> actually does. A policy that describes controls you do not operate is worse than no policy:`,
    `> it becomes an audit exception, because the stated control and observed reality disagree.`,
    `>`,
    `> **Having this document does not satisfy ${criteria.join(", ")}.** SOC 2 also wants evidence that`,
    `> it was approved, communicated, acknowledged, and followed. See "What else you need" at the end.`,
    `>`,
    `> This tool is not a law firm and not a CPA firm. ${title} content is a starting point for your`,
    `> own review.`,
].join("\n");
function workforceClause(a) {
    if (!a)
        return "{{WHO_THIS_APPLIES_TO — employees, contractors, or both}}";
    switch (a.workforce) {
        case "employees":
            return "all employees";
        case "contractors-only":
            return "all contractors and their personnel";
        default:
            return "all employees and contractors";
    }
}
function accessReviewCadence(a) {
    // Never silently assert a cadence.
    //
    // Returning a bare "quarterly" for an in-audit company wrote a specific,
    // checkable commitment into the policy with no placeholder and no warning --
    // the exact "policy describes a control you do not operate" failure this
    // module exists to prevent. If they have not been doing quarterly reviews,
    // the document now contradicts their own evidence.
    if (a?.timeline === "type2-window-open" || a?.timeline === "in-audit") {
        return "{{REVIEW_CADENCE — quarterly is the usual choice for an open Type II window, but state the cadence you have ACTUALLY been keeping; a cadence you have not met is an exception, not a control}}";
    }
    return "{{REVIEW_CADENCE — quarterly is the common choice; pick one you will actually keep}}";
}
function buildBody(input) {
    const { kind, answers: a, batch } = input;
    const company = input.companyName ?? "{{COMPANY_NAME}}";
    const grounded = [];
    const warnings = [];
    if (a)
        grounded.push(`Workforce model: ${a.workforce}`);
    if (a)
        grounded.push(`Production access: ${a.productionAccess}`);
    if (a)
        grounded.push(`Change process: ${a.changeProcess}`);
    if (batch) {
        // Actually USE the scan rather than merely naming it. Previously `batch` was
        // referenced only to print this line, while the tool description claimed the
        // draft was "grounded in a real scan" -- an overclaim about our own output.
        grounded.push(`Scan ${batch.batchId}: ${batch.findings.length} finding(s) across ${batch.fileCount} file(s), fingerprint ${batch.fingerprint.slice(0, 12)}`);
        const controls = [...new Set(batch.findings.map((f) => f.mapping.controlId).filter(Boolean))].sort();
        if (controls.length > 0) {
            grounded.push(`Open findings map to: ${controls.join(", ")}`);
        }
        if (batch.parseErrors.length > 0) {
            warnings.push(`The scan this draft references had ${batch.parseErrors.length} parse error(s), so its coverage is incomplete. Do not describe your infrastructure as assessed on the strength of it.`);
        }
        if (batch.suppressions.length > 0) {
            warnings.push(`${batch.suppressions.length} check(s) were suppressed in source. If this policy claims a control is enforced, confirm the suppressions do not contradict it.`);
        }
    }
    const who = workforceClause(a);
    switch (kind) {
        case "access-control": {
            const soloWarning = a?.productionAccess === "solo"
                ? "\n\n### Segregation of duties\n\nOnly one person can currently change production. Separation of duties cannot be achieved by separating people at this size, so this policy relies on compensating controls: {{COMPENSATING_CONTROLS — e.g. all production actions logged and alerted to an external party; monthly review of your own access by an advisor}}. State these explicitly; an auditor will ask, and \"we're too small\" is not an answer they can accept on its own."
                : "\n\n### Segregation of duties\n\nNo single person may both author and approve their own production change. {{EXCEPTIONS_AND_HOW_APPROVED}}";
            if (a?.productionAccess === "solo") {
                warnings.push("Single-operator production access. CC6.3 cannot be satisfied by separating duties between people — you must name compensating controls explicitly.");
            }
            return {
                body: `## Purpose

This policy defines how ${company} grants, modifies, reviews, and revokes access to systems and data.

## Scope

Applies to ${who}, and to all systems that store or process customer data.

## Granting access

1. Access is requested through {{ACCESS_REQUEST_CHANNEL — e.g. a ticket, a form, a named Slack channel}}.
2. Requests are approved by {{APPROVER_ROLE}} before any credential is issued.
3. Access is granted at the least privilege needed for the role.
4. The approval record is retained for at least {{RETENTION_PERIOD — commonly the audit window plus one year}}.

## Removing access

1. Access is revoked within **{{OFFBOARDING_SLA — commonly 24 hours}}** of a person's departure or role change.
2. The trigger for revocation is {{OFFBOARDING_TRIGGER — e.g. HR marks the person terminated; for contractors, contract end date}}.
3. Revocation covers: {{SYSTEM_LIST — enumerate every system, including ones without SSO}}.
4. Completion is recorded, with a timestamp, by {{RESPONSIBLE_ROLE}}.

## Periodic review

Access is reviewed **${accessReviewCadence(a)}**. Each review records the reviewer, the date, and a per-person decision to keep or revoke. Where a review decides to revoke, the revocation is tracked to completion — an intent to revoke is not a revocation.
${soloWarning}

## Authentication

Multi-factor authentication is required for {{MFA_SCOPE — at minimum, all administrative and production access}}. Password requirements are {{PASSWORD_REQUIREMENTS}}.`,
                grounded,
                warnings,
            };
        }
        case "change-management": {
            if (a?.changeProcess === "direct-push" || a?.changeProcess === "pr-usually") {
                warnings.push(a.changeProcess === "direct-push"
                    ? "You reported pushing directly to production. This policy describes a review process you do not currently operate — either adopt the process before the observation window opens, or rewrite this policy to describe what you actually do."
                    : "You reported that hotfixes bypass review. The policy below must describe your ACTUAL hotfix path, including retroactive approval, or it will contradict your change population.");
            }
            const hotfix = a?.changeProcess === "pr-usually"
                ? "\n\n## Emergency changes\n\nYou indicated hotfixes sometimes bypass review. Describe that path honestly rather than omitting it: {{HOTFIX_PROCESS — who may invoke it, what is done at the time, and how it is retroactively reviewed and approved, within what window}}. An emergency path is acceptable to auditors. An undocumented one is not."
                : "\n\n## Emergency changes\n\n{{EMERGENCY_CHANGE_PROCESS — if you have no emergency path, say so explicitly}}";
            return {
                body: `## Purpose

This policy defines how changes to ${company}'s infrastructure and software are authorized, tested, approved, and released.

## Scope

All changes to production systems, including application code, infrastructure-as-code, and configuration.

## Standard change process

1. Changes are proposed as a pull request against {{REPOSITORY_LIST}}.
2. Each pull request requires at least {{REQUIRED_APPROVALS — commonly 1}} approving review from someone other than the author.
3. Automated tests must pass before merge. {{TEST_REQUIREMENTS}}.
4. Branch protection enforces the above on {{PROTECTED_BRANCHES}}. Enforcement in the tool, rather than convention, is what makes this evidenceable.
5. Deployment to production occurs via {{DEPLOYMENT_MECHANISM}}.
${hotfix}

## Evidence

The complete population of production changes for any period is derived from {{CHANGE_POPULATION_SOURCE — e.g. merged pull requests against protected branches, joined with deployment records}}. Completeness matters more than volume: an auditor needs confidence the list contains every change, not merely the changes you remembered.

## Infrastructure as code

Infrastructure is defined as code and changed through the same review process. Static analysis runs on {{SCAN_TRIGGER — e.g. every pull request}}, and findings are triaged before merge.`,
                grounded,
                warnings,
            };
        }
        case "incident-response":
            return {
                body: `## Purpose

This plan defines how ${company} detects, responds to, contains, and recovers from security incidents.

## Roles

- **Incident lead:** {{INCIDENT_LEAD_ROLE}}
- **Escalation contacts:** {{ESCALATION_CONTACTS}}
- **External support:** {{EXTERNAL_CONTACTS — legal, insurer, forensics, if any}}

## Severity levels

{{SEVERITY_DEFINITIONS — define at least two levels and what qualifies for each}}

## Response steps

1. **Detect and record.** Any suspected incident is recorded in {{INCIDENT_TRACKER}} with the time first observed.
2. **Triage.** The incident lead determines severity and whether this is a security incident or a non-security event.
3. **Contain.** {{CONTAINMENT_ACTIONS}}
4. **Eradicate and recover.** Restore affected systems and confirm the cause is removed.
5. **Notify.** Customer and regulatory notification is decided by {{NOTIFICATION_DECISION_ROLE}} within {{NOTIFICATION_WINDOW}}. {{REGULATORY_OBLIGATIONS}}
6. **Post-mortem.** Within {{POSTMORTEM_WINDOW — commonly 5 business days}}, document root cause and the changes made to prevent recurrence.

## Exercising this plan

If no real incident occurs during the audit window, run a documented tabletop exercise at least {{TABLETOP_CADENCE — commonly annually}}. Auditors accept a tabletop as evidence the plan is live; they do not accept an unexercised document.`,
                grounded,
                warnings,
            };
        case "vendor-management":
            return {
                body: `## Purpose

This policy defines how ${company} evaluates and monitors the security of third-party vendors.

## Vendor inventory

All vendors that store, process, or can access customer data are recorded in {{VENDOR_INVENTORY_LOCATION}}, with an owner for each.

## Risk tiering

Vendors are tiered by the sensitivity of data they touch and how critical they are to operations:

- **Tier 1 (critical):** {{TIER_1_DEFINITION}}
- **Tier 2:** {{TIER_2_DEFINITION}}
- **Tier 3:** {{TIER_3_DEFINITION}}

## Review

Before engaging a Tier 1 or Tier 2 vendor, ${company} obtains and reviews {{REQUIRED_EVIDENCE — commonly the vendor's SOC 2 Type II report, or a completed security questionnaire where no report exists}}. Reviews are repeated {{REVIEW_CADENCE — commonly annually}}, and the review record notes who reviewed it, when, and what was concluded.

## Contracts

Vendor contracts include {{CONTRACT_REQUIREMENTS — e.g. security obligations, breach notification timelines, data handling and return}}.

## Sub-processors

{{SUBPROCESSOR_DISCLOSURE — how you disclose your own sub-processors to customers, if applicable}}`,
                grounded,
                warnings,
            };
        case "risk-assessment":
            return {
                body: `## Purpose

This policy defines how ${company} identifies, analyses, and treats risks to its objectives.

## Objectives

The system objectives against which risk is assessed are: {{SYSTEM_OBJECTIVES — be specific; "be secure" is not assessable}}.

## Cadence

A full risk assessment is performed {{ASSESSMENT_CADENCE — commonly annually}}, and additionally whenever a significant change occurs: {{SIGNIFICANT_CHANGE_TRIGGERS — e.g. new product line, new region, material headcount change, new subprocessor, a security incident}}.

## Method

1. Identify risks across {{RISK_CATEGORIES — commonly at least: security, availability, vendor, personnel, legal/regulatory}}.
2. Score each on likelihood and impact using {{SCORING_SCALE}}.
3. Explicitly consider **fraud risk**, including insider misconduct and misappropriation. This is a distinct requirement and is commonly the one that gets skipped.
4. Decide a treatment for each risk: accept, mitigate, transfer, or avoid — with an owner and a date.

## Register

Risks and treatments are recorded in {{RISK_REGISTER_LOCATION}}. The register records who participated in the assessment and when, because the artifact alone does not evidence that the activity happened.`,
                grounded,
                warnings,
            };
        case "business-continuity":
            return {
                body: `## Purpose

This plan defines how ${company} continues operating through, and recovers from, a significant disruption.

## Scope and targets

- **Recovery Time Objective (RTO):** {{RTO — how long you can be down}}
- **Recovery Point Objective (RPO):** {{RPO — how much data you can afford to lose}}

State targets you can actually meet. An RTO you have never tested is a finding waiting to happen.

## Backups

Backups run {{BACKUP_FREQUENCY}} and are retained for {{BACKUP_RETENTION}}. Backups are stored {{BACKUP_LOCATION — note whether this is a separate region or account}} and encrypted.

## Restore testing

A restore is tested at least {{RESTORE_TEST_CADENCE — commonly annually}}. The test records what was restored, how long it took, and whether the RTO/RPO were met. An untested backup is not a control.

## Scenarios

{{SCENARIOS — at minimum: loss of primary cloud region; loss of a critical vendor; loss of a key person}}

## Communication

During a disruption, {{COMMUNICATION_PLAN — who tells customers what, and through which channel}}.`,
                grounded,
                warnings,
            };
        case "data-classification":
            return {
                body: `## Purpose

This policy defines how ${company} classifies data and the handling requirements for each level.

## Classification levels

- **Restricted:** {{RESTRICTED_DEFINITION — typically customer personal data, secrets, credentials}}
- **Confidential:** {{CONFIDENTIAL_DEFINITION — typically internal business data}}
- **Internal:** {{INTERNAL_DEFINITION}}
- **Public:** information approved for public release

## Handling requirements

| Level | At rest | In transit | Access | Retention |
|---|---|---|---|---|
| Restricted | Encrypted | Encrypted (TLS) | Least privilege, MFA | {{RESTRICTED_RETENTION}} |
| Confidential | Encrypted | Encrypted (TLS) | Role-based | {{CONFIDENTIAL_RETENTION}} |
| Internal | {{INTERNAL_AT_REST}} | Encrypted (TLS) | All staff | {{INTERNAL_RETENTION}} |
| Public | Not required | Not required | Public | n/a |

## Data inventory

Data holdings are recorded in {{DATA_INVENTORY_LOCATION}}, mapped to classification level and storage location.

## Disposal

Media and devices holding Restricted or Confidential data are {{DISPOSAL_METHOD — e.g. cryptographically erased, or physically destroyed with a certificate}} before disposal or reassignment, and the disposal is recorded.`,
                grounded,
                warnings,
            };
        case "information-security":
        default:
            return {
                body: `## Purpose

This policy sets out how ${company} protects the confidentiality, integrity, and availability of the systems and data it is responsible for.

## Scope

Applies to ${who}, and to all systems that store or process customer data.

## Roles and responsibilities

- **Accountable owner:** {{SECURITY_OWNER_ROLE — a named role, not "the team"}}
- **Independent oversight:** {{OVERSIGHT_BODY — board member, advisor, or committee, and how often they review}}
- **Everyone:** is responsible for following this policy and reporting suspected security issues via {{REPORTING_CHANNEL}}.

## Standards

${company} maintains the following supporting policies: {{SUPPORTING_POLICY_LIST — access control, change management, incident response, risk assessment, vendor management, business continuity, data classification}}.

## Acceptable use

{{ACCEPTABLE_USE_SUMMARY — device requirements, prohibited activities, and what happens when data is handled outside approved systems}}

## Training and acknowledgment

${who.charAt(0).toUpperCase()}${who.slice(1)} complete security awareness training {{TRAINING_CADENCE — commonly at hire and annually}} and acknowledge this policy. Completion records are retained.

## Enforcement

Violations are handled by {{ENFORCEMENT_PROCESS}}.

## Review

This policy is reviewed and approved at least annually by {{APPROVER}}. The approval date and approver are recorded, because an unapproved policy is not evidence of anything.`,
                grounded,
                warnings,
            };
    }
}
const PLACEHOLDER_RE = /\{\{([^}]+)\}\}/g;
export function draftPolicy(input) {
    const meta = POLICY_CATALOG[input.kind];
    const { body, grounded, warnings } = buildBody(input);
    const markdown = [
        `# ${meta.title}`,
        "",
        HEADER_NOTE(meta.title, meta.supportsCriteria),
        "",
        `**Owner:** {{POLICY_OWNER}}  `,
        `**Approved by:** {{APPROVER}}  `,
        `**Approval date:** {{APPROVAL_DATE}}  `,
        `**Next review:** {{NEXT_REVIEW_DATE}}  `,
        `**Version:** {{VERSION}}`,
        "",
        body,
        "",
        "## What else you need",
        "",
        `This document contributes toward ${meta.supportsCriteria.join(", ")}. On its own it evidences none of them. You will also need:`,
        "",
        ...meta.alsoRequires.map((r) => `- ${r}`),
    ].join("\n");
    const placeholders = [...new Set([...markdown.matchAll(PLACEHOLDER_RE)].map((m) => m[1].trim()))].sort();
    return {
        kind: input.kind,
        title: meta.title,
        markdown,
        supportsCriteria: meta.supportsCriteria.map((id) => ({
            id,
            title: getControl(id)?.title ?? id,
        })),
        alsoRequires: meta.alsoRequires,
        placeholders,
        groundedIn: grounded,
        warnings,
    };
}
//# sourceMappingURL=draft.js.map