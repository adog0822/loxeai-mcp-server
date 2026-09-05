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
/**
 * NOTE ON CC2's NAME: the 2022 revision renamed this group to "Information and
 * Communication" (the pre-2022 edition said "Communication and Information").
 * Most secondary sources — including Vanta, Drata and Secureframe — still
 * publish the old ordering. This catalog uses the current one.
 */
export const SOC2_CONTROLS = [
    // ---- CC1: Control Environment (5) ----
    {
        id: "CC1.1",
        group: "Control Environment",
        title: "Integrity and Ethical Values",
        description: "The organization demonstrates a commitment to integrity and ethical values.",
        plainEnglish: "You have a written code of conduct, and people actually sign it.",
        primarySource: "document",
        alsoPartial: ["hr-process", "human-process"],
        iac: "none",
        iacNote: "A code of conduct is a document signed by people. No infrastructure scan can evidence it.",
    },
    {
        id: "CC1.2",
        group: "Control Environment",
        title: "Board Oversight",
        description: "A governing body independent of management oversees the development and performance of internal control.",
        plainEnglish: "Someone independent of the CEO oversees security, and that body actually meets.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Board independence and oversight meetings leave no trace in infrastructure configuration.",
    },
    {
        id: "CC1.3",
        group: "Control Environment",
        title: "Structure and Authority",
        description: "Management establishes reporting lines and appropriate authorities and responsibilities.",
        plainEnglish: "There's an org chart and written role definitions; who decides what is clear.",
        primarySource: "document",
        alsoPartial: ["identity", "human-process"],
        iac: "none",
        iacNote: "Reporting lines are organizational facts. IAM group structure hints at them but does not evidence them.",
    },
    {
        id: "CC1.4",
        group: "Control Environment",
        title: "Competence",
        description: "The organization attracts, develops, and retains competent people in line with its objectives.",
        plainEnglish: "You background-check, screen for competence, and train people.",
        primarySource: "hr-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Hiring, screening and training records live in HR systems, not in infrastructure.",
    },
    {
        id: "CC1.5",
        group: "Control Environment",
        title: "Accountability",
        description: "The organization holds individuals accountable for their internal control responsibilities.",
        plainEnglish: "Security duties are written into job descriptions, reviewed, and actually enforceable.",
        primarySource: "hr-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Accountability is evidenced by job descriptions and performance records, not configuration.",
    },
    // ---- CC2: Information and Communication (3) ----
    {
        id: "CC2.1",
        group: "Information and Communication",
        title: "Quality Information",
        description: "The organization obtains or generates relevant, quality information to support internal control.",
        plainEnglish: "You actually collect the data your controls depend on — logs, asset inventories, data-flow records.",
        primarySource: "document",
        alsoPartial: ["cloud-runtime"],
        iac: "none",
        iacNote: "IaC can declare log destinations, but this criterion is about whether the resulting information is used to run controls.",
    },
    {
        id: "CC2.2",
        group: "Information and Communication",
        title: "Internal Communication",
        description: "The organization internally communicates internal control objectives and responsibilities.",
        plainEnglish: "Staff know their security duties, security training runs, and there's a way to report problems.",
        primarySource: "hr-process",
        alsoPartial: ["document", "identity"],
        iac: "none",
        iacNote: "Training completion and policy acknowledgment are people records.",
    },
    {
        id: "CC2.3",
        group: "Information and Communication",
        title: "External Communication",
        description: "The organization communicates with external parties about matters affecting internal control.",
        plainEnglish: "Customers, vendors and regulators get told what they need to know.",
        primarySource: "document",
        alsoPartial: ["human-process"],
        iac: "none",
        iacNote: "External communication is evidenced by notices, contracts and disclosures.",
    },
    // ---- CC3: Risk Assessment (4) ----
    {
        id: "CC3.1",
        group: "Risk Assessment",
        title: "Objectives",
        description: "The organization specifies objectives clearly enough to identify and assess related risks.",
        plainEnglish: "You've written down what the system is supposed to achieve, specifically enough to risk-assess it.",
        primarySource: "document",
        alsoPartial: [],
        iac: "none",
        iacNote: "Stated objectives are a document. Nothing in infrastructure expresses them.",
    },
    {
        id: "CC3.2",
        group: "Risk Assessment",
        title: "Risk Identification",
        description: "The organization identifies and analyzes risks to its objectives as a basis for managing them.",
        plainEnglish: "You ran a real risk assessment and scored or decided on the risks you found.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "A risk assessment is an activity people perform. A scanner finds misconfigurations, which is not the same thing.",
    },
    {
        id: "CC3.3",
        group: "Risk Assessment",
        title: "Fraud Risk",
        description: "The organization considers the potential for fraud when assessing risk.",
        plainEnglish: "Your risk assessment explicitly covers fraud and insider misconduct.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Fraud consideration is a documented judgment, not a configuration state.",
    },
    {
        id: "CC3.4",
        group: "Risk Assessment",
        title: "Change Risk",
        description: "The organization identifies and assesses changes that could significantly affect internal control.",
        plainEnglish: "Big changes — new product, new region, reorg, new tech — trigger a fresh risk look.",
        primarySource: "human-process",
        alsoPartial: ["document", "code-process"],
        iac: "none",
        iacNote: "Change history is visible in version control, but the reassessment itself is a human activity.",
    },
    // ---- CC4: Monitoring Activities (2) ----
    {
        id: "CC4.1",
        group: "Monitoring Activities",
        title: "Control Evaluations",
        description: "The organization performs ongoing or separate evaluations to confirm controls are present and functioning.",
        plainEnglish: "You independently check your own controls — pen tests, vulnerability scans, internal audit.",
        primarySource: "human-process",
        alsoPartial: ["cloud-runtime", "document"],
        iac: "partial",
        iacNote: "Running this scanner on a schedule is one input to an ongoing evaluation, but it does not by itself satisfy the criterion. Auditors generally expect independent evaluation too.",
    },
    {
        id: "CC4.2",
        group: "Monitoring Activities",
        title: "Deficiency Communication",
        description: "Control deficiencies are evaluated and communicated promptly to those responsible for corrective action.",
        plainEnglish: "Findings get logged, escalated to leadership, and tracked until they're closed.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "This is about escalation and closure, which live in your issue tracker, not your infrastructure.",
    },
    // ---- CC5: Control Activities (3) ----
    {
        id: "CC5.1",
        group: "Control Activities",
        title: "Risk-Mitigating Controls",
        description: "The organization selects and develops control activities that mitigate risks to acceptable levels.",
        plainEnglish: "Every risk you identified has a control mapped against it.",
        primarySource: "document",
        alsoPartial: ["human-process"],
        iac: "none",
        iacNote: "The risk-to-control mapping is a document produced by management.",
    },
    {
        id: "CC5.2",
        group: "Control Activities",
        title: "Technology General Controls",
        description: "The organization selects and develops general control activities over technology.",
        plainEnglish: "You have IT general controls — access, change and operations — over the technology that runs the business.",
        primarySource: "document",
        alsoPartial: ["iac", "cloud-runtime"],
        iac: "partial",
        iacNote: "IaC shows which technology controls are declared. It cannot show that they operate over time.",
    },
    {
        id: "CC5.3",
        group: "Control Activities",
        title: "Policies and Procedures",
        description: "Control activities are deployed through policies that set expectations and procedures that carry them out.",
        plainEnglish: "Policies exist, have owners, get reviewed, and have real procedures behind them.",
        primarySource: "document",
        alsoPartial: ["hr-process"],
        iac: "none",
        iacNote: "Policy existence and review cadence are document facts.",
    },
    // ---- CC6: Logical and Physical Access Controls (8) ----
    {
        id: "CC6.1",
        group: "Logical and Physical Access Controls",
        title: "Logical Access Architecture",
        description: "The organization implements logical access security over protected information assets.",
        plainEnglish: "Access architecture is built right: you know your assets, auth is in place, data is encrypted, the network is segmented.",
        primarySource: "iac",
        alsoPartial: ["cloud-runtime", "document"],
        iac: "primary",
        iacNote: "IaC shows declared access architecture, encryption and segmentation. It cannot show who actually has access today.",
    },
    {
        id: "CC6.2",
        group: "Logical and Physical Access Controls",
        title: "Access Provisioning and Deprovisioning",
        description: "Access is authorized and registered before credentials are issued, and removed when no longer authorized.",
        plainEnglish: "Access is approved before it's granted, and revoked when someone leaves.",
        primarySource: "identity",
        alsoPartial: ["hr-process", "cloud-runtime"],
        iac: "none",
        iacNote: "IaC may declare password policy resources, but provisioning and offboarding are identity-system and HR events. This is the criterion offboarding evidence maps to.",
    },
    {
        id: "CC6.3",
        group: "Logical and Physical Access Controls",
        title: "Least Privilege",
        description: "Access is authorized, modified, and removed by role, with least privilege and segregation of duties considered.",
        plainEnglish: "People have the minimum access they need, duties are separated, and access gets reviewed periodically.",
        primarySource: "cloud-runtime",
        alsoPartial: ["identity", "iac", "code-process"],
        iac: "partial",
        iacNote: "IaC shows declared policy scope. Actually-granted privilege and the periodic access review are runtime and process evidence.",
    },
    {
        id: "CC6.4",
        group: "Logical and Physical Access Controls",
        title: "Physical Access",
        description: "Physical access to facilities and protected assets is restricted to authorized personnel.",
        plainEnglish: "Badges and locks on data centers and offices. If you're cloud-only, this is mostly inherited from AWS or GCP.",
        primarySource: "document",
        alsoPartial: ["human-process"],
        iac: "none",
        iacNote: "For cloud-only companies this is normally addressed by a subservice organization carve-out, citing the cloud provider's own SOC 2 report.",
    },
    {
        id: "CC6.5",
        group: "Logical and Physical Access Controls",
        title: "Asset Disposal",
        description: "Protections are removed from physical assets only after data can no longer be read or recovered.",
        plainEnglish: "Wipe or destroy drives and laptops before disposal, and keep proof you did.",
        primarySource: "document",
        alsoPartial: ["human-process", "cloud-runtime"],
        iac: "none",
        iacNote: "Disposal is evidenced by destruction certificates and asset records.",
    },
    {
        id: "CC6.6",
        group: "Logical and Physical Access Controls",
        title: "External Threat Protection",
        description: "Logical access measures protect against threats originating outside the system boundary.",
        plainEnglish: "Your perimeter is defended: security groups and firewalls are tight, external entry points are protected, traffic is encrypted.",
        primarySource: "iac",
        alsoPartial: ["cloud-runtime"],
        iac: "primary",
        iacNote: "IaC shows declared security groups, NACLs and ingress rules. Effective reachability of a running system is runtime-only.",
    },
    {
        id: "CC6.7",
        group: "Logical and Physical Access Controls",
        title: "Data Transmission and Movement",
        description: "The movement and removal of information is restricted to authorized parties and protected in transit.",
        plainEnglish: "Data is encrypted in transit, and you control what can leave — egress, removable media, endpoints.",
        primarySource: "iac",
        alsoPartial: ["cloud-runtime", "identity"],
        iac: "primary",
        iacNote: "IaC shows declared encryption in transit and egress rules. Endpoint and device posture come from an MDM, not from infrastructure code.",
    },
    {
        id: "CC6.8",
        group: "Logical and Physical Access Controls",
        title: "Malicious Software Prevention",
        description: "Controls prevent or detect and act upon the introduction of unauthorized or malicious software.",
        plainEnglish: "You run anti-malware or EDR, scan images and dependencies, and restrict what software can be installed.",
        primarySource: "cloud-runtime",
        alsoPartial: ["iac", "identity"],
        iac: "partial",
        iacNote: "IaC can declare baseline images and admission control. Actual agent coverage and scan results are runtime evidence.",
    },
    // ---- CC7: System Operations (5) ----
    {
        id: "CC7.1",
        group: "System Operations",
        title: "Configuration and Vulnerability Detection",
        description: "Detection and monitoring procedures identify configuration changes that introduce vulnerabilities, and newly discovered vulnerabilities.",
        plainEnglish: "You have hardening baselines, you notice when config drifts, and you scan for vulnerabilities on a schedule.",
        primarySource: "cloud-runtime",
        alsoPartial: ["iac"],
        iac: "partial",
        iacNote: "IaC expresses the baseline. Detecting drift away from it requires comparing against live state, which this scanner does not do.",
    },
    {
        id: "CC7.2",
        group: "System Operations",
        title: "Anomaly Monitoring",
        description: "System components are monitored for anomalies indicating malicious acts or errors, and anomalies are analyzed.",
        plainEnglish: "Logging and alerting are on, and someone actually triages the alerts.",
        primarySource: "cloud-runtime",
        alsoPartial: ["iac"],
        iac: "partial",
        iacNote: "IaC can declare alarms and log destinations. Whether anything fires, and whether a human looks, is runtime and process evidence.",
    },
    {
        id: "CC7.3",
        group: "System Operations",
        title: "Security Event Evaluation",
        description: "Security events are evaluated to determine whether they are incidents, and action is taken.",
        plainEnglish: "You decide whether an alert is a real incident, and then you act on it.",
        primarySource: "human-process",
        alsoPartial: ["cloud-runtime", "document"],
        iac: "none",
        iacNote: "Triage judgment is a human activity, evidenced by ticket trails.",
    },
    {
        id: "CC7.4",
        group: "System Operations",
        title: "Incident Response",
        description: "Identified incidents are responded to through a defined incident-response program.",
        plainEnglish: "You have an incident response plan and you actually run it — including tabletop exercises if you've had no real incidents.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "An IR program is evidenced by the plan plus records of it being exercised.",
    },
    {
        id: "CC7.5",
        group: "System Operations",
        title: "Incident Recovery",
        description: "The organization identifies, develops, and implements activities to recover from identified incidents.",
        plainEnglish: "After an incident you restore the environment, find the root cause, and fix the underlying gap.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Recovery and root-cause analysis are activities, evidenced by post-mortems.",
    },
    // ---- CC8: Change Management (1) ----
    {
        id: "CC8.1",
        group: "Change Management",
        title: "Change Management",
        description: "Changes to infrastructure, data, software and procedures are authorized, designed, tested, approved and implemented.",
        plainEnglish: "Changes go through review and testing before they ship, and nobody pushes to production unilaterally.",
        primarySource: "code-process",
        alsoPartial: ["iac", "cloud-runtime"],
        iac: "partial",
        iacNote: "Keeping infrastructure in version control is partial evidence. The approval and testing records live in pull requests and CI, not in the files themselves.",
    },
    // ---- CC9: Risk Mitigation (2) ----
    {
        id: "CC9.1",
        group: "Risk Mitigation",
        title: "Business Disruption Risk",
        description: "The organization identifies and develops activities that mitigate risks from business disruptions.",
        plainEnglish: "You've planned for outages and disasters — redundancy, backups, recovery plans, maybe insurance.",
        primarySource: "document",
        alsoPartial: ["human-process", "iac"],
        iac: "partial",
        iacNote: "IaC can show multi-AZ and backup resources are declared. The BC/DR plan and evidence of testing it are documents.",
    },
    {
        id: "CC9.2",
        group: "Risk Mitigation",
        title: "Vendor Risk",
        description: "The organization assesses and manages risks arising from vendors and business partners.",
        plainEnglish: "You keep a vendor list, tier them by risk, review them periodically, and put security terms in contracts.",
        primarySource: "human-process",
        alsoPartial: ["document"],
        iac: "none",
        iacNote: "Vendor review is an activity evidenced by vendor questionnaires, their SOC 2 reports, and contract terms.",
    },
];
// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------
export const SUPPORTED_CONTROL_IDS = SOC2_CONTROLS.map((c) => c.id);
export function getControl(controlId) {
    return SOC2_CONTROLS.find((control) => control.id === controlId);
}
export function controlsByGroup() {
    const order = [];
    const map = new Map();
    for (const control of SOC2_CONTROLS) {
        if (!map.has(control.group)) {
            map.set(control.group, []);
            order.push(control.group);
        }
        map.get(control.group).push(control);
    }
    return order.map((group) => ({ group, controls: map.get(group) }));
}
/** Controls this IaC scanner can serve as PRIMARY evidence for. Exactly 3. */
export function iacPrimaryControls() {
    return SOC2_CONTROLS.filter((c) => c.iac === "primary");
}
/**
 * Coverage counts, computed rather than hardcoded so they cannot drift as the
 * catalog is edited. Any number quoted in docs or tool output should come from
 * here.
 */
export function coverageSummary() {
    const byPrimarySource = {
        iac: 0,
        "cloud-runtime": 0,
        identity: 0,
        "code-process": 0,
        "hr-process": 0,
        document: 0,
        "human-process": 0,
    };
    const iac = { primary: 0, partial: 0, none: 0 };
    for (const control of SOC2_CONTROLS) {
        byPrimarySource[control.primarySource] += 1;
        iac[control.iac] += 1;
    }
    return {
        total: SOC2_CONTROLS.length,
        byPrimarySource,
        iac,
        notAutomatable: byPrimarySource.document + byPrimarySource["human-process"],
    };
}
/** @deprecated Use `SOC2_CONTROLS`. */
export const SOC2_CONTROL_OPTIONS = SOC2_CONTROLS;
/** @deprecated Read `iac` and `iacNote` off the control directly. */
export const IAC_EVIDENCE_CAPABILITY = Object.fromEntries(SOC2_CONTROLS.map((c) => [c.id, { capability: c.iac, note: c.iacNote }]));
//# sourceMappingURL=soc2-controls.js.map