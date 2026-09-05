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
import { SOC2_CONTROLS, } from "../catalog/soc2-controls.js";
export const QUESTIONS = [
    {
        id: "workforce",
        question: "Who does the work — employees, contractors, or both?",
        why: "Determines whether hiring, onboarding and termination evidence sits in an HR system or in contracts. Both are acceptable; the evidence looks completely different.",
        options: [
            { value: "employees", label: "W-2 employees" },
            { value: "contractors-only", label: "Contractors only" },
            { value: "both", label: "Both" },
        ],
    },
    {
        id: "premises",
        question: "Do you have physical premises or company-owned hardware?",
        why: "This is the one place the criteria genuinely scope differently. Fully-remote, cloud-only companies inherit physical security from their cloud provider.",
        options: [
            { value: "fully-remote", label: "Fully remote, no office, laptops only" },
            { value: "office", label: "We have an office" },
            { value: "own-hardware", label: "We run our own servers or datacenter" },
        ],
    },
    {
        id: "customerData",
        question: "What kind of customer data do you handle?",
        why: "Drives how heavy the confidentiality and disposal criteria get, and whether you should be scoping the Confidentiality or Privacy categories on top of Security.",
        options: [
            { value: "none", label: "None — we don't hold customer data" },
            { value: "business-data", label: "Business data, no personal information" },
            { value: "personal-data", label: "Personal information (names, emails, usage)" },
            { value: "regulated-data", label: "Regulated data (health, financial, government)" },
        ],
    },
    {
        id: "cloud",
        question: "Where does your infrastructure run?",
        why: "Determines which evidence is collectable from a cloud API and which needs a different source entirely.",
        options: [
            { value: "single-cloud", label: "One cloud provider" },
            { value: "multi-cloud", label: "More than one cloud provider" },
            { value: "on-prem", label: "Our own hardware" },
            { value: "no-infrastructure", label: "Serverless / fully managed, we run nothing" },
        ],
    },
    {
        id: "iacCoverage",
        question: "How much of your infrastructure is defined as code?",
        why: "This is the direct predictor of how much THIS tool can do for you. It cannot help with infrastructure that was clicked together in a console.",
        options: [
            { value: "all", label: "Essentially all of it" },
            { value: "partial", label: "Some — the rest was set up by hand" },
            { value: "none", label: "None — everything is manual" },
        ],
    },
    {
        id: "productionAccess",
        question: "How many people can change production?",
        why: "Below about three people, segregation of duties becomes the hardest criterion to satisfy honestly, and auditors know it.",
        options: [
            { value: "solo", label: "Just me" },
            { value: "small-team", label: "2 to 5 people" },
            { value: "larger-team", label: "More than 5" },
        ],
    },
    {
        id: "changeProcess",
        question: "Does every production change go through a reviewed pull request?",
        why: "Change management is the single criterion where an auditor will most reliably pull a sample and find an exception.",
        options: [
            { value: "pr-required", label: "Always — branch protection enforces it" },
            { value: "pr-usually", label: "Usually, but hotfixes bypass it" },
            { value: "direct-push", label: "We push directly" },
        ],
    },
    {
        id: "timeline",
        question: "Where are you in the process?",
        why: "Type I is a point in time; Type II needs a complete population across a window. The difference changes what you must start capturing TODAY.",
        options: [
            { value: "exploring", label: "Just exploring whether we need this" },
            { value: "type1-soon", label: "Going for Type I soon" },
            { value: "type2-window-open", label: "Type II observation window is open" },
            { value: "in-audit", label: "Auditor is engaged and asking for evidence" },
        ],
    },
];
// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
function baseWhatYouNeed(control, a) {
    switch (control.id) {
        case "CC1.1":
            return a.workforce === "contractors-only"
                ? "A code of conduct, plus evidence contractors agreed to it — usually a clause in the contractor agreement rather than an HR acknowledgment."
                : "A written code of conduct and a record that each person acknowledged it.";
        case "CC1.2":
            return "Evidence that someone independent of day-to-day management reviews security. At an early-stage company this is usually a board or advisory member with documented periodic review, not a formal audit committee.";
        case "CC1.4":
            return a.workforce === "contractors-only"
                ? "Screening evidence for contractors — usually the vetting done before engagement, plus contract terms. Background-check expectations differ from employees; agree the standard with your auditor early."
                : "Background checks for new hires within a defined window, plus role-appropriate security training.";
        case "CC2.2":
            return "Security awareness training with completion records, and a documented way for people to report concerns.";
        case "CC6.2":
            return a.workforce === "contractors-only"
                ? "Access approved before it is granted and removed when an engagement ends. With contractors, the trigger for revocation is contract end — make sure someone owns noticing it."
                : "Access approved before granting, and removed on termination within your stated SLA. This is where most first audits generate exceptions.";
        case "CC6.4":
            return a.premises === "fully-remote"
                ? "Cite your cloud provider's SOC 2 for datacenter physical security. Cover laptops through device policy."
                : "Badge or lock records for your office or datacenter, plus a visitor process.";
        case "CC6.5":
            return a.premises === "fully-remote"
                ? "A documented process for wiping or destroying laptops when someone leaves, with proof it happened."
                : "Media destruction records for retired drives and hardware.";
        case "CC8.1":
            return a.changeProcess === "pr-required"
                ? "You are in good shape structurally. You will need to show the complete population of production changes for the window and that each went through review."
                : "Evidence that changes are reviewed and approved before production. Direct pushes and hotfixes are the specific thing an auditor will sample for.";
        case "CC9.2":
            return "A vendor inventory, risk tiering, and periodic review of each material vendor — usually collecting their SOC 2 report.";
        default:
            return control.plainEnglish;
    }
}
function classify(control, a) {
    // The only genuine scope difference in the whole catalog.
    if ((control.id === "CC6.4" || control.id === "CC6.5") && a.premises === "fully-remote" && a.cloud !== "on-prem") {
        return {
            applicability: "inherited-via-carve-out",
            rationale: "You have no office and no owned hardware, so datacenter physical security is normally addressed by carving out your cloud provider and citing their SOC 2 report. This is still IN SCOPE — it is satisfied by inheritance, not by omission. Laptop handling remains yours.",
        };
    }
    // Elevated-risk signals, each tied to a specific answer.
    if (control.id === "CC6.3" && a.productionAccess === "solo") {
        return {
            applicability: "applies-elevated-risk",
            rationale: "You are the only person who can change production, so segregation of duties cannot be satisfied by separating people. Auditors accept compensating controls here — logging, alerting on your own actions, an external reviewer — but you must name them explicitly.",
        };
    }
    if (control.id === "CC8.1" && (a.changeProcess === "direct-push" || a.changeProcess === "pr-usually")) {
        return {
            applicability: "applies-elevated-risk",
            rationale: a.changeProcess === "direct-push"
                ? "You push directly to production. This is the criterion most likely to produce an exception, and it is worth fixing before the observation window opens rather than explaining afterwards."
                : "Hotfixes bypass review. Proving a COMPLETE population of changes is much harder when some bypassed the process, because you end up proving a negative.",
        };
    }
    if (control.id === "CC6.2" && a.workforce !== "contractors-only" && a.timeline === "type2-window-open") {
        return {
            applicability: "applies-elevated-risk",
            rationale: "Your Type II window is open, so every termination from here forward becomes a sampled population. Offboarding is the most common source of first-audit exceptions.",
        };
    }
    if (control.id === "CC6.7" && a.customerData === "regulated-data") {
        return {
            applicability: "applies-elevated-risk",
            rationale: "You handle regulated data, so encryption and data-movement controls will be examined more closely than the baseline.",
        };
    }
    if ((control.id === "CC7.1" || control.id === "CC6.1") && a.iacCoverage === "none") {
        return {
            applicability: "applies-elevated-risk",
            rationale: "None of your infrastructure is defined as code, so there is no reviewable record of intended configuration. Evidence has to come from live cloud state instead, and this tool cannot help you here.",
        };
    }
    return {
        applicability: "applies",
        rationale: "In scope for every SOC 2 Security engagement.",
    };
}
function priorityFor(control, a, applicability) {
    let score = 40;
    if (applicability === "applies-elevated-risk")
        score += 35;
    if (applicability === "inherited-via-carve-out")
        score -= 25;
    // Things that must be in place BEFORE a Type II window opens, because they
    // generate a population you cannot retroactively create.
    const populationBearing = ["CC6.2", "CC6.3", "CC8.1", "CC7.2", "CC2.2", "CC1.4"];
    if (populationBearing.includes(control.id)) {
        if (a.timeline === "type2-window-open" || a.timeline === "in-audit")
            score += 20;
        else if (a.timeline === "type1-soon")
            score += 10;
    }
    // Documents are cheap to produce late; activities are not.
    if (control.primarySource === "document")
        score -= 10;
    if (control.primarySource === "human-process")
        score += 5;
    // If the tool can act on it now, surface it — it is the cheapest progress.
    if (control.iac === "primary" && a.iacCoverage !== "none")
        score += 10;
    return Math.max(0, Math.min(100, score));
}
function scopeNotes(a) {
    const notes = [];
    if (a.customerData === "personal-data" || a.customerData === "regulated-data") {
        notes.push("You handle personal data. Consider whether the Confidentiality (C1.1-C1.2) or Privacy (P1-P8, 18 criteria) categories should be in scope alongside Security. They are ADDITIVE to these 33, not a substitute.");
    }
    if (a.customerData === "regulated-data") {
        notes.push("Regulated data often brings a second framework entirely (HIPAA, PCI DSS, or similar). SOC 2 does not satisfy those. This tool covers SOC 2 Security only.");
    }
    if (a.cloud === "multi-cloud") {
        notes.push("Multi-cloud means each provider is a separate subservice organization to carve out, and each needs its own configuration evidence.");
    }
    if (a.timeline === "type2-window-open" || a.timeline === "in-audit") {
        notes.push("Type II needs a COMPLETE population across the window, not a point-in-time snapshot. Start capturing offboarding records, access reviews and change approvals now — these cannot be reconstructed after the fact.");
    }
    if (a.timeline === "exploring") {
        notes.push("If you are exploring: SOC 2 is usually driven by a specific enterprise deal. If no customer has asked, the honest answer may be that you do not need it yet.");
    }
    if (a.iacCoverage === "none") {
        notes.push("With no infrastructure-as-code, this tool's scanner has nothing to read. The catalog and this brief are still useful; the scanning is not.");
    }
    return notes;
}
const STANDING_CAVEATS = [
    "All 33 Common Criteria are in scope for a SOC 2 Security engagement. This brief tells you what each one looks like for a company shaped like yours and what to deal with first. It does not remove anything from scope.",
    "This is a self-assessment produced by a local tool. It is not an audit, an examination, an attestation, or an opinion, and it was not prepared or reviewed by a licensed CPA firm.",
    "Only a licensed CPA firm can perform a SOC 2 examination and issue a report.",
    "Priority ordering is deterministic and derived only from your answers. It is not a score of your security posture.",
];
// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
export function buildApplicabilityBrief(answers) {
    const controls = SOC2_CONTROLS.map((control) => {
        const { applicability, rationale } = classify(control, answers);
        return {
            id: control.id,
            title: control.title,
            group: control.group,
            applicability,
            rationale,
            whatYouNeed: baseWhatYouNeed(control, answers),
            thisToolHelps: control.iac === "none" ? "no" : control.iac,
            priority: priorityFor(control, answers, applicability),
        };
    }).sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
    const elevated = controls.filter((c) => c.applicability === "applies-elevated-risk");
    const startHere = (elevated.length > 0 ? elevated : controls).slice(0, 5).map((c) => ({
        id: c.id,
        title: c.title,
        why: c.rationale,
    }));
    return {
        answers,
        summary: {
            total: controls.length,
            applies: controls.filter((c) => c.applicability === "applies").length,
            inheritedViaCarveOut: controls.filter((c) => c.applicability === "inherited-via-carve-out").length,
            elevatedRisk: elevated.length,
            thisToolCanHelpWith: controls.filter((c) => c.thisToolHelps !== "no").length,
        },
        controls,
        startHere,
        scopeNotes: scopeNotes(answers),
        caveats: STANDING_CAVEATS,
    };
}
//# sourceMappingURL=questionnaire.js.map