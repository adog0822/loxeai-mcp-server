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
import { getControl } from "../catalog/soc2-controls.js";
const AUDITOR_FRAMING = {
    "CC6.1": "CC6.1 is about whether your access architecture is deliberately designed — that protected assets are identified and defended. An auditor reading your Terraform is checking whether the protection was designed in, or bolted on after someone asked.",
    "CC6.3": "CC6.3 covers least privilege and segregation of duties. Over-broad permissions in code are one of the easiest things for an auditor to spot and one of the hardest to argue away, because the policy document says exactly what it grants.",
    "CC6.6": "CC6.6 covers protection against threats from outside your system boundary. An ingress rule open to the world is the single most legible finding in a SOC 2 examination — it needs no interpretation.",
    "CC6.7": "CC6.7 covers protecting information as it moves and restricting where it can go. Unencrypted storage or transport is a direct, documentable gap against this criterion.",
    "CC6.8": "CC6.8 covers preventing or detecting unauthorized software. Baseline images and admission controls are part of how entities commonly address it.",
    "CC7.1": "CC7.1 covers detecting configuration changes that introduce vulnerabilities. Ironically, running this scanner regularly is itself part of how entities address CC7.1 — but the finding below is a gap in the baseline it is checking against.",
    "CC7.2": "CC7.2 covers monitoring for anomalies. Missing logging or alerting configuration means there would be nothing to detect an anomaly with.",
    "CC8.1": "CC8.1 covers whether changes are authorized, tested and approved. Because your infrastructure is in version control, the fix for this finding will itself become change-management evidence — the pull request is the artifact.",
    "CC5.2": "CC5.2 covers general controls over technology. This finding is one input into whether those controls are actually implemented rather than merely described in a policy.",
    "CC9.1": "CC9.1 covers mitigating risks from business disruption. Backup, redundancy and recovery configuration are how entities commonly address it.",
};
const EFFORT_DESCRIPTION = {
    "one-change": "one account-level or organization-level change that closes every instance at once",
    "per-region": "the same change repeated across each affected region",
    "per-resource": "a separate change for each affected resource",
    "per-person": "coordination with each affected person, not a code change",
    unknown: "unclear from the finding alone",
};
function effortShapeFrom(finding) {
    switch (finding.blastRadius.scope) {
        case "account-wide":
            return "one-change";
        case "per-region":
            return "per-region";
        case "per-resource":
            return "per-resource";
        case "per-user":
            return "per-person";
        default:
            return "unknown";
    }
}
function riskLanguage(finding) {
    const subject = finding.resourceType || "this resource";
    if (finding.severity === "UNKNOWN") {
        return (`The scanner did not assign a severity to this check, so the risk is not rated. ` +
            `(Open-source Checkov ships without severity metadata — that is expected, not a defect.) ` +
            `Judge it on what the check is: ${finding.checkName}. If that describes something you would not ` +
            `want to explain to a customer's security team, treat it as real.`);
    }
    const base = {
        CRITICAL: `Left alone, this is the kind of misconfiguration that shows up in an incident report. It affects ${subject}.`,
        HIGH: `This meaningfully weakens the protection around ${subject}, and it is the sort of thing a security reviewer will find quickly.`,
        MEDIUM: `This is a real gap in ${subject}, though exploiting it would usually need something else to go wrong first.`,
        LOW: `This is a hardening gap in ${subject} rather than an active exposure.`,
        INFO: `This is informational — a deviation from the baseline in ${subject} rather than a risk on its own.`,
    };
    return base[finding.severity] ?? `Severity ${finding.severity} on ${subject}.`;
}
export function explainFinding(finding, affectedInThisScan) {
    const control = finding.mapping.controlId ? getControl(finding.mapping.controlId) : undefined;
    const shape = effortShapeFrom(finding);
    const caveats = [];
    const strengths = [];
    const weaknesses = [];
    // ---- what it means ----
    const whatThisMeans = `The check "${finding.checkName}" looked at ${finding.resource} in ${finding.filePath}` +
        (finding.lineRange ? ` (lines ${finding.lineRange[0]}-${finding.lineRange[1]})` : "") +
        ` and found it does not meet the expected configuration. This is a finding about what your ` +
        `infrastructure code DECLARES, not about what is currently running in your account.`;
    // ---- auditor framing ----
    let whyAnAuditorWouldCare;
    if (!control) {
        whyAnAuditorWouldCare =
            "This finding could not be mapped to a SOC 2 criterion, so there is no reliable auditor framing for it. " +
                "It is still a security finding worth fixing on its own merits — it just should not be presented as SOC 2 evidence.";
        weaknesses.push("Not mapped to a criterion, so it contributes nothing to your SOC 2 evidence either way.");
    }
    else {
        const framing = AUDITOR_FRAMING[control.id];
        whyAnAuditorWouldCare = framing
            ? framing
            : `${control.id} (${control.title}) covers: ${control.description} An auditor would read this finding as a gap against that criterion.`;
        if (finding.mapping.confidence === "low") {
            whyAnAuditorWouldCare +=
                ` — treat this mapping with caution: it was inferred from the check name alone and the resource type did not corroborate it. Confirm the criterion before citing this as evidence.`;
            caveats.push("The control mapping is low confidence. The finding is real; the criterion it is attached to may not be.");
        }
        // The honest limit, always stated.
        whyAnAuditorWouldCare +=
            ` Note that fixing this proves INTENDED configuration. It is not evidence of deployed state — that needs a runtime check against your live account.`;
    }
    // ---- what to fix ----
    const whatToFix = `${finding.blastRadius.actionVerb}: ${finding.blastRadius.explanation} ` +
        `Start at ${finding.filePath}` +
        (finding.lineRange ? `:${finding.lineRange[0]}` : "") +
        `.` +
        (finding.guideline ? ` Reference: ${finding.guideline}` : "");
    // ---- strengths / weaknesses, derived only from what we know ----
    strengths.push("This resource is defined as code, which means the fix is reviewable in a pull request — and that pull request is itself partial CC8.1 change-management evidence.");
    if (finding.mapping.confidence === "high" || finding.mapping.confidence === "medium") {
        strengths.push(`The mapping to ${finding.mapping.controlId} is ${finding.mapping.confidence} confidence (${finding.mapping.mappingSource}), so this can be cited with reasonable safety.`);
    }
    if (shape === "one-change" && affectedInThisScan > 1) {
        strengths.push(`This is an account-level fix covering ${affectedInThisScan} findings at once — unusually good effort-to-coverage ratio.`);
    }
    if (shape === "per-resource" && affectedInThisScan > 5) {
        weaknesses.push(`${affectedInThisScan} resources need this same fix individually. Consider whether a module or a policy-as-code guardrail would prevent recurrence, rather than fixing each one.`);
    }
    if (finding.severity === "UNKNOWN") {
        weaknesses.push("No severity metadata, so this cannot be prioritised against other findings automatically.");
    }
    const headline = control
        ? `${finding.checkName} — maps to ${control.id} (${control.title})`
        : `${finding.checkName} — no SOC 2 mapping`;
    return {
        findingId: finding.id,
        headline,
        whatThisMeans,
        realWorldRisk: riskLanguage(finding),
        whyAnAuditorWouldCare,
        whatToFix,
        effort: {
            shape,
            description: EFFORT_DESCRIPTION[shape],
            affectedInThisScan,
        },
        strengths,
        weaknesses,
        caveats,
    };
}
//# sourceMappingURL=explain.js.map