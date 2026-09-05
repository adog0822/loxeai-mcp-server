export const SEVERITY_RANK = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
    UNKNOWN: 5,
};
export function emptyCounts() {
    return {
        total: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 },
        byControl: {},
        unmapped: 0,
    };
}
export function toSummary(finding) {
    return {
        id: finding.id,
        checkId: finding.checkId,
        checkName: finding.checkName,
        severity: finding.severity,
        resource: finding.resource,
        filePath: finding.filePath,
        controlId: finding.mapping.controlId,
        mappingConfidence: finding.mapping.confidence,
    };
}
//# sourceMappingURL=types.js.map