/**
 * Blast-radius classifier and finding grouper.
 *
 * Ported from the LoxeAI platform (`lib/remediation-meta.ts`). Pure: no I/O, no
 * network, no Prisma. This is what turns "400 findings" into "9 action items
 * across 400 resources".
 *
 * Divergence from the platform copy: the UI-only `REMEDIATION_SCOPE_CONFIG`
 * label/className map is omitted entirely -- it is meaningless over MCP.
 * Classification behaviour is identical, so the two stay in agreement.
 */
export type RemediationScope = "account-wide" | "per-region" | "per-resource" | "per-user";
export type RemediationMeta = {
    scope: RemediationScope;
    actionVerb: string;
    scopeLabel: string;
    explanation: string;
};
export type RemediationGroup<T> = {
    key: string;
    controlId: string;
    title: string;
    severity: string;
    priority: number;
    items: T[];
    meta: RemediationMeta;
};
export declare function remediationGroupKey(item: {
    controlId: string;
    title: string;
}): string;
export declare function getRemediationMeta(input: {
    title: string;
    controlId?: string | null;
}): RemediationMeta;
export declare function groupRemediationItems<T extends {
    controlId: string;
    title: string;
    severity: string;
    priority: number;
}>(items: T[]): RemediationGroup<T>[];
