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

const severityRank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

export function remediationGroupKey(item: { controlId: string; title: string }): string {
  return `${item.controlId}::${normalize(item.title)}`;
}

const accountWide: RemediationMeta = {
  scope: "account-wide",
  actionVerb: "Enable once",
  scopeLabel: "Account-wide fix",
  explanation: "One account or organization-level change can close every affected instance in this group.",
};

const perRegion: RemediationMeta = {
  scope: "per-region",
  actionVerb: "Run per region",
  scopeLabel: "Regional rollout",
  explanation: "Apply the same fix across the affected AWS regions, usually with a CLI loop or org-level rollout.",
};

const perResource: RemediationMeta = {
  scope: "per-resource",
  actionVerb: "Update each resource",
  scopeLabel: "Resource-by-resource",
  explanation: "Each affected resource needs its configuration reviewed or changed.",
};

const perUser: RemediationMeta = {
  scope: "per-user",
  actionVerb: "Update each person",
  scopeLabel: "Human coordination",
  explanation: "This needs user-by-user coordination or identity policy enforcement.",
};

const EXACT_TITLE_META: Record<string, RemediationMeta> = {
  "iam access analyzer has no active analyzer": accountWide,
  "iam access analyzer is not enabled": accountWide,
  "cloudtrail is not enabled": accountWide,
  "cloudtrail multi region trail is not enabled": accountWide,
  "cloudwatch alarm for root account login is missing": accountWide,
  "root account access key exists": accountWide,
  "aws organizations is not configured": accountWide,
  "guardduty is not enabled": perRegion,
  "guardduty detector is not enabled": perRegion,
  "security hub is not enabled": perRegion,
  "aws security hub is not enabled": perRegion,
  "aws config recorder is not enabled": perRegion,
  "config recorder is not enabled": perRegion,
  "macie is not enabled": perRegion,
  "iam user does not have mfa": perUser,
  "iam user mfa is not enabled": perUser,
  "console user does not have mfa": perUser,
  "s3 bucket public access block is not fully enabled": perResource,
  "s3 bucket default encryption is not configured": perResource,
  "s3 bucket versioning is not enabled": perResource,
  "security group allows public ingress": perResource,
  "rds instance is publicly accessible": perResource,
  "rds storage encryption is not enabled": perResource,
  "ebs volume is not encrypted": perResource,
  "ecr repository image scanning is not enabled": perResource,
  "lambda function environment is not encrypted with a customer managed key": perResource,
  "github repository does not require branch protection": perResource,
  "github repository does not require code review": perResource,
  "github repository secret scanning is not enabled": perResource,
  "github repository dependabot alerts are not enabled": perResource,
};

export function getRemediationMeta(input: { title: string; controlId?: string | null }): RemediationMeta {
  const title = normalize(input.title);
  const exact = EXACT_TITLE_META[title];
  if (exact) return exact;

  if (title.includes("access analyzer")) return accountWide;
  if (title.includes("root account") || title.includes("root user")) return accountWide;
  if (title.includes("organizations") || title.includes("organization trail")) return accountWide;
  if (title.includes("cloudtrail") && !title.includes("trail log file validation")) return accountWide;
  if (title.includes("guardduty") || title.includes("security hub") || title.includes("config recorder")) return perRegion;
  if (title.includes("aws config") || title.includes("macie") || title.includes("detective")) return perRegion;
  if (title.includes("mfa") || title.includes("password") || title.includes("inactive user") || title.includes("access key")) return perUser;
  if (title.includes("github repository") || title.includes("repo ")) return perResource;
  if (title.includes("bucket") || title.includes("security group") || title.includes("rds") || title.includes("ebs")) return perResource;
  if (title.includes("lambda") || title.includes("ecr") || title.includes("kms") || title.includes("secret")) return perResource;

  return perResource;
}

export function groupRemediationItems<
  T extends { controlId: string; title: string; severity: string; priority: number },
>(items: T[]): RemediationGroup<T>[] {
  const groups = new Map<string, RemediationGroup<T>>();
  for (const item of items) {
    const key = remediationGroupKey(item);
    const current = groups.get(key);
    if (current) {
      current.items.push(item);
      if ((severityRank[item.severity] ?? 9) < (severityRank[current.severity] ?? 9)) current.severity = item.severity;
      current.priority = Math.min(current.priority, item.priority);
    } else {
      groups.set(key, {
        key,
        controlId: item.controlId,
        title: item.title,
        severity: item.severity,
        priority: item.priority,
        items: [item],
        meta: getRemediationMeta(item),
      });
    }
  }
  return [...groups.values()].sort(
    (a, b) =>
      a.priority - b.priority ||
      (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) ||
      b.items.length - a.items.length,
  );
}
