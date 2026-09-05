/**
 * In-memory batch store with cursor paging.
 *
 * `scan_iac` returns a handoff -- `{ batchId, fingerprint, counts, next }` --
 * not findings. A real Terraform repo yields hundreds of findings; returning
 * them inline would blow the context window and is why every mature scanner MCP
 * (Trivy's `Next`, Prowler's two-tier list/detail, Snyk's output-to-file mode)
 * refuses to do it.
 *
 * State is process-local and deliberately not persisted: a batch is only
 * meaningful for the session that produced it, and writing scan results to disk
 * would create a new artifact to secure.
 */

import { createHash } from "node:crypto";

import { randomUUID } from "node:crypto";
import type { Batch, Finding, FindingSummary, Severity } from "./types.js";
import { SEVERITY_RANK, toSummary } from "./types.js";

/** Keep memory bounded; oldest batches are evicted first. */
const MAX_BATCHES = 10;

const batches = new Map<string, Batch>();

export function putBatch(batch: Omit<Batch, "batchId">): Batch {
  const batchId = `batch_${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const stored: Batch = { batchId, ...batch };
  batches.set(batchId, stored);

  while (batches.size > MAX_BATCHES) {
    const oldest = batches.keys().next();
    if (oldest.done) break;
    batches.delete(oldest.value);
  }

  return stored;
}

export function getBatch(batchId: string): Batch | undefined {
  return batches.get(batchId);
}

export function listBatchIds(): string[] {
  return [...batches.keys()];
}

/** Test seam. */
export function __clearBatches(): void {
  batches.clear();
}

export type FindingFilter = {
  minSeverity?: Severity;
  controlId?: string;
  /** Only findings no rule could map. Useful for validating the mapping layer. */
  unmappedOnly?: boolean;
};

/**
 * Filter findings.
 *
 * UNKNOWN severity is NEVER dropped by `minSeverity`. Checkov's open-source
 * output commonly omits severity, and silently hiding those findings behind a
 * severity filter would under-report real misconfigurations -- the failure mode
 * that matters in a compliance tool. They sort last but stay visible.
 */
export function filterFindings(findings: Finding[], filter: FindingFilter): Finding[] {
  return findings.filter((finding) => {
    if (filter.unmappedOnly && finding.mapping.controlId !== null) return false;
    if (filter.controlId && finding.mapping.controlId !== filter.controlId) return false;
    if (filter.minSeverity) {
      if (finding.severity === "UNKNOWN") return true; // see note above
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[filter.minSeverity]) return false;
    }
    return true;
  });
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.filePath.localeCompare(b.filePath) ||
      a.checkId.localeCompare(b.checkId),
  );
}

export type Page = {
  findings: FindingSummary[];
  nextCursor: string | null;
  total: number;
  returned: number;
};

/**
 * Cursors bind to the filter they were issued under.
 *
 * A bare offset silently skips or repeats rows when the caller changes
 * `minSeverity` or `controlId` between pages -- the offset still points into a
 * list that no longer exists. Embedding a hash of the filter lets us detect the
 * mismatch and say so, rather than returning quietly wrong results.
 */
function filterKey(filter: unknown): string {
  return createHash("sha256").update(JSON.stringify(filter ?? {})).digest("hex").slice(0, 12);
}

function encodeCursor(offset: number, key: string): string {
  return Buffer.from(JSON.stringify({ o: offset, k: key }), "utf8").toString("base64url");
}

function decodeCursor(cursor: string): { offset: number; key: string | null } {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown; k?: unknown };
    return {
      offset: typeof parsed.o === "number" && parsed.o >= 0 ? parsed.o : 0,
      key: typeof parsed.k === "string" ? parsed.k : null,
    };
  } catch {
    return { offset: 0, key: null };
  }
}

export class CursorMismatchError extends Error {
  constructor() {
    super(
      "This cursor was issued for a different filter. Paging with a changed minSeverity or controlId would " +
        "silently skip or repeat findings, so it is refused. Drop the cursor to start over with the new filter.",
    );
    this.name = "CursorMismatchError";
  }
}

export function pageFindings(findings: Finding[], limit: number, cursor?: string, filter?: unknown): Page {
  const key = filterKey(filter);
  const decoded = cursor ? decodeCursor(cursor) : { offset: 0, key: null };
  if (cursor && decoded.key !== null && decoded.key !== key) throw new CursorMismatchError();
  const offset = decoded.offset;
  const slice = findings.slice(offset, offset + limit);
  const nextOffset = offset + slice.length;
  return {
    findings: slice.map(toSummary),
    nextCursor: nextOffset < findings.length ? encodeCursor(nextOffset, key) : null,
    total: findings.length,
    returned: slice.length,
  };
}
