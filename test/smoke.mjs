/**
 * Protocol smoke test.
 *
 * Drives the built server over real stdio JSON-RPC. Checks two things at once:
 * that every tool/resource/prompt actually works, and that nothing which is not
 * a valid MCP message ever reaches stdout.
 *
 * Run: node test/smoke.mjs
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const serverPath = resolve(here, "..", "dist", "index.js");
const fixtureDir = resolve(here, "fixtures", "tf-injection");

const child = spawn(process.execPath, [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, LOXE_TRUSTED_ROOTS: resolve(here, "..") },
});

let stdoutBuf = "";
const pending = new Map();
const stdoutLines = [];
let stderr = "";

child.stdout.on("data", (chunk) => {
  stdoutBuf += chunk.toString("utf8");
  let idx;
  while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
    const line = stdoutBuf.slice(0, idx).trim();
    stdoutBuf = stdoutBuf.slice(idx + 1);
    if (line.length === 0) continue;
    stdoutLines.push(line);
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      console.error(`\n!! NON-JSON ON STDOUT: ${line.slice(0, 200)}`);
      continue;
    }
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

child.stderr.on("data", (chunk) => {
  stderr += chunk.toString("utf8");
});

let nextId = 1;
function send(method, params) {
  const id = nextId++;
  return new Promise((res, rej) => {
    const timer = setTimeout(() => rej(new Error(`timeout waiting for ${method}`)), 120_000);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      res(msg);
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
}

function notify(method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
}

const results = [];
function check(name, condition, detail = "") {
  results.push({ name, pass: Boolean(condition), detail });
  console.log(`${condition ? "PASS" : "FAIL"}  ${name}${detail ? ` -- ${detail}` : ""}`);
}

function textOf(msg) {
  return (msg?.result?.content ?? []).map((c) => c.text ?? "").join("\n");
}

try {
  // ---- initialize ----
  const init = await send("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "smoke", version: "0" },
  });
  check("initialize returns serverInfo", init.result?.serverInfo?.name === "loxeai-compliance", init.result?.serverInfo?.name);
  check(
    "initialize advertises tools+resources+prompts",
    init.result?.capabilities?.tools && init.result?.capabilities?.resources && init.result?.capabilities?.prompts,
    Object.keys(init.result?.capabilities ?? {}).join(","),
  );
  check("instructions state the SOC 2 scope limit", /Security category/.test(init.result?.instructions ?? "") && /33/.test(init.result?.instructions ?? ""));
  notify("notifications/initialized");

  // ---- listings ----
  const tools = await send("tools/list", {});
  const toolNames = (tools.result?.tools ?? []).map((t) => t.name).sort();
  const EXPECTED_TOOLS = [
    "applicability_brief","applicability_questions","check_capabilities","classify_blast_radius",
    "controls","draft_policy","explain_finding","export_oscal","get_finding","list_findings",
    "list_policies","map_iac_finding_to_control","preview_trust_page","render_trust_page",
    "scan_iac","scanner_status",
  ];
  const missing = EXPECTED_TOOLS.filter((t) => !toolNames.includes(t));
  check("tools/list exposes the expected tool surface", missing.length === 0,
    missing.length ? `missing: ${missing.join(", ")}` : `${toolNames.length} tools`);
  check(
    "every tool declares readOnlyHint:true",
    (tools.result?.tools ?? []).every((t) => t.annotations?.readOnlyHint === true),
    (tools.result?.tools ?? []).map((t) => `${t.name}:${t.annotations?.readOnlyHint}`).join(" "),
  );
  check(
    "every tool declares destructiveHint:false",
    (tools.result?.tools ?? []).every((t) => t.annotations?.destructiveHint === false),
  );
  // Every tool now declares an outputSchema, so a client can validate every
  // payload. The SDK enforces the other direction at runtime: a declared schema
  // with no structuredContent throws.
  const noSchema = (tools.result?.tools ?? []).filter((t) => !t.outputSchema).map((t) => t.name);
  check("every tool declares an outputSchema", noSchema.length === 0, noSchema.join(", ") || "all present");

  const resources = await send("resources/list", {});
  const templates = await send("resources/templates/list", {});
  const resCount = (resources.result?.resources ?? []).length;
  const tplCount = (templates.result?.resourceTemplates ?? []).length;
  check("resources: 3 static + 2 templated", resCount === 3 && tplCount === 2, `static=${resCount} templated=${tplCount}`);

  const prompts = await send("prompts/list", {});
  check("prompts/list returns 2 prompts", (prompts.result?.prompts ?? []).length === 2, (prompts.result?.prompts ?? []).map((p) => p.name).join(","));

  // ---- scanner_status ----
  const status = await send("tools/call", { name: "scanner_status", arguments: {} });
  check("scanner_status returns structuredContent", status.result?.structuredContent !== undefined);
  check(
    // The honest claim is narrower than "none": the server itself makes no
    // requests, but it spawns subprocesses (and check_capabilities probes STS
    // and api.github.com). Assert the disclosure, not the absolute.
    "scanner_status discloses subprocess network behaviour honestly",
    /makes no outbound network requests/.test(status.result?.structuredContent?.networkEgress ?? "") &&
      /subprocess/i.test(status.result?.structuredContent?.networkEgress ?? ""),
    status.result?.structuredContent?.networkEgress,
  );
  check(
    "scanner_status lists all 33 supported controls",
    (status.result?.structuredContent?.supportedControlIds ?? []).length === 33,
  );
  const scannersFound = (status.result?.structuredContent?.scanners ?? []).length;
  console.log(`      (scanners installed on this machine: ${scannersFound})`);

  // ---- controls ----
  const allControls = await send("tools/call", { name: "controls", arguments: {} });
  check("controls returns all 33 criteria", (allControls.result?.structuredContent?.controls ?? []).length === 33);
  const one = await send("tools/call", { name: "controls", arguments: { controlId: "CC6.7" } });
  check(
    "controls(CC6.7) returns its catalog title",
    one.result?.structuredContent?.controls?.[0]?.title === "Data Transmission and Movement",
    one.result?.structuredContent?.controls?.[0]?.title,
  );
  check(
    "CC7.3 reports it cannot be evidenced by IaC",
    (allControls.result?.structuredContent?.controls ?? []).find((c) => c.id === "CC7.3")?.iacEvidenceCapability === "none",
  );

  // ---- mapping ----
  const mapEnc = await send("tools/call", {
    name: "map_iac_finding_to_control",
    arguments: {
      checkName: "Ensure all data stored in the S3 bucket is securely encrypted at rest",
      resourceType: "aws_s3_bucket",
    },
  });
  check(
    "encryption check maps to CC6.7 with medium confidence",
    mapEnc.result?.structuredContent?.controlId === "CC6.7" && mapEnc.result?.structuredContent?.confidence === "medium",
    `${mapEnc.result?.structuredContent?.controlId} / ${mapEnc.result?.structuredContent?.confidence}`,
  );
  check(
    "mapping includes an evidenceLimit caveat",
    typeof mapEnc.result?.structuredContent?.evidenceLimit === "string",
  );

  const mapSg = await send("tools/call", {
    name: "map_iac_finding_to_control",
    arguments: { checkName: "Security group allows ingress from 0.0.0.0/0 to port 22", resourceType: "aws_security_group" },
  });
  check(
    "open security group maps to CC6.6",
    mapSg.result?.structuredContent?.controlId === "CC6.6",
    `${mapSg.result?.structuredContent?.controlId} / ${mapSg.result?.structuredContent?.confidence}`,
  );

  const mapNonsense = await send("tools/call", {
    name: "map_iac_finding_to_control",
    arguments: { checkName: "Ensure widget frobnicator is calibrated" },
  });
  check(
    "unrelated check returns unmapped, not a guess",
    mapNonsense.result?.structuredContent?.controlId === null &&
      mapNonsense.result?.structuredContent?.mappingSource === "unmapped",
    `${mapNonsense.result?.structuredContent?.controlId} / ${mapNonsense.result?.structuredContent?.mappingSource}`,
  );

  // ---- blast radius ----
  const blast = await send("tools/call", {
    name: "classify_blast_radius",
    arguments: {
      findings: [
        { controlId: "CC7.1", title: "CloudTrail is not enabled", severity: "HIGH" },
        { controlId: "CC6.7", title: "S3 bucket default encryption is not configured", severity: "HIGH" },
        { controlId: "CC6.7", title: "S3 bucket default encryption is not configured", severity: "MEDIUM" },
        { controlId: "CC6.7", title: "S3 bucket default encryption is not configured", severity: "LOW" },
        { controlId: "CC6.2", title: "IAM user does not have MFA", severity: "CRITICAL" },
      ],
    },
  });
  const sc = blast.result?.structuredContent;
  check("5 findings collapse to 3 action items", sc?.totalFindings === 5 && sc?.totalActionItems === 3, `${sc?.totalFindings} -> ${sc?.totalActionItems}`);
  check(
    "CloudTrail classified account-wide",
    sc?.groups?.find((g) => g.title.includes("CloudTrail"))?.scope === "account-wide",
    sc?.groups?.find((g) => g.title.includes("CloudTrail"))?.scope,
  );
  check(
    "MFA classified per-user",
    sc?.groups?.find((g) => g.title.includes("MFA"))?.scope === "per-user",
    sc?.groups?.find((g) => g.title.includes("MFA"))?.scope,
  );
  check(
    "duplicate S3 group keeps worst severity (HIGH)",
    sc?.groups?.find((g) => g.title.includes("encryption"))?.severity === "HIGH",
    sc?.groups?.find((g) => g.title.includes("encryption"))?.severity,
  );
  check(
    "highest severity sorts first",
    sc?.groups?.[0]?.severity === "CRITICAL",
    sc?.groups?.[0]?.severity,
  );

  // ---- trust gate: relative path ----
  const rel = await send("tools/call", { name: "scan_iac", arguments: { path: "./relative/path" } });
  check("relative path rejected", rel.result?.isError === true && /relative/i.test(textOf(rel)));
  check("relative-path error tells agent to use pwd", /pwd/.test(textOf(rel)));

  // ---- trust gate: outside trusted root ----
  const outside = await send("tools/call", { name: "scan_iac", arguments: { path: "/etc" } });
  check("path outside trusted root refused", outside.result?.isError === true && /trusted root/i.test(textOf(outside)));

  // ---- trust gate: credential directory ----
  const cred = await send("tools/call", { name: "scan_iac", arguments: { path: `${process.env.HOME}/.aws` } });
  check("credential directory refused", cred.result?.isError === true, textOf(cred).split("\n")[0]?.slice(0, 80));

  // ---- scan the injection fixture ----
  const scan = await send("tools/call", { name: "scan_iac", arguments: { path: fixtureDir } });
  const scanText = textOf(scan);
  if (scannersFound === 0) {
    check("no scanner => actionable error, not empty success", scan.result?.isError === true && /install/i.test(scanText));
    check(
      "no-scanner error explicitly warns it is NOT a clean result",
      /NOT a clean result|not report this infrastructure as compliant/i.test(scanText),
    );
  } else {
    const s = scan.result?.structuredContent;
    check("scan returns a batchId", typeof s?.batchId === "string", s?.batchId);
    check("scan returns a fingerprint", typeof s?.fingerprint === "string" && s.fingerprint.length === 64);
    check("scan does NOT inline findings", s?.findings === undefined);
    check("scan payload under 4KB", JSON.stringify(s).length < 4096, `${JSON.stringify(s).length} bytes`);
    check("scan returns a next handoff", s?.next?.tool === "list_findings");
    check("scan carries the intended-vs-deployed caveat", /intended/i.test(s?.caveat ?? ""));
    check(
      "sanitizer neutralized injection text in scanner output",
      s?.sanitization?.injectionPatternsNeutralized > 0 || s?.sanitization?.invisibleCharsRemoved > 0,
      JSON.stringify(s?.sanitization),
    );

    // fingerprint stability
    const scan2 = await send("tools/call", { name: "scan_iac", arguments: { path: fixtureDir } });
    check(
      "rescan of unchanged input yields identical fingerprint",
      scan2.result?.structuredContent?.fingerprint === s.fingerprint,
    );

    // real mapping distribution: the fixture has encryption + network findings
    check(
      "real scan maps findings to CC6.7 (encryption) and CC6.6 (network)",
      s?.counts?.byControl?.["CC6.7"] > 0 && s?.counts?.byControl?.["CC6.6"] > 0,
      JSON.stringify(s?.counts?.byControl),
    );

    // the name-injection vector, end to end
    const allFindings = await send("tools/call", {
      name: "list_findings",
      arguments: { batchId: s.batchId, limit: 200 },
    });
    const allText = JSON.stringify(allFindings.result?.structuredContent ?? {});
    check(
      "injection in a resource NAME is neutralized in findings output",
      !/ignore_all_previous_instructions/i.test(allText) && /loxe:neutralized/.test(allText),
    );
    check(
      "the resource itself is still identifiable after sanitization",
      /aws_ebs_volume/.test(allText),
    );

    // findings paging
    const findings = await send("tools/call", { name: "list_findings", arguments: { batchId: s.batchId, limit: 5 } });
    check("list_findings returns rows", (findings.result?.structuredContent?.findings ?? []).length > 0);
    check("list_findings output is wrapped as untrusted", /<untrusted-data/.test(textOf(findings)));
    const firstId = findings.result?.structuredContent?.findings?.[0]?.id;
    if (firstId) {
      const detail = await send("tools/call", { name: "get_finding", arguments: { batchId: s.batchId, findingId: firstId } });
      check("get_finding returns mapping with rationale", typeof detail.result?.structuredContent?.mapping?.rationale === "string");
      check("get_finding includes remediation guardrails", (detail.result?.structuredContent?.remediationGuardrails ?? []).length >= 5);
      check(
        "get_finding never emits an absolute path",
        !String(detail.result?.structuredContent?.finding?.filePath ?? "").startsWith("/"),
        detail.result?.structuredContent?.finding?.filePath,
      );
    }
  }

  // ---- unknown batch ----
  const badBatch = await send("tools/call", { name: "list_findings", arguments: { batchId: "batch_nope" } });
  check("unknown batchId returns actionable error", badBatch.result?.isError === true && /scan_iac/.test(textOf(badBatch)));

  // ---- resources ----
  const catalog = await send("resources/read", { uri: "loxe://controls/soc2" });
  const catalogJson = JSON.parse(catalog.result?.contents?.[0]?.text ?? "{}");
  check("control catalog resource reads", catalogJson.controlCount === 33, `controlCount=${catalogJson.controlCount}`);
  check("catalog documents what is NOT covered", typeof catalogJson.notCovered === "string");

  const tpl = await send("resources/read", { uri: "loxe://controls/soc2/CC6.6" });
  check(
    "templated control resource reads",
    JSON.parse(tpl.result?.contents?.[0]?.text ?? "{}").title === "External Threat Protection",
  );

  const wf = await send("resources/read", { uri: "loxe://workflow/remediation" });
  const wfText = wf.result?.contents?.[0]?.text ?? "";
  check("workflow resource reads as markdown", wfText.includes("scan_iac") && wfText.includes("fingerprint"));
  check("workflow states the honesty rule", /intended.*not.*deployed|INTENDED/i.test(wfText));

  const rules = await send("resources/read", { uri: "loxe://mappings/rules" });
  check(
    "mapping-rules resource explains why no hardcoded ID table",
    /worse than no mapping/.test(rules.result?.contents?.[0]?.text ?? ""),
  );

  // ---- completion ----
  const completion = await send("completion/complete", {
    ref: { type: "ref/resource", uri: "loxe://controls/soc2/{controlId}" },
    argument: { name: "controlId", value: "CC6" },
  });
  check(
    "controlId completion returns CC6.x",
    (completion.result?.completion?.values ?? []).length >= 4,
    (completion.result?.completion?.values ?? []).join(","),
  );

  // ---- prompts ----
  const prompt = await send("prompts/get", {
    name: "remediate_finding",
    arguments: { batchId: "batch_nope", findingId: "x" },
  });
  check("remediate_finding handles a stale batch gracefully", /scan_iac/.test(prompt.result?.messages?.[0]?.content?.text ?? ""));

  // ---- stdout discipline ----
  check("every stdout line was valid JSON", stdoutLines.every((l) => { try { JSON.parse(l); return true; } catch { return false; } }), `${stdoutLines.length} lines`);
  check("startup diagnostics went to stderr", /ready on stdio/.test(stderr));
} catch (error) {
  console.error(`\nSMOKE TEST ERROR: ${error.stack ?? error.message}`);
  results.push({ name: "harness completed", pass: false, detail: error.message });
} finally {
  child.kill();
}

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (stderr.trim()) console.log(`\n--- server stderr ---\n${stderr.trim()}`);
if (failed.length > 0) {
  console.log(`\nFAILED:\n${failed.map((f) => `  - ${f.name}${f.detail ? ` (${f.detail})` : ""}`).join("\n")}`);
  process.exit(1);
}
