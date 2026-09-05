#!/usr/bin/env bash
#
# Verification gate.
#
# Every check below must pass or this script exits non-zero. Do not add a check
# that prints a count without setting `fail=1` -- a gate that reports and exits
# 0 is worse than no gate, because it manufactures confidence.
set -uo pipefail
fail=0

# Strip only FULL-LINE comments. A previous version used `grep -v '//'`, which
# discarded any line containing a URL -- so `await fetch("https://x")` counted
# as zero matches and the no-network invariant was trivially defeated.
# NOTE the `file:line:` prefix that `grep -rn` emits -- the pattern must skip it
# or nothing is ever recognised as a comment.
strip_comments() { grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|\*|/\*)'; }

count() { # count <pattern> <label>
  local n
  n=$(grep -rn "$1" src/ 2>/dev/null | strip_comments | wc -l | tr -d ' ')
  printf '  %-34s %s\n' "$2" "$n"
  [ "$n" != "0" ] && fail=1
  return 0
}

echo "== deprecated SDK APIs =="
for p in 'server\.tool(' 'server\.resource(' 'server\.prompt(' 'SSEServerTransport' 'transport\.handleMessage'; do
  count "$p" "$p"
done

echo "== no filesystem writes =="
for p in 'writeFileSync' 'fs\.writeFile' 'appendFileSync' 'mkdirSync' 'rmSync' 'unlinkSync' 'createWriteStream' 'renameSync'; do
  count "$p" "$p"
done

echo "== no outbound network from this server =="
for p in 'fetch(' 'https\.request' 'http\.request' 'node:https' 'node:http"' 'axios' 'node-fetch' 'undici' 'XMLHttpRequest'; do
  count "$p" "$p"
done

echo "== stdout discipline =="
count 'console\.log' 'console.log'

echo "== zod .describe not .description =="
count '\.description(' '.description('

echo "== claim safety =="
# Negated forms are the whole point of the disclaimers -- "there is no such
# thing as being 'SOC 2 certified'" must not be flagged as an overclaim. Only
# bare assertions count.
n=$(grep -rn 'SOC 2 certified\|SOC2 certified\|is SOC 2 compliant\|12 criteria\|12 controls' src/ 2>/dev/null \
      | strip_comments \
      | grep -viE 'no such thing|not a certification|is NOT an?|never|do not|does not' \
      | wc -l | tr -d ' ')
printf '  %-34s %s\n' 'stale scope / overclaim strings' "$n"
[ "$n" != "0" ] && fail=1

echo "== typecheck =="
if npx tsc --noEmit; then printf '  %-34s ok\n' 'tsc'; else printf '  %-34s FAILED\n' 'tsc'; fail=1; fi
npx tsc >/dev/null 2>&1   # emit dist for the runtime checks below

echo "== runtime invariants =="
inv=$(node -e "
Promise.all([
  import('./dist/catalog/control-mappings.js'),
  import('./dist/catalog/soc2-controls.js'),
  import('./dist/trust/trust-page.js'),
]).then(([m,c,t])=>{
  const problems=[];
  for (const id of m.mappableControlIds()) {
    const x=c.getControl(id);
    if(!x||x.iac==='none') problems.push('mapper can emit unevidenceable '+id);
  }
  if (c.SOC2_CONTROLS.length!==33) problems.push('catalog is not 33');
  // A scan that parsed nothing must never yield a clean criterion.
  const empty={batchId:'b',fingerprint:'f'.repeat(64),scanner:'checkov',scannerVersion:'x',
    root:'/r',frameworks:[],createdAt:'2026-01-01T00:00:00.000Z',fileCount:0,
    fingerprintTruncated:false,findings:[],counts:{total:0,bySeverity:{},byControl:{},unmapped:0},
    sanitization:{modified:false,invisibleCharsRemoved:0,injectionPatternsNeutralized:0},
    parseErrors:[],suppressions:[],evaluatedResources:0,evaluatedChecks:0};
  const page=t.buildTrustPage(empty);
  if (page.summary.noExceptionsFound!==0) problems.push('empty scan reported '+page.summary.noExceptionsFound+' clean criteria');
  if (!/INCOMPLETE/.test(page.statusLine)) problems.push('empty scan status line not marked incomplete');
  // Files present, but the scanner evaluated nothing -- the unparseable case.
  const nothing={...empty,fileCount:5,evaluatedResources:0,evaluatedChecks:0};
  const p2=t.buildTrustPage(nothing);
  if (p2.summary.noExceptionsFound!==0) problems.push('zero-evaluation scan reported '+p2.summary.noExceptionsFound+' clean criteria');
  console.log(problems.length?problems.join(' | '):'0');
}).catch(e=>console.log('ERROR '+e.message));" 2>&1)
printf '  %-34s %s\n' 'invariant violations' "$inv"
[ "$inv" != "0" ] && fail=1

echo "== unit tests =="
if npx vitest run --reporter=dot >/tmp/loxe-vitest.txt 2>&1; then
  grep -E '^\s+Tests' /tmp/loxe-vitest.txt | sed 's/^/  /'
else
  echo "  FAILED"; tail -20 /tmp/loxe-vitest.txt | sed 's/^/    /'; fail=1
fi

echo "== protocol smoke =="
if smoke=$(node test/smoke.mjs 2>&1); then
  echo "$smoke" | grep -E 'checks passed|^NOTE' | sed 's/^/  /'
else
  echo "  FAILED"; echo "$smoke" | sed -n '/^FAILED:/,$p' | sed 's/^/    /'; fail=1
fi

echo
if [ "$fail" != "0" ]; then echo "VERIFY FAILED"; else echo "VERIFY OK"; fi
exit $fail
