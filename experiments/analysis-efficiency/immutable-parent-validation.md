# Reuse successful immutable parent validation

This checkpoint addresses [#4810](https://github.com/morluto/rea/issues/4810),
found in the [retained-investigation audit](retained-investigation-workflows.md).
It changes the shared format interpretation used by CLI and MCP views, without
adding a tool, changing a schema, projecting away source data, or rerunning a
provider.

## Question, ownership, and compatibility

The task resumes authentic exported Evidence in a fresh production stdio MCP
server, discovers its source, reads six original symbols or modules in two-row
pages, repeats that traversal three times, queries the existing Unknowns,
exports the investigation, and closes it. The original source records must
survive the round trip exactly. Pages are compared to original retained facts.
Independent ELF byte decoding checks symbol names, values, and ranges; JavaScript
checks cover selected source bytes and the `lib/cli.js` module identity, rather
than independently proving the entire application inventory or semantic graph.

Imported JavaScript graphs lack the producer's realm-private format proofs.
Previously each view repeated full schema, graph/hash, and cross-graph binding
validation. Native layout views likewise parsed the entire layout for every
page. An immutable Evidence root alone was insufficient: its selected normalized
result did not carry the JSON owner's private sealing proof.

The JSON owner now transfers that proof to a selected own member without another
walk or per-node registration. Each format owner records a **successful complete
interpretation of the exact immutable source** in a WeakSet. There is no second
retained parsed graph, strong cache, cross-process cache, or live-state cache.
The schema implementation is fixed for the process; a different source object
must validate independently. Weak entries do not keep Evidence alive, and session
lookup continues to gate access after close.

Cache admission follows full validation and requires that parsing preserved the
source representation. A shared iterative JSON comparison checks own data keys,
scalar values, prototypes, and enumerability without calling accessors. Object
member order is immaterial; array order remains exact. Parser
defaults, hidden-field removal, or other normalization retain the parser's
result and do not cache the source. Writable/configurable descriptor differences
are immaterial: the source is sealed while the temporary parse is mutable.
The JSON sealing boundary rejects proxies before reflection, so arbitrary
mutable proxy behavior cannot acquire an immutable proof. Mutable, merely
Object.freeze'd, failed, and abandoned inputs do not qualify for successful
format reuse.

No Evidence identity, source linkage, coverage, unknown, omission, error, or
caller-selected page changes are intended. Complete source Evidence remains
accessible through the existing contracts. The first view still pays for full
validation and the representation comparison; a one-off CLI invocation cannot
benefit from a cache in a previous process.

## Inputs and measurement scope

Baseline: `2c4338db1fdb7773e05376301c558cff2a0b4b80` (REA 6.6.0).
Node 24.18.0, npm 11.16.0, Linux x86-64 (AMD EPYC 7B12, kernel 6.1.0-53-cloud).
The ELF producer reports pwntools 4.15.0, pyelftools 0.33, and Unicorn 2.1.2.
The baseline's built runtime was preserved
before production changes. Candidate and baseline use the same locked packages.

- SQLite `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6`: SHA-256
  `2e6eef9a727f081f0d453b4e5e6cbd8b9ef8b6f86cbf7681cbad444d3b0b55c8`;
  26 sections, 1,479 symbols, 2,963 relocations. Original history: 1,745,224 bytes.
- Shipped npm 11.16.0: inventory digest
  `f8e576a7d162542c616168b25a95a5f62b9accf29467cc37e149905ad4b8e603`;
  five explicitly selected paths (`package.json`, `bin/npm-cli.js`, `lib/cli.js`,
  `lib/cli/entry.js`, `lib/commands/install.js`), 2,822 application nodes,
  1,796 semantic nodes, 13,682 semantic unknowns. The 1,416 unselected files stay
  unknown. Original history: 21,058,430 bytes.
- Small case `/usr/bin/true`: SHA-256
  `c79bf44242829108e323378531f4ac839513ca1fba45efd6583643526e1e9fd2`;
  31 sections, 53 symbols, 66 relocations. Produced through the real production
  `inspect_binary_layout` MCP operation. An independent raw ELF reader checked
  every symbol name, value, and source range plus section/relocation counts.

The two larger histories were produced and independently checked in the linked
previous audit. They are historical Evidence, not a claim of fresh provider
analysis during a resumed view. All tasks here are static; no target executable
is run.

Each completed comparison includes startup, the complete 207-tool catalog,
import, queries, oracle checks, export, close, receipt writing, and SDK cleanup.
RPC timings exclude subsequent client-side oracle/receipt work. Fresh servers
separate first-view validation from later pages; OS file caches are uncontrolled.
Runs alternate baseline/candidate order. One CPU, 8 GiB hard family memory,
7 GiB early stop, no swap, and a 192-task ceiling bound each serial task.
Resource counters are observed at payload exit while the observer remains alive;
final whole-scope counters are unavailable. Kernel cgroup peaks include charged
file cache and descendants, rather than just the server's JS heap.

## Results and executed validation

Candidate production code: `e30a94a4de6a3c4ec7c577c1551d2b448d82081e`.
The [curated receipt](immutable-parent-validation.json) retains every final run,
ranges, offline token estimates, compatibility checks, and exploratory costs.
Values below are medians with min–max ranges across three alternating pairs.

| Source     | First page, before → after (ms)                       | Eight later pages, before → after (ms)                |
| ---------- | ----------------------------------------------------- | ----------------------------------------------------- |
| SQLite ELF | 237.99 [230.23–251.23] → 287.69 [268.00–297.15]       | 536.28 [505.14–757.92] → 88.24 [85.99–89.71]          |
| npm        | 2358.93 [2344.59–2360.74] → 2784.85 [2661.51–9919.96] | 15087.62 [14619.84–29077.06] → 125.89 [110.60–283.43] |
| Small ELF  | 146.23 [139.34–155.19] → 149.71 [149.42–151.66]       | 510.68 [165.38–545.23] → 196.17 [84.37–206.36]        |

| Source / runtime    | Whole elapsed (s)   | Family CPU (s)      | Kernel family peak (MiB) |
| ------------------- | ------------------- | ------------------- | ------------------------ |
| SQLite ELF / before | 19.25 [19.07–20.01] | 18.91 [18.76–19.67] | 1005.1 [1003.7–1028.3]   |
| SQLite ELF / after  | 18.74 [18.10–20.92] | 18.41 [17.73–20.60] | 1033.2 [985.7–1039.5]    |
| npm / before        | 42.80 [41.50–57.87] | 42.33 [41.17–56.04] | 1394.9 [1289.9–1449.6]   |
| npm / after         | 27.88 [27.27–65.25] | 27.44 [26.82–55.89] | 1259.3 [1241.3–1264.8]   |
| Small ELF / before  | 19.13 [18.55–25.96] | 18.79 [18.30–21.55] | 1006.8 [921.6–1017.8]    |
| Small ELF / after   | 18.69 [18.17–19.06] | 18.43 [17.93–18.74] | 1027.4 [1027.3–1031.4]   |

The demonstrated benefit is repeated selected reads: approximately 6.1× for
SQLite and 120× for npm at the eight-later-pages median. First-view validation
is more expensive. The small case is noisy, and whole-task ranges overlap;
**no stable whole-task, general memory, or complex-software investigation
advantage is established**. npm repetition three slowed on both sides: the
baseline later pages rose across the traversal, and the candidate catalog,
import, and first view were unusually slow. Their cause was not profiled;
neither completed run is excluded or explained away.

All 18 final workflow runs preserve original records and canonical answer
digests. Every corresponding query's structured result and complete catalog
is equal. The three public CLI source pairs are also byte-for-byte identical.
The two additional mixed-history tasks preserve all 97 original records, check
64 follow-up heads over 32 pages and revision two, reject stale updates and
tampered imports atomically, clear Unknowns on close, and refuse old references.

Offline `tiktoken` 0.12.0 / `cl100k_base` estimates for one pass over the complete
catalog, named-call arguments, and replies are **unchanged**: 849,730 native,
856,378 JavaScript, and 840,303 small-case tokens. The catalog contributes
805,215 tokens alone. These are raw transport serialization estimates, not
actual model context or usage; initialization/framing, prompts, client discovery,
rendering/replay, and continuations are unmeasured. No token saving or improved
agent outcome is claimed.

Executed checks at the final production code:

- `npm run check` and `npm run docs:check` pass (including five README
  consistency tests); normal source/architecture/lint/format/metadata checks ran.
- 124 source tests across immutable JSON, native/JavaScript format validation,
  and the shared application view service; `npm run check:fast` and
  `npm run build:cached` pass.
- `npm run test:focused -- tests/boundary/mcp/evidenceBundleInline.test.ts
  tests/boundary/mcp/serverUnknownsMcp.test.ts
  tests/boundary/mcp/analysisViewMcp.test.ts
  tests/boundary/cli/analysisViewCli.test.ts`: 36 tests pass.
- Real public stdio MCP: 18 final paired tasks, two additional mixed tasks;
  public CLI: six invocations, with three exact output pairs. All completed
  guarded tasks have exit zero, verified payload cleanup and zero observed
  payload-exit OOM events.

An internal review reproduced a **candidate-only** defect in the initial
generic deep-equality admission: hidden fields removed by parsing could be
borrowed back. The JSON owner comparison and both format-owner regressions
now cover that case, normalization, mutable/shallow-frozen data, proxies,
and abandoned validation. It is not claimed as a runtime bug in the baseline.

Initial exploratory cohorts used the earlier candidate and are not the final
comparison. One source-check attempt was mistakenly started during an initial
baseline run; the newly started owned scope was stopped after 17.27 s and that
check remains incomplete (exit 241). Its observed counters, contended baseline,
and all later successful retries remain available; no OOM or terminal-counter
claim is inferred from that stopped task.

Real Ghidra, Hopper, JEB, fresh JavaScript producer performance, and new actual
agent trials are outside this checkpoint. Private WeakSet metadata/heap retention
was not measured independently; the absence of a strong retained parsed graph
is source-derived, while the tables measure the complete charged family peak.

## Reproduction and retained evidence

Use `retained-investigation.mjs` from this directory with an authentic exported
bundle and its original source Evidence ID. Build both selected runtime revisions
with the pinned toolchain, preserving a separate baseline. For each runtime run:

```sh
python3 experiments/analysis-efficiency/resource-run.py --observe-payload-exit -- \
  node experiments/analysis-efficiency/retained-investigation.mjs \
  --runtime-root /absolute/runtime --revision REVISION \
  --bundle /absolute/history.json --evidence-id ORIGINAL_EVIDENCE_ID \
  --scenario native --delivery focused --output /absolute/new-receipt-directory
```

Use `--scenario javascript` for the npm history, and `--verify-mixed` with an
actual mixed investigation. Reuse the same bytes and source identity on both
sides. Do not regenerate parent identities or synthesize bundle records.
The checked-in wrapper defaults to a 4 GiB hard / 3 GiB early stop. This
checkpoint used a private resource-only copy with 8 GiB / 7 GiB thresholds,
a 16 GiB available-memory start floor and 8 GiB host early stop. Its source
and unchanged observer hashes are recorded in the curated receipt. This local
resource policy does not change the public workflow or global wrapper defaults.
Raw histories, transcripts, oracle outputs, and resource logs stay in the private
local audit cache; only curated receipts are committed.
