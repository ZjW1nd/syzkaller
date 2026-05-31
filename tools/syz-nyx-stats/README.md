# syz-nyx-stats

`syz-nyx-stats` collects runtime counters from `syz-manager` and `syz-nyx-runner`
logs, writes a CSV timeline, and renders simple SVG/HTML plots.

## Collect

```bash
./bin/syz-nyx-stats collect \
  --manager-log /path/to/fullchain-manager.log \
  --runner-log /path/to/fullchain-runner.log \
  --output /path/to/stats.csv
```

## Plot

```bash
./bin/syz-nyx-stats plot \
  --input /path/to/stats.csv \
  --outdir /path/to/stats
```

Outputs:

- `coverage_corpus.svg`
- `throughput.svg`
- `exec_mix.svg`
- `signal_cover.svg`
- `pt_trace.svg`
- `windows_templates.svg`
- `summary.json`
- `index.html`

## Fullchain

`guest-vm/run-nyx-fullchain.sh --collect-stats` starts the collector
automatically and writes results under `guest-vm/runtime/stats/`.

## Compare

```bash
./bin/syz-nyx-stats compare \
  --inputs /path/to/run1.csv,/path/to/run2.csv,/path/to/run3.csv \
  --outdir /path/to/aggregate
```

Outputs:

- `aggregate_coverage_corpus.svg`
- `aggregate_throughput.svg`
- `aggregate_exec_mix.svg`
- `aggregate_signal_cover.svg`
- `aggregate_pt_trace.svg`
- `aggregate_windows_templates.svg`
- `aggregate_summary.json`
- `final_metrics.csv`
- `index.html`

## Collide Analysis

```bash
./bin/syz-nyx-stats collide-summary \
  --manager-log /path/to/fullchain-manager.log \
  --output /path/to/collide_summary.json
```

Summarizes `windows collide result` shapes by `origin` and active-call set.

```bash
./bin/syz-nyx-stats collide-quality \
  --manager-log /path/to/fullchain-manager.log \
  --output /path/to/collide_quality.json
```

Correlates collide events with later triage and corpus-save ownership, using
`trace=` IDs when present.

```bash
./bin/syz-nyx-stats collide-owners \
  --inputs /path/to/run1_collide_quality.json,/path/to/run2_collide_quality.json \
  --output /path/to/collide_owners.json
```

Aggregates collide owners across multiple runs to show which deep calls most
often survive into triage/corpus retention.

## AFD Focused Summary

```bash
./bin/syz-nyx-stats afd-summary \
  --manager-log /path/to/fullchain-manager.log \
  --runner-log /path/to/fullchain-runner.log \
  --output /path/to/afd_summary.json
```

Summarizes AFD-focused runs by call and category. The JSON separates deep
Winsock/mswsock owners from setup/helper calls, and includes triage jobs,
triage events, corpus saves, collide active calls, runner cover counts, hangs,
restarts, submitted module ranges, and manager aggregate counters such as
coverage, corpus, exec mix, template hits, and resource-centric hits. When the
runner emits per-slot module coverage, the summary also reports per-module hits
and `afd_module_hit_ratio`. Newer runner logs also include call-level module
coverage; when present, `call_stats` and `category_stats` include
`afd_module_*`, `ntos_module_*`, and total `module_*` counters so a run can show
which Winsock/mswsock calls actually produced AFD PCs. Runner call-feedback logs
also populate `exec_results`, `exec_raw_signal`, `exec_raw_cover`, and
`exec_comps` per call/category, separating ordinary execution feedback from
triage/corpus retention. The `owner_stats` rollup groups those counters into
deep, setup/helper, and other owners, making it quick to see whether feedback
and retention are still dominated by setup scaffolding. The request-level
`module_cover_classes` section separates AFD-hit, ntos-only, other-module,
unknown/user-mode, and no-cover executions, and the summary records hanged
request IDs plus VM restart reasons. Each module-cover class also includes
request, module-record, and PC ratios, so the JSON directly shows whether
feedback is mostly from AFD, ntos glue, some other kernel module, unknown/user
coverage, or no-cover executions.
Runner crash/failure diagnostics are also grouped under `failure_events`, so
Windows bugchecks, request failures, hangs, runner fatals, and VM start failures
can be compared without re-reading the full runner log. When the runner logs
program summaries, request-scoped failure events also include the failing
program's sha1, call count, first call, and call category, making it easier to
see whether hangs and restarts concentrate in async, lifecycle, accepted-data,
or setup programs. Newer runner summaries also include the first deep AFD call
as `deep0`; when present, failure attribution uses that field so async/cancel
programs that start with socket setup are not misclassified as setup failures.
The summary also embeds collide quality rows from the manager log. Each row
lists active calls/categories, whether the active set contains deep or setup
calls, and the follow-up triage/corpus owners, so a single AFD summary can show
whether collide actually reached deep AFD paths and whether those paths survived
into retention.
The companion `failure_category_stats` section rolls those attributable failures
up by AFD category, with hang/request-failure/crash/fatal counters, so a run can
answer whether restarts are concentrating in accepted-data, async/completion,
setup/helper, or another path.

```bash
./bin/syz-nyx-stats afd-compare \
  --inputs /path/to/run1_afd_summary.json,/path/to/run2_afd_summary.json \
  --output /path/to/afd_aggregate.json
```

Aggregates multiple AFD focused summaries to compare AFD module hit ratio,
deep/setup owner retention, owner distribution, module-cover classes, top
calls/categories, collide quality, hangs, restart reasons, failure events, and
failure category concentration across repeated runs. The aggregate
`collide_quality_summary` rolls up active collide shapes by run/count and keeps
the deep/setup active flags plus follow-up triage/corpus owners, so repeated
runs can show which collide combinations consistently retain deep AFD paths.
