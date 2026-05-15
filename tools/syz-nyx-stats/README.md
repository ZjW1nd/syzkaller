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
