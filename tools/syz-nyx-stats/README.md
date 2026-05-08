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
- `signal_cover.svg`
- `pt_trace.svg`
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
- `aggregate_signal_cover.svg`
- `aggregate_pt_trace.svg`
- `aggregate_summary.json`
- `final_metrics.csv`
- `index.html`
