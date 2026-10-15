# KEV check

KEV check answers one question: is this CVE on CISA's Known Exploited Vulnerabilities list, the vulnerabilities attackers are already using? `GET /process?id=CVE-2021-44228` says yes, with the vendor, product, and patch due date. An ID that isn't listed gets a no, which still counts as a success. Only junk input or a missing catalog is an error.

It's a small service built to be observed. The app exposes Prometheus metrics and one JSON log line per lookup. It runs as two copies behind nginx, with a local Prometheus and Alertmanager. A Chronosphere roll-up rule for its request counter is in [`chronosphere/`](chronosphere/), and [Chronosphere](#chronosphere) below explains it. Outputs here are from a real run on 2026-10-15.

## Run it

You need Docker Desktop. The stack needs one secret, `SECRET_KEY_BASE`, because a Phoenix release won't boot without it. If you use 1Password, keep it in an item called `kev-check` in your `Private` vault and copy the reference file:

```bash
cp op.env.example op.env
```

The Makefile then wraps every Compose command in `op run`, so the value never touches disk. Set `OP_ACCOUNT` if your 1Password CLI has more than one account. Without 1Password, put a value in `.env`:

```bash
echo "SECRET_KEY_BASE=$(openssl rand -base64 48)" > .env
```

Then start everything:

```bash
make up
```

The first build takes about 20 seconds once the base images are pulled. Each copy boots on the catalog snapshot in `priv/kev/`, pulls CISA's live feed 5 seconds later, and refreshes every 6 hours.

- API: http://localhost:8080/process?id=CVE-2021-44228
- Prometheus: http://localhost:9090
- Alertmanager: http://localhost:9093

```bash
curl -s 'localhost:8080/process?id=CVE-2021-44228' | jq -c '{cve_id, known_exploited, vendor, product, due_date}'
```

```json
{"cve_id":"CVE-2021-44228","known_exploited":true,"vendor":"Apache","product":"Log4j2","due_date":"2021-12-24"}
```

```bash
curl -s 'localhost:8080/process?id=CVE-2023-99999'
```

```json
{"catalog_version":"2026.10.15","cve_id":"CVE-2023-99999","known_exploited":false}
```

```bash
curl -s -w ' %{http_code}\n' 'localhost:8080/process?id=123'
```

```text
{"error":"invalid_format","message":"Expected an ID shaped like CVE-YYYY-NNNN."} 400
```

`make help` lists every target. The demo uses `make faults`, `make faults-reset`, `make kill-pod`, `make scale N=4`, `make metrics`, and `make logs`. `make down` stops everything and keeps Prometheus's history, and `make clean` deletes it too.

To run it without Docker you need Elixir 1.18 or later. Run `mix setup`, then `mix phx.server`, and the API is on port 4000 with metrics on 9568. `make check` runs the formatter, the compiler with warnings as errors, Credo, the 111 tests, and Dialyzer, all inside Docker.

## What it measures

One telemetry span wraps each lookup. Its stop event feeds the histogram, both counters, and the log line, so they all describe the same lookup with the same duration. Metrics are served on their own port, 9568, so no public route exposes them.

| Signal | Metric | Why this type |
|---|---|---|
| Histogram | `kev_process_duration_seconds` | Bucket counts add up across copies, so a fleet-wide p95 is real |
| Success counter | `kev_process_success_total{known_exploited}` | It only goes up, and `rate()` turns it into lookups per second across restarts |
| Error counter | `kev_process_errors_total{reason}` | Counts the app's own verdict (`invalid_format`, `missing_id`, `year_out_of_range`, `catalog_unavailable`), not the HTTP status |
| Gauge | `kev_catalog_age_seconds` | How stale the threat data is right now. It drops when a refresh lands, so it can't be a counter |
| Log line | One JSON object per lookup | Carries the CVE ID and the raw input, which don't belong in metrics |

The CVE ID never goes in a label. Every new label value is a new series, and anyone can send a new ID with every request, so a `cve_id` label would grow without limit. Logs handle that fine:

```json
{"message":"CVE-2021-44228 is on the KEV list","time":"2026-10-15T21:13:18.549Z","metadata":{"request_id":"GN7QXMDIGC6Z4rgAAZbB","event":"kev.process","cve_id":"CVE-2021-44228","known_exploited":true,"outcome":"ok","raw_id":"cve-2021-44228","duration_ms":19.869},"severity":"info"}
```

`http_requests_total{method, route, status}` counts every response. The alerts read it, and it's the metric the roll-up rule targets.

## Two PromQL queries

How slow are the slowest 5% of lookups:

```promql
histogram_quantile(0.95, sum by (env, le) (rate(kev_process_duration_seconds_bucket[5m])))
```

`rate` turns each copy's bucket counters into per-second rates, `sum by (env, le)` adds the copies together while keeping the buckets, and `histogram_quantile` estimates the 95th percentile. Normal is about 0.030, or 30 ms. After `make faults LATENCY_MS=400` it reached about 0.4 within three minutes.

What share of lookups couldn't be answered:

```promql
sum by (env) (rate(kev_process_errors_total[5m]))
/
(sum by (env) (rate(kev_process_errors_total[5m])) + sum by (env) (rate(kev_process_success_total[5m])))
```

Normal is 0.20, all of it bad input from the load generator, since 4 of the 20 IDs it sends are junk. That's why the paging alerts read 5xx from `http_requests_total` instead. A client sending junk isn't our outage. `sum by (reason) (rate(kev_process_errors_total[5m]))` shows which kind of error it was.

## Chronosphere

The roll-up rule removes `pod` and `instance` from `http_requests_total` in `env:production`, drops the raw data, and stores one point every 60 seconds. It's in `chronosphere/rollup-http-requests-total.yaml`:

```yaml
api_version: v1/config
kind: RollupRule
spec:
  slug: http-requests-total-production-without-pod-instance
  name: http_requests_total in production without pod and instance
  filters:
    - name: __name__
      value_glob: http_requests_total
    - name: env
      value_glob: production
  metric_name: '{{ .MetricName }}:without_pod_instance'
  metric_type: CUMULATIVE_COUNTER
  aggregation: SUM
  interval: 60s
  label_policy:
    discard:
      - pod
      - instance
  drop_raw: true
  add_metric_type_label: true
  mode: ENABLED
```

It matches series named `http_requests_total` that carry `env=production`. Every 60 seconds it takes each series' increase, adds those up across all the series that collapse together once `pod` and `instance` are gone, and stores the result as a counter called `http_requests_total:without_pod_instance`. `discard` keeps every other label (`method`, `route`, `status`, `env`, `job`). `drop_raw: true` means the per-pod input is never stored. I checked every field against Chronosphere's API reference, since I don't have a tenant to apply it to.

The catch is the name. With `drop_raw`, anything still querying `http_requests_total{env="production"}` goes empty the moment the rule turns on, dashboards and alerts included. So I'd roll it out in `mode: PREVIEW` first, which reports the impact without changing stored data. Then I'd point dashboards and alerts at the new name and switch to `ENABLED`.

The saving shows up locally too. A recording rule in `ops/prometheus/rules.yml` approximates the roll-up. `count(http_requests_total{env="production"})` is 6 (2 copies times 3 status codes), and the rolled-up version is 3. Scaling to 4 copies took the raw count from 7 to 13 in my test, and the rolled-up count stayed at 4. On Kubernetes every deploy brings new pod names and a fresh set of series, which is where most of the saving comes from.

What it costs: once the raw data is dropped, long-term storage can't tell you which pod was slow. I'd keep per-pod detail in short local retention for debugging and let Chronosphere keep the fleet view.

The four rule types, and when I'd use each:

- Drop rule: throws matching series away as they arrive. `chronosphere/drop-health-checks.yaml` drops `/healthz` request counts, which Kubernetes probes generate forever and nobody graphs. It ships in `PREVIEW`.
- Roll-up rule: aggregates as data arrives, before it's stored. It's the only one of the four that cuts what's stored and keeps the data useful.
- Recording rule: runs a query on a schedule and stores the result next to the raw data. It's good for an expensive dashboard query, but it can't save storage, because the raw data has to be stored first. It also misses samples that arrive late.
- Derived metric: a saved query with a name, computed when someone reads it, so nothing extra is stored. `chronosphere/derived-error-ratio.yaml` saves query 2 above as `kev_check_error_ratio`.

## How the histogram tracks latency

Prometheus stores histogram buckets cumulatively. `le="0.025"` counts every lookup at or under 25 ms, and `le="+Inf"` is the total. The edges are 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, and 2500 ms. They're dense under 25 ms because the stack simulates 0 to 25 ms of work per lookup (a real lookup takes microseconds). There's an edge at 250 ms because that's the latency SLO, and the slow-lookup alert reads that bucket directly: the share over 250 ms is `1 - bucket{le="0.25"} / count`.

`histogram_quantile` finds the bucket the percentile falls in and assumes values are spread evenly inside it. At 21:17 UTC the fleet did 8.105 lookups a second, so p95 is lookup number 7.700 of them. The 25 ms bucket held 7.600 and the 50 ms bucket 8.105, so p95 sits 0.100 / 0.505 = 20% of the way from 25 to 50 ms, which is 29.9 ms. Prometheus said 29.948. The true value is probably nearer 25 ms, since the simulated work tops out there, but the error can never exceed the bucket's width.

I picked a histogram over a summary because bucket counts from different copies add up. Quantiles from a summary are computed inside each copy and can't be combined.

## Alerting

Page on what users feel, ticket on causes, and alert on the whole fleet, never on one pod.

| Alert | Fires when | Severity |
|---|---|---|
| `KevCheckErrorBudgetFastBurn` | More than 1.44% of requests return a 5xx, over both 5 minutes and 1 hour | page |
| `KevCheckErrorBudgetSlowBurn` | More than 0.6%, over both 30 minutes and 6 hours | ticket |
| `KevCheckSlowLookups` | More than 5% of lookups take over 250 ms, over 5 minutes | page |
| `KevCheckCatalogStale` | Any copy's catalog is more than 7 days old | ticket |
| `KevCheckMetricsMissing` | No production target has been up for 5 minutes | page |

The SLO is my pick: 99.9% of requests succeed and 95% finish within 250 ms. The burn-rate thresholds come from the Google SRE workbook. 1.44% is 14.4 times the 0.1% the SLO allows, a rate that spends a month's budget in about two days. The short window makes the alert fire fast, and the long window keeps one bad minute from paging anyone.

Every rule groups by `env`, so the alerts keep working after the roll-up removes `pod`. Alertmanager sends pages to a `pager` receiver and tickets to `tickets` (both empty locally), and mutes the slow-burn ticket while the fast burn is paging. A `Watchdog` alert always fires, so if it ever disappears, alerting itself is broken.

In a test run with a clean hour of history, the fast burn fired 8 minutes after `make faults ERROR_RATE=0.2`, and slow lookups 4 minutes after `make faults LATENCY_MS=400`. The fast burn waits on the 1 hour ratio, which took 6 minutes to pass 1.44%. The paging alerts wait 2 minutes so they fire during a demo. In production I'd use 5 or more.

## Many copies and many services

Prometheus finds the app containers through the Docker socket. It labels each series with `pod` (the container name), `instance` (its IP and port), and `env` (a container label). `make scale N=4` adds targets with no config change.

Adding copies up correctly means `rate()` before `sum()`. A counter resets when its copy restarts, and `rate()` handles that one series at a time. In a `make kill-pod` test, one copy's counter dropped from 2,010 to 35. `sum(rate(...))` stayed between 6.4 and 6.8 lookups a second, while `rate(sum(...))` jumped to 50 for a full minute.

Past one Prometheus, I'd run one per cluster and `remote_write` to Chronosphere for the global view and long retention, with roll-up rules removing `pod` before storage.

With more services I'd add OpenTelemetry. Every service would get the same rate, error, and duration metrics with the same labels, and W3C trace context on every call, so one request becomes one trace. Exemplars would link a slow histogram bucket to a trace that landed in it. An OpenTelemetry Collector would batch, sample, and forward everything to Chronosphere.

## Drive the demo from Livebook

<!-- livebook: replace this section once livebook/tour.livemd exists, and bring the Demo walkthrough in line with the notebook's sections. -->

The Livebook tour isn't in the repo yet. Until it is, the walkthrough below is the whole demo.

## Demo walkthrough

Start `make up` an hour before, so the 1 hour alert windows have data.

1. `curl` a listed ID, an unlisted one, and `123`. A no is still an answer, and `123` is an app-level error.
2. Open `lib/kev_check/lookup.ex` and `lib/kev_check_web/telemetry.ex`. One span feeds five signals, and the CVE ID stays in logs.
3. `make metrics`: cumulative buckets, `_sum`, and `_count`.
4. Prometheus target health: where `pod`, `instance`, and `env` come from.
5. Query 1, then `make faults ERROR_RATE=0.2`. Start the fault now, because the page takes about 8 minutes.
6. Query 2 by reason. `catalog_unavailable` appears next to the bad input.
7. The Alerts page, then Alertmanager. The fast burn goes Pending, then Firing, routed to `pager`.
8. `make faults-reset`, then `make faults LATENCY_MS=400`. p95 climbs, and slow lookups fires about 4 minutes later.
9. `make faults-reset`, then `make kill-pod`. Graph `sum(rate(kev_process_success_total[1m]))` next to `rate(sum(kev_process_success_total)[1m:15s])`.
10. The series counts, then the `chronosphere/` files: roll-up versus recording, derived, and drop, `PREVIEW` first, and the naming catch.
11. Open discussion: limits and what I'd do next.

A slow-burn ticket shows up about 17 minutes after step 5. The 6 hour window only holds the history the stack has, so a short burst reads as a big share. It's not a bad rule.

## Limits and what I'd do next

- It runs on Docker Compose on one laptop, not Kubernetes. Container names don't change between deploys here, so the series churn that makes roll-ups pay off doesn't show.
- The Chronosphere rules have never been applied. The next step is a real tenant, in `PREVIEW`.
- After the roll-up, long-term data can't answer "which pod?".
- The latency is simulated.
- There's one environment, so every `by (env)` query has one line.
- No traces yet.
- Alertmanager's receivers go nowhere.
- Prometheus mounts the Docker socket. That's fine on a laptop and not in production.

## Code layout

`lib/kev_check/core/` is pure code: it parses an ID, parses CISA's feed, and answers a lookup. Everything that holds state or does I/O sits around it, and the `boundary` library fails the build if the core calls Req or Jason. Start reading at `lib/kev_check/lookup.ex`. The Prometheus and Alertmanager config is in `ops/`, and `make reload` runs the rule tests in `ops/prometheus/rules_test.yml` before reloading Prometheus.

## Sources

- Chronosphere: [roll-up rules](https://docs.chronosphere.io/control/shaping/rules/rollup), [drop rules](https://docs.chronosphere.io/control/shaping/rules/drop-rules), [recording rules](https://docs.chronosphere.io/control/shaping/rules/recording), [derived metrics](https://docs.chronosphere.io/investigate/querying/metrics/derived-telemetry/derived-metrics)
- Prometheus: [histograms and summaries](https://prometheus.io/docs/practices/histograms/)
- Google SRE workbook: [alerting on SLOs](https://sre.google/workbook/alerting-on-slos/)
- CISA: [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
