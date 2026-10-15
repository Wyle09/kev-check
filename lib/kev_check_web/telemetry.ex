defmodule KevCheckWeb.Telemetry do
  @moduledoc """
  Every Prometheus metric the app exposes, plus the reporter that holds them and a
  poller that, every 10 seconds, refreshes the catalog gauges and adds 0 to every
  outcome counter. The `vm_*` gauges come from telemetry_poller's default poller,
  which runs on its own every 5 seconds.
  """

  use Supervisor

  import Telemetry.Metrics

  # Seconds. Dense under 25ms, where normal lookups land, with an edge at 250ms,
  # the latency threshold the alerts use.
  @latency_buckets [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]

  @doc "Start the reporter and the poller."
  @spec start_link(term()) :: Supervisor.on_start()
  def start_link(arg), do: Supervisor.start_link(__MODULE__, arg, name: __MODULE__)

  @impl true
  def init(_arg) do
    children = [
      # start_async: false attaches every handler before the endpoint takes traffic.
      {TelemetryMetricsPrometheus.Core, metrics: metrics(), start_async: false},
      # Adding 0 to the outcome counters again and again is harmless, and it brings the
      # series back if the reporter ever restarts with empty tables.
      {:telemetry_poller,
       measurements: [
         {KevCheck.Catalog.Store, :emit_stats, []},
         {KevCheck.Lookup, :emit_zero_counts, []}
       ],
       period: 10_000,
       name: :kev_check_poller}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  @doc "The metric definitions, in `Telemetry.Metrics` form."
  @spec metrics() :: [Telemetry.Metrics.t()]
  def metrics do
    [
      distribution("kev.process.duration.seconds",
        event_name: [:kev_check, :process, :stop],
        measurement: :duration,
        unit: {:native, :second},
        reporter_options: [buckets: @latency_buckets],
        description: "Time to answer one /process lookup, including injected latency."
      ),
      # Sums of :count rather than counters, so Lookup.emit_zero_counts/0 can create
      # each series at 0. Prometheus still sees counters.
      sum("kev.process.success.total",
        event_name: [:kev_check, :process, :stop],
        measurement: :count,
        keep: &match?(%{outcome: :ok}, &1),
        tags: [:known_exploited],
        description: "Lookups that got an answer, split by whether the CVE is on the list."
      ),
      sum("kev.process.errors.total",
        event_name: [:kev_check, :process, :stop],
        measurement: :count,
        keep: &match?(%{outcome: :error}, &1),
        tags: [:reason],
        description: "Lookups that couldn't be answered, by app-level reason."
      ),
      last_value("kev.catalog.age.seconds",
        event_name: [:kev_check, :catalog],
        measurement: :age_seconds,
        description: "Seconds since CISA released the catalog this pod serves."
      ),
      last_value("kev.catalog.entries",
        event_name: [:kev_check, :catalog],
        measurement: :entries,
        description: "Vulnerabilities in the catalog this pod serves."
      ),
      # RequestTelemetry emits this once per response, from the two places Phoenix
      # reports one.
      counter("http.requests.total",
        event_name: [:kev_check, :http, :request],
        tags: [:method, :route, :status],
        description: "HTTP requests by method, route, and status code."
      ),
      last_value("vm.memory.total.bytes",
        event_name: [:vm, :memory],
        measurement: :total,
        description: "Bytes the BEAM has allocated."
      ),
      last_value("vm.run_queue.length",
        event_name: [:vm, :total_run_queue_lengths],
        measurement: :total,
        description:
          "Processes waiting for a scheduler. Sustained growth means the node is CPU bound."
      )
    ]
  end
end
