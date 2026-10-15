defmodule KevCheckWeb.MetricsTest do
  # Every test reads and moves the same global metrics.
  use KevCheckWeb.ConnCase, async: false

  import Plug.Test, only: [conn: 2]

  @outcome_series [
    ~s(kev_process_success_total{known_exploited="true"}),
    ~s(kev_process_success_total{known_exploited="false"}),
    ~s(kev_process_errors_total{reason="missing_id"}),
    ~s(kev_process_errors_total{reason="invalid_format"}),
    ~s(kev_process_errors_total{reason="year_out_of_range"}),
    ~s(kev_process_errors_total{reason="catalog_unavailable"})
  ]

  alias KevCheck.Catalog.Store
  alias KevCheck.Faults
  alias KevCheck.Lookup
  alias KevCheckWeb.MetricsPlug

  describe "after one good and one bad lookup" do
    setup %{conn: conn} do
      before = scrape()
      get(conn, "/process?id=CVE-2021-44228")
      get(build_conn(), "/process?id=123")
      %{before: before, after: scrape()}
    end

    test "the success counter counts the answer, labeled by the answer", %{before: b, after: a} do
      assert delta(b, a, ~s(kev_process_success_total{known_exploited="true"})) == 1
      assert delta(b, a, ~s(kev_process_success_total{known_exploited="false"})) == 0
    end

    test "the errors counter counts the rejection, labeled by the app's reason", %{
      before: b,
      after: a
    } do
      assert delta(b, a, ~s(kev_process_errors_total{reason="invalid_format"})) == 1
    end

    test "the histogram counts both lookups", %{before: b, after: a} do
      assert delta(b, a, "kev_process_duration_seconds_count") == 2
      assert delta(b, a, ~s(kev_process_duration_seconds_bucket{le="+Inf"})) == 2
      # Both lookups take microseconds, so they land in the 250ms bucket too.
      assert delta(b, a, ~s(kev_process_duration_seconds_bucket{le="0.25"})) == 2
      assert value(a, "kev_process_duration_seconds_sum") > 0
    end

    test "the request counter counts both, by method, route, and status", %{before: b, after: a} do
      assert delta(b, a, ~s(http_requests_total{method="GET",route="/process",status="200"})) == 1
      assert delta(b, a, ~s(http_requests_total{method="GET",route="/process",status="400"})) == 1
    end
  end

  describe "http_requests_total" do
    test "counts a crash once, as a 500 under its route" do
      # Make the store's catalog unreadable, so the lookup raises.
      {:ok, catalog} = Store.fetch()
      :persistent_term.put({Store, Store}, :not_a_catalog)
      on_exit(fn -> :persistent_term.put({Store, Store}, catalog) end)
      before = scrape()

      assert_error_sent 500, fn -> get(build_conn(), "/process?id=CVE-2021-44228") end

      assert delta(
               before,
               scrape(),
               ~s(http_requests_total{method="GET",route="/process",status="500"})
             ) == 1
    end

    test "counts a path that matches no route under one fixed label" do
      before = scrape()

      assert build_conn() |> get("/wp-login.php") |> response(404)

      assert delta(
               before,
               scrape(),
               ~s(http_requests_total{method="GET",route="unmatched",status="404"})
             ) == 1
    end

    test "counts a made-up method as OTHER, so clients can't mint new series" do
      before = scrape()

      assert build_conn() |> dispatch(@endpoint, "BREW", "/process") |> response(404)

      assert delta(
               before,
               scrape(),
               ~s(http_requests_total{method="OTHER",route="unmatched",status="404"})
             ) == 1
    end

    test "matches a percent-encoded path to its route, the way the router does" do
      before = scrape()

      assert build_conn() |> get("/proc%65ss?id=CVE-2021-44228") |> json_response(200)

      assert delta(
               before,
               scrape(),
               ~s(http_requests_total{method="GET",route="/process",status="200"})
             ) == 1
    end

    test "counts HEAD as GET, both after the router and before it" do
      before = scrape()

      assert build_conn() |> head("/healthz") |> response(200)
      assert_error_sent 400, fn -> head(build_conn(), "/process?id=%FF") end
      after_scrape = scrape()

      assert delta(
               before,
               after_scrape,
               ~s(http_requests_total{method="GET",route="/healthz",status="200"})
             ) == 1

      assert delta(
               before,
               after_scrape,
               ~s(http_requests_total{method="GET",route="/process",status="400"})
             ) == 1
    end

    test "counts health checks under their own route", %{conn: conn} do
      before = scrape()
      get(conn, "/healthz")

      assert delta(
               before,
               scrape(),
               ~s(http_requests_total{method="GET",route="/healthz",status="200"})
             ) == 1
    end

    test "counts a request a plug rejects before the router, and the app's counters don't move" do
      before = scrape()

      # %FF isn't valid UTF-8, so Plug.Parsers answers 400 before the controller runs.
      assert_error_sent 400, fn -> get(build_conn(), "/process?id=%FF") end
      after_scrape = scrape()

      assert delta(
               before,
               after_scrape,
               ~s(http_requests_total{method="GET",route="/process",status="400"})
             ) == 1

      assert delta(before, after_scrape, "kev_process_duration_seconds_count") == 0
    end
  end

  test "the histogram records seconds: a 75ms lookup lands in the 0.1 bucket, not 0.05" do
    before = scrape()

    :telemetry.execute(
      [:kev_check, :process, :stop],
      %{duration: System.convert_time_unit(75, :millisecond, :native)},
      %{outcome: :ok, known_exploited: true, cve_id: "CVE-2021-44228", raw_id: "CVE-2021-44228"}
    )

    after_scrape = scrape()

    assert delta(before, after_scrape, ~s(kev_process_duration_seconds_bucket{le="0.05"})) == 0
    assert delta(before, after_scrape, ~s(kev_process_duration_seconds_bucket{le="0.1"})) == 1
    assert_in_delta delta(before, after_scrape, "kev_process_duration_seconds_sum"), 0.075, 1.0e-6
  end

  test "the catalog gauges report the size and age of the catalog this node serves" do
    :ok = Store.emit_stats()
    scrape = scrape()

    # The fixture's dateReleased.
    expected_age = DateTime.diff(DateTime.utc_now(), ~U[2026-10-14 19:27:28.0105Z])

    assert value(scrape, "kev_catalog_entries") == 2
    assert_in_delta value(scrape, "kev_catalog_age_seconds"), expected_age, 5
    assert scrape =~ "# TYPE kev_catalog_age_seconds gauge"
  end

  test "the VM gauges map the poller's measurements" do
    :telemetry.execute([:vm, :memory], %{total: 123_456}, %{})
    :telemetry.execute([:vm, :total_run_queue_lengths], %{total: 3, cpu: 3, io: 0}, %{})
    scrape = scrape()

    assert value(scrape, "vm_memory_total_bytes") == 123_456
    assert value(scrape, "vm_run_queue_length") == 3
  end

  test "every metric has the type Prometheus expects" do
    get(build_conn(), "/process?id=CVE-2021-44228")
    get(build_conn(), "/process?id=123")
    :ok = Store.emit_stats()
    scrape = scrape()

    for {name, type} <- [
          {"kev_process_duration_seconds", "histogram"},
          {"kev_process_success_total", "counter"},
          {"kev_process_errors_total", "counter"},
          {"kev_catalog_age_seconds", "gauge"},
          {"kev_catalog_entries", "gauge"},
          {"http_requests_total", "counter"}
        ] do
      assert scrape =~ "# TYPE #{name} #{type}\n"
    end
  end

  describe "the outcome counters" do
    setup do
      # A second reporter with the app's metric list, so these tests see series that
      # are born here, not ones earlier tests already created.
      start_supervised!(
        {TelemetryMetricsPrometheus.Core,
         name: :fresh_reporter, metrics: KevCheckWeb.Telemetry.metrics(), start_async: false}
      )

      on_exit(&Faults.reset/0)
    end

    test "start at 0 for every outcome, and the zeros skip the histogram" do
      :ok = Lookup.emit_zero_counts()
      scrape = scrape(:fresh_reporter)

      assert outcome_series(scrape) == Enum.sort(Enum.map(@outcome_series, &{&1, 0}))
      refute scrape =~ "kev_process_duration_seconds"
    end

    test "every outcome a lookup can end in is one of those series" do
      :ok = Lookup.emit_zero_counts()

      for raw_id <- ["CVE-2021-44228", "CVE-2023-99999", nil, "123", "CVE-2099-0001"],
          do: Lookup.run(raw_id)

      Faults.put(error_rate: 1.0)
      Lookup.run("CVE-2021-44228")

      assert outcome_series(scrape(:fresh_reporter)) ==
               Enum.sort(Enum.map(@outcome_series, &{&1, 1}))
    end

    test "the app's poller sends the zeros" do
      assert {Lookup, :emit_zero_counts, []} in :telemetry_poller.list_measurements(
               :kev_check_poller
             )
    end
  end

  describe "MetricsPlug" do
    test "serves GET /metrics in the Prometheus text format" do
      conn = MetricsPlug.call(conn(:get, "/metrics"), [])

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/plain; version=0.0.4; charset=utf-8"]
      assert conn.resp_body =~ "# TYPE"
    end

    test "answers 404 for any other path or method" do
      assert MetricsPlug.call(conn(:get, "/"), []).status == 404
      assert MetricsPlug.call(conn(:get, "/process"), []).status == 404
      assert MetricsPlug.call(conn(:post, "/metrics"), []).status == 404
    end
  end

  defp scrape(reporter \\ :prometheus_metrics),
    do: TelemetryMetricsPrometheus.Core.scrape(reporter)

  # Every success and error line in a scrape, sorted. A list, not a map, so a series
  # exported twice (a seed label with the wrong type) shows up as a duplicate.
  defp outcome_series(scrape) do
    for line <- String.split(scrape, "\n"),
        String.starts_with?(line, ["kev_process_success_total{", "kev_process_errors_total{"]) do
      [series, number] = String.split(line, " ")
      {series, parse(number)}
    end
    |> Enum.sort()
  end

  defp delta(before, after_scrape, series),
    do: value(after_scrape, series) - value(before, series)

  # The sample value for one exact series line, or 0 before the series exists.
  defp value(scrape, series) do
    prefix = series <> " "

    scrape
    |> String.split("\n")
    |> Enum.find_value(0, fn line ->
      if String.starts_with?(line, prefix),
        do: line |> String.replace_prefix(prefix, "") |> parse()
    end)
  end

  defp parse(number) do
    case Integer.parse(number) do
      {integer, ""} -> integer
      _float -> String.to_float(number)
    end
  end
end
