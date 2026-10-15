defmodule KevCheck.Catalog.StoreTest do
  # The app's store and its telemetry event are global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias KevCheck.Catalog.Store
  alias KevCheck.Core.Catalog

  @fixture_path Path.expand("../../support/fixtures/kev_fixture.json", __DIR__)

  test "fetch/0 returns the catalog the app booted with" do
    assert {:ok, %Catalog{version: "2026.10.14"} = catalog} = Store.fetch()
    assert Catalog.size(catalog) == 2
  end

  test "fetch/1 says the catalog is unavailable for a store that never started" do
    assert Store.fetch(:never_started) == {:error, :catalog_unavailable}
  end

  test "emit_stats/0 reports the catalog's size, age, and version" do
    :telemetry.attach("store-test", [:kev_check, :catalog], &__MODULE__.forward/4, self())
    on_exit(fn -> :telemetry.detach("store-test") end)

    assert Store.emit_stats() == :ok

    assert_received {[:kev_check, :catalog], %{entries: 2, age_seconds: age},
                     %{version: "2026.10.14"}}

    assert age > 0
  end

  test "the bundled snapshot parses into the full catalog" do
    path = Application.app_dir(:kev_check, "priv/kev/known_exploited_vulnerabilities.json")

    assert {:ok, catalog} = path |> File.read!() |> Catalog.parse()
    assert Catalog.size(catalog) > 1_700
  end

  describe "refresh" do
    test "swaps in a valid feed, even though CISA serves it as application/json" do
      feed =
        @fixture_path |> File.read!() |> JSON.decode!() |> Map.put("catalogVersion", "2026.10.15")

      log_info_for_this_test()

      log = capture_log(fn -> refresh_with(:refresh_ok, &Req.Test.json(&1, feed)) end)

      assert {:ok, %Catalog{version: "2026.10.15"}} = Store.fetch(:refresh_ok)

      assert log =~
               "serving KEV catalog 2026.10.15 with 2 entries from http://cisa.test/feed.json"
    end

    test "keeps the current catalog after an HTTP error" do
      assert_kept(:refresh_503, &Plug.Conn.send_resp(&1, 503, "Service Unavailable"), "HTTP 503")
    end

    test "keeps the current catalog after a page that isn't a feed" do
      assert_kept(
        :refresh_html,
        &Req.Test.html(&1, "<html>maintenance</html>"),
        "the feed isn't a valid catalog"
      )
    end

    test "keeps the current catalog after a network failure" do
      assert_kept(
        :refresh_down,
        &Req.Test.transport_error(&1, :econnrefused),
        "connection refused"
      )
    end
  end

  describe "start_link/1 fails the boot" do
    bad_settings = [
      {"a URL with no scheme", [refresh_url: "www.cisa.gov/feed.json"]},
      {"a non-HTTP URL", [refresh_url: "ftp://www.cisa.gov/feed.json"]},
      {"an empty URL", [refresh_url: ""]},
      {"a zero refresh interval",
       [refresh_url: "https://www.cisa.gov/feed.json", refresh_interval_ms: 0]}
    ]

    for {name, settings} <- bad_settings do
      test "on #{name}" do
        opts = [name: :bad_settings] ++ unquote(settings)

        capture_log(fn ->
          assert {:error, _reason} = start_supervised({Store, opts})
        end)

        assert Store.fetch(:bad_settings) == {:error, :catalog_unavailable}
      end
    end

    test "on a snapshot that isn't a catalog" do
      path =
        Path.join(
          System.tmp_dir!(),
          "kev-not-a-catalog-#{System.unique_integer([:positive])}.json"
        )

      File.write!(path, "{}")
      on_exit(fn -> File.rm(path) end)

      capture_log(fn ->
        assert {:error, _reason} =
                 start_supervised({Store, name: :bad_snapshot, snapshot_path: path})
      end)
    end
  end

  @doc false
  def forward(event, measurements, metadata, test_pid),
    do: send(test_pid, {event, measurements, metadata})

  defp assert_kept(name, plug, reason) do
    log = capture_log(fn -> refresh_with(name, plug) end)

    assert {:ok, %Catalog{version: "2026.10.14"}} = Store.fetch(name)
    assert log =~ "KEV refresh failed, keeping the current catalog: #{reason}"
  end

  # The test config logs warnings and up, and capture_log can't go below that.
  defp log_info_for_this_test do
    Logger.configure(level: :info)
    on_exit(fn -> Logger.configure(level: :warning) end)
  end

  # Starts a second store under its own name, so the app's catalog stays untouched,
  # then runs one refresh against `plug` instead of the network.
  defp refresh_with(name, plug) do
    store =
      start_supervised!(
        {Store,
         name: name,
         refresh_url: "http://cisa.test/feed.json",
         req_options: [plug: plug, retry: false]},
        id: name
      )

    send(store, :refresh)
    _ = :sys.get_state(store)
    :ok
  end
end
