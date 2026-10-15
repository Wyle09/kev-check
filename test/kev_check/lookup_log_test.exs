defmodule KevCheck.LookupLogTest do
  # Changes the global log level and fault knobs, so it can't run alongside other tests.
  use ExUnit.Case, async: false

  alias KevCheck.Faults
  alias KevCheck.Lookup

  # Tests read the structured log event, not formatted text: the text formatter
  # dev and test use leaves out metadata whose value is false.
  setup do
    # The test config logs warnings and up.
    Logger.configure(level: :info)
    :ok = :logger.add_handler(:lookup_log_test, __MODULE__, %{config: %{test_pid: self()}})

    on_exit(fn ->
      :logger.remove_handler(:lookup_log_test)
      Logger.configure(level: :warning)
      Faults.reset()
    end)
  end

  test "a listed ID logs at info with the CVE ID, the raw input, and the duration" do
    Lookup.run(" cve-2021-44228 ")

    assert {:info, "CVE-2021-44228 is on the KEV list", meta} = receive_lookup_log()

    assert %{
             outcome: :ok,
             cve_id: "CVE-2021-44228",
             raw_id: " cve-2021-44228 ",
             known_exploited: true,
             duration_ms: duration_ms
           } = meta

    assert is_float(duration_ms) and duration_ms >= 0
    refute Map.has_key?(meta, :reason)
  end

  test "an unlisted ID logs at info as not on the list" do
    Lookup.run("CVE-2023-99999")

    assert {:info, "CVE-2023-99999 is not on the KEV list", %{known_exploited: false}} =
             receive_lookup_log()
  end

  test "a rejected ID logs a warning with the reason and the raw input, and no CVE ID" do
    Lookup.run("123")

    assert {:warning, "rejected id: invalid_format", meta} = receive_lookup_log()
    assert %{outcome: :error, reason: :invalid_format, raw_id: "123"} = meta
    refute Map.has_key?(meta, :cve_id)
    refute Map.has_key?(meta, :known_exploited)
  end

  test "a missing ID logs without a raw_id" do
    Lookup.run(nil)

    assert {:warning, "rejected id: missing_id", meta} = receive_lookup_log()
    refute Map.has_key?(meta, :raw_id)
  end

  test "catalog trouble logs an error" do
    Faults.put(error_rate: 1.0)
    Lookup.run("CVE-2021-44228")

    assert {:error, "catalog unavailable", %{reason: :catalog_unavailable}} = receive_lookup_log()
  end

  test "raw input is capped at 64 bytes" do
    Lookup.run(String.duplicate("A", 500))

    assert {_level, _message, %{raw_id: raw_id}} = receive_lookup_log()
    assert raw_id == String.duplicate("A", 64)
  end

  test "the cap never splits a character" do
    # 63 ASCII bytes, then a 2-byte "é" that would straddle the 64-byte cap.
    Lookup.run(String.duplicate("A", 63) <> "é")

    assert {_level, _message, %{raw_id: raw_id}} = receive_lookup_log()
    assert raw_id == String.duplicate("A", 63)
  end

  test "input that isn't a string is logged as its inspected form" do
    Lookup.run(["CVE-2021-44228"])

    assert {_level, _message, %{raw_id: ~s(["CVE-2021-44228"])}} = receive_lookup_log()
  end

  test "the zero counts that create the counter series don't log, and the handler keeps working" do
    :ok = Lookup.emit_zero_counts()
    refute_received {:log_event, %{meta: %{event: "kev.process"}}}

    # A handler that raised would be detached, and this lookup wouldn't log.
    Lookup.run("CVE-2021-44228")
    assert {:info, "CVE-2021-44228 is on the KEV list", _meta} = receive_lookup_log()
  end

  test "the production formatter writes the line as one JSON object, request_id included" do
    Logger.metadata(request_id: "F-request-id")
    Lookup.run("CVE-2023-99999")
    assert_receive {:log_event, %{meta: %{event: "kev.process"}} = event}

    {formatter, config} = production_formatter()
    line = event |> formatter.format(config) |> IO.iodata_to_binary()

    assert String.ends_with?(line, "}\n")

    assert %{
             "severity" => "info",
             "message" => "CVE-2023-99999 is not on the KEV list",
             "metadata" => %{
               "request_id" => "F-request-id",
               "event" => "kev.process",
               "outcome" => "ok",
               "cve_id" => "CVE-2023-99999",
               "raw_id" => "CVE-2023-99999",
               "known_exploited" => false,
               "duration_ms" => duration_ms
             }
           } = JSON.decode!(line)

    assert is_number(duration_ms)
  end

  @doc false
  def log(event, %{config: %{test_pid: test_pid}}), do: send(test_pid, {:log_event, event})

  # The formatter config/runtime.exs builds for prod. That file raises without a
  # SECRET_KEY_BASE, so lend it one for the read.
  defp production_formatter do
    previous = System.get_env("SECRET_KEY_BASE")
    System.put_env("SECRET_KEY_BASE", String.duplicate("x", 64))

    try do
      prod = Config.Reader.read!(Path.expand("../../config/runtime.exs", __DIR__), env: :prod)
      prod[:logger][:default_handler][:formatter]
    after
      if previous,
        do: System.put_env("SECRET_KEY_BASE", previous),
        else: System.delete_env("SECRET_KEY_BASE")
    end
  end

  defp receive_lookup_log do
    assert_receive {:log_event, %{meta: %{event: "kev.process"}} = event}
    %{level: level, msg: {:string, message}, meta: meta} = event
    {level, IO.chardata_to_string(message), meta}
  end
end
