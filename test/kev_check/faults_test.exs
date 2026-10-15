defmodule KevCheck.FaultsTest do
  # The knobs are global, so these tests can't run alongside lookups.
  use ExUnit.Case, async: false

  alias KevCheck.Faults

  @boot %{latency_ms: 0, error_rate: 0.0}

  setup do
    on_exit(&Faults.reset/0)
  end

  test "current/0 starts at the boot values from config" do
    assert Faults.current() == @boot
  end

  test "put/1 changes one knob and keeps the other" do
    assert Faults.put(latency_ms: 400) == %{latency_ms: 400, error_rate: 0.0}
    assert Faults.put(error_rate: 1) == %{latency_ms: 400, error_rate: 1.0}
    assert Faults.current() == %{latency_ms: 400, error_rate: 1.0}
  end

  for bad <- [[latency_ms: -1], [latency_ms: 1.5], [error_rate: 2], [error_rate: -0.1], [typo: 1]] do
    test "put/1 rejects #{inspect(bad)} and changes nothing" do
      Faults.put(latency_ms: 10)

      assert_raise FunctionClauseError, fn -> Faults.put(unquote(bad)) end
      assert Faults.current() == %{latency_ms: 10, error_rate: 0.0}
    end
  end

  test "reset/0 drops live changes and returns the boot values" do
    Faults.put(latency_ms: 400, error_rate: 0.5)

    assert Faults.reset() == @boot
    assert Faults.current() == @boot
  end

  test "bad boot values raise, which is how the app refuses to start with them" do
    boot_config = Application.fetch_env!(:kev_check, Faults)
    on_exit(fn -> Application.put_env(:kev_check, Faults, boot_config) end)

    Application.put_env(:kev_check, Faults, latency_ms: -5, error_rate: 0.0)

    assert_raise FunctionClauseError, &Faults.reset/0
  end

  test "inject/0 always fails at rate 1 and never at rate 0" do
    Faults.put(error_rate: 1.0)
    assert Enum.all?(1..100, fn _ -> Faults.inject() == {:error, :catalog_unavailable} end)

    Faults.put(error_rate: 0.0)
    assert Enum.all?(1..100, fn _ -> Faults.inject() == :ok end)
  end

  test "inject/0 sleeps a random 0 to latency_ms" do
    Faults.put(latency_ms: 20)

    {micros, :ok} = :timer.tc(fn -> Enum.each(1..20, fn _ -> Faults.inject() end) end)

    # 20 sleeps average 200ms. Under 50ms is more than five standard deviations out,
    # and the ceiling is 20 full sleeps plus room for scheduler jitter.
    assert micros > 50_000
    assert micros < 20 * 20_000 + 100_000
  end
end
