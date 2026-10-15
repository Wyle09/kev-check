defmodule KevCheck.Faults do
  @moduledoc """
  Demo knobs that slow `/process` down or make the catalog look unavailable, so the
  histogram and the alerts have something to show.

  Settings live in `:persistent_term`. Change them on a running pod with
  `bin/kev_check rpc 'KevCheck.Faults.put(latency_ms: 400)'`.
  """

  @key {__MODULE__, :settings}
  @defaults %{latency_ms: 0, error_rate: 0.0}

  @type settings :: %{latency_ms: non_neg_integer(), error_rate: float()}

  @doc "The settings in effect, falling back to the boot values from config. Bad boot values raise."
  @spec current() :: settings()
  def current, do: :persistent_term.get(@key, nil) || boot_settings()

  @doc "Change one or both knobs and return the new settings. Bad values raise."
  @spec put(keyword()) :: settings()
  def put(changes) when is_list(changes) do
    settings = Enum.reduce(changes, current(), &change/2)
    :persistent_term.put(@key, settings)
    settings
  end

  @doc "Drop live changes and go back to the boot values."
  @spec reset() :: settings()
  def reset do
    :persistent_term.erase(@key)
    current()
  end

  @doc "Sleep a random 0 to `latency_ms`, then fail with probability `error_rate`."
  @spec inject() :: :ok | {:error, :catalog_unavailable}
  def inject do
    %{latency_ms: latency_ms, error_rate: error_rate} = current()
    sleep_up_to(latency_ms)
    fail_with_probability(error_rate)
  end

  defp change({:latency_ms, ms}, settings) when is_integer(ms) and ms >= 0,
    do: %{settings | latency_ms: ms}

  defp change({:error_rate, rate}, settings) when is_number(rate) and rate >= 0 and rate <= 1,
    do: %{settings | error_rate: rate * 1.0}

  defp sleep_up_to(0), do: :ok
  defp sleep_up_to(ms), do: Process.sleep(:rand.uniform(ms + 1) - 1)

  defp fail_with_probability(rate) do
    if :rand.uniform() < rate, do: {:error, :catalog_unavailable}, else: :ok
  end

  defp boot_settings do
    :kev_check
    |> Application.get_env(__MODULE__, [])
    |> Enum.reduce(@defaults, &change/2)
  end
end
