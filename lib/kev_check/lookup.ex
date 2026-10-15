defmodule KevCheck.Lookup do
  @moduledoc """
  Runs one KEV check inside a `[:kev_check, :process]` telemetry span. The
  histogram, both counters, and the log line all hang off the span's stop event.

  The poller also sends that event with `%{count: 0}` and no duration, through
  `emit_zero_counts/0`, so every handler on it has to accept that shape.
  """

  alias KevCheck.Catalog.Store
  alias KevCheck.Core.Catalog
  alias KevCheck.Core.CveId
  alias KevCheck.Faults

  @type reason :: CveId.reason() | :catalog_unavailable

  # Every outcome a lookup can end in, which is every label set the two counters have.
  @outcomes [
    %{outcome: :ok, known_exploited: true},
    %{outcome: :ok, known_exploited: false},
    %{outcome: :error, reason: :missing_id},
    %{outcome: :error, reason: :invalid_format},
    %{outcome: :error, reason: :year_out_of_range},
    %{outcome: :error, reason: :catalog_unavailable}
  ]

  # Raw input goes into logs, so cap how much of it we keep.
  @max_logged_bytes 64

  @doc "Check `raw_id` against the catalog, timing the work and tagging the outcome."
  @spec run(term()) :: {:ok, Catalog.answer()} | {:error, reason()}
  def run(raw_id) do
    :telemetry.span([:kev_check, :process], %{}, fn ->
      result = check(raw_id, Date.utc_today().year)
      {result, %{count: 1}, stop_metadata(result, raw_id)}
    end)
  end

  @doc """
  Emit the stop event with `%{count: 0}` and no duration for every outcome, so both
  counters export all six series at 0 even before their first lookup.
  """
  @spec emit_zero_counts() :: :ok
  def emit_zero_counts,
    do: Enum.each(@outcomes, &:telemetry.execute([:kev_check, :process, :stop], %{count: 0}, &1))

  defp check(raw_id, current_year) do
    with {:ok, cve_id} <- CveId.parse(raw_id, current_year),
         :ok <- Faults.inject(),
         {:ok, catalog} <- Store.fetch() do
      {:ok, Catalog.answer(catalog, cve_id)}
    end
  end

  defp stop_metadata({:ok, answer}, raw_id) do
    %{
      outcome: :ok,
      known_exploited: answer.known_exploited,
      cve_id: answer.cve_id,
      raw_id: loggable(raw_id)
    }
  end

  defp stop_metadata({:error, reason}, raw_id),
    do: %{outcome: :error, reason: reason, raw_id: loggable(raw_id)}

  # Bytes, not characters: one character can carry any number of combining marks.
  # byte_slice never splits a code point, so the log line stays valid UTF-8.
  defp loggable(raw) when is_binary(raw), do: String.byte_slice(raw, 0, @max_logged_bytes)
  defp loggable(nil), do: nil

  defp loggable(other),
    do: other |> inspect(limit: 5, printable_limit: @max_logged_bytes) |> loggable()
end
