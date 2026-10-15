defmodule KevCheck.LookupLog do
  @moduledoc """
  Writes one structured log line per lookup, from the span's stop event. The CVE ID
  lives here and never in a metric label.
  """

  require Logger

  @handler_id "kev-check-lookup-log"

  @doc "Attach the handler. Attaching twice is a no-op."
  @spec attach() :: :ok
  def attach do
    case :telemetry.attach(
           @handler_id,
           [:kev_check, :process, :stop],
           &__MODULE__.handle_event/4,
           nil
         ) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  @doc "Log the finished lookup at a level that matches who's at fault."
  @spec handle_event([atom()], map(), map(), nil) :: :ok
  # Lookup.emit_zero_counts/0 sends these to create the counter series. They aren't lookups.
  def handle_event(_event, %{count: 0}, _metadata, _config), do: :ok

  def handle_event(_event, %{duration: duration}, metadata, _config) do
    fields = [
      event: "kev.process",
      outcome: metadata.outcome,
      reason: metadata[:reason],
      cve_id: metadata[:cve_id],
      raw_id: metadata.raw_id,
      known_exploited: metadata[:known_exploited],
      duration_ms: System.convert_time_unit(duration, :native, :microsecond) / 1000
    ]

    Logger.log(
      level(metadata),
      message(metadata),
      Enum.reject(fields, fn {_key, value} -> is_nil(value) end)
    )
  end

  defp level(%{outcome: :ok}), do: :info
  defp level(%{reason: :catalog_unavailable}), do: :error
  defp level(%{outcome: :error}), do: :warning

  defp message(%{outcome: :ok, known_exploited: true, cve_id: id}), do: "#{id} is on the KEV list"
  defp message(%{outcome: :ok, cve_id: id}), do: "#{id} is not on the KEV list"
  defp message(%{reason: :catalog_unavailable}), do: "catalog unavailable"
  defp message(%{reason: reason}), do: "rejected id: #{reason}"
end
