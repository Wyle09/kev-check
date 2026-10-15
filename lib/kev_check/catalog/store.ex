defmodule KevCheck.Catalog.Store do
  @moduledoc """
  Holds the KEV catalog in `:persistent_term` so every request reads it without a
  process hop. Loads the bundled snapshot at boot and, when a refresh URL is
  configured, swaps in CISA's latest feed on a timer.
  """

  use GenServer

  alias KevCheck.Core.Catalog

  require Logger

  @first_refresh_ms 5_000

  @doc "Start the store. Boot fails if the snapshot can't be parsed or the refresh settings are invalid."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, Keyword.put(opts, :name, name), name: name)
  end

  @doc "The catalog this node is serving."
  @spec fetch(atom()) :: {:ok, Catalog.t()} | {:error, :catalog_unavailable}
  def fetch(name \\ __MODULE__) do
    case :persistent_term.get({__MODULE__, name}, nil) do
      %Catalog{} = catalog -> {:ok, catalog}
      nil -> {:error, :catalog_unavailable}
    end
  end

  @doc "Emit `[:kev_check, :catalog]` with the catalog's age and size. The telemetry poller calls this every 10 seconds."
  @spec emit_stats() :: :ok
  def emit_stats do
    case fetch() do
      {:ok, catalog} ->
        :telemetry.execute(
          [:kev_check, :catalog],
          %{
            age_seconds: Catalog.age_seconds(catalog, DateTime.utc_now()),
            entries: Catalog.size(catalog)
          },
          %{version: catalog.version}
        )

      {:error, :catalog_unavailable} ->
        :ok
    end
  end

  @impl GenServer
  def init(opts) do
    config = :kev_check |> Application.get_env(__MODULE__, []) |> Keyword.merge(opts)
    :ok = validate_refresh!(config[:refresh_url], config[:refresh_interval_ms])

    {:ok, catalog} = config |> snapshot_path() |> File.read!() |> Catalog.parse()
    serve(config[:name], catalog, "bundled snapshot")
    schedule_refresh(config[:refresh_url], @first_refresh_ms)
    {:ok, config}
  end

  @impl GenServer
  def handle_info(:refresh, config) do
    refresh(config)
    schedule_refresh(config[:refresh_url], config[:refresh_interval_ms])
    {:noreply, config}
  end

  defp refresh(config) do
    url = config[:refresh_url]
    # Without decode_body: false, Req hands back a decoded map for CISA's JSON content type.
    req_options = config |> Keyword.get(:req_options, []) |> Keyword.merge(decode_body: false)

    with {:ok, %Req.Response{status: 200, body: body}} <- Req.get(url, req_options),
         {:ok, catalog} <- Catalog.parse(body) do
      serve(config[:name], catalog, url)
    else
      failure ->
        Logger.warning("KEV refresh failed, keeping the current catalog: #{describe(failure)}",
          event: "kev.refresh"
        )
    end
  end

  defp serve(name, catalog, source) do
    :persistent_term.put({__MODULE__, name}, catalog)

    Logger.info(
      "serving KEV catalog #{catalog.version} with #{Catalog.size(catalog)} entries from #{source}",
      event: "kev.catalog"
    )
  end

  defp describe({:ok, %Req.Response{status: status}}), do: "HTTP #{status}"
  defp describe({:error, :invalid_catalog}), do: "the feed isn't a valid catalog"
  defp describe({:error, exception}), do: Exception.message(exception)

  defp schedule_refresh(nil, _after_ms), do: :ok

  defp schedule_refresh(_url, after_ms) do
    Process.send_after(self(), :refresh, after_ms)
    :ok
  end

  # Req raises on a malformed URL, which would crash the store on every refresh instead of once at boot.
  defp validate_refresh!(nil, _interval_ms), do: :ok

  defp validate_refresh!(url, interval_ms)
       when is_binary(url) and is_integer(interval_ms) and interval_ms > 0 do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host}}
      when scheme in ["http", "https"] and host not in [nil, ""] ->
        :ok

      _invalid ->
        raise ArgumentError, "the KEV refresh URL must be http or https, got: #{inspect(url)}"
    end
  end

  defp snapshot_path(config),
    do:
      config[:snapshot_path] ||
        Application.app_dir(:kev_check, "priv/kev/known_exploited_vulnerabilities.json")
end
