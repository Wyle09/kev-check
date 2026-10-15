defmodule KevCheck.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Boundary, top_level?: true, deps: [KevCheck, KevCheckWeb, Phoenix]
  use Application

  @impl true
  def start(_type, _args) do
    :ok = KevCheck.LookupLog.attach()
    :ok = KevCheckWeb.RequestTelemetry.attach()
    # Reading the boot values checks them, so a bad KEV_LATENCY_MS or KEV_ERROR_RATE
    # fails the boot instead of every lookup.
    _boot_settings = KevCheck.Faults.reset()

    children =
      [
        # First, so the gauge poller and the first request always find a catalog.
        KevCheck.Catalog.Store,
        KevCheckWeb.Telemetry,
        {DNSCluster, query: Application.get_env(:kev_check, :dns_cluster_query) || :ignore},
        {Phoenix.PubSub, name: KevCheck.PubSub},
        KevCheckWeb.Endpoint
      ] ++ metrics_server(Phoenix.Endpoint.server?(:kev_check, KevCheckWeb.Endpoint))

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: KevCheck.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    KevCheckWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  # Metrics get their own listener, so no public route can expose them. It runs only
  # when the API does, so `mix run` beside a running server doesn't fight over the port.
  defp metrics_server(false = _endpoint_serves?), do: []

  defp metrics_server(true = _endpoint_serves?) do
    opts = Application.fetch_env!(:kev_check, :metrics_server)
    [{Bandit, [plug: KevCheckWeb.MetricsPlug] ++ opts}]
  end
end
