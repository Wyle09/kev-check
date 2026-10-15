defmodule KevCheck.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      KevCheckWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:kev_check, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: KevCheck.PubSub},
      # Start a worker by calling: KevCheck.Worker.start_link(arg)
      # {KevCheck.Worker, arg},
      # Start to serve requests, typically the last entry
      KevCheckWeb.Endpoint
    ]

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
end
