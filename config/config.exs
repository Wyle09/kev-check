# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :kev_check,
  generators: [timestamp_type: :utc_datetime]

# Configure the endpoint
config :kev_check, KevCheckWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [json: KevCheckWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: KevCheck.PubSub,
  live_view: [signing_salt: "IinDvhvZ"]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [
    :request_id,
    :event,
    :outcome,
    :reason,
    :cve_id,
    :raw_id,
    :known_exploited,
    :duration_ms
  ]

config :kev_check, KevCheck.Catalog.Store,
  snapshot_path: nil,
  refresh_url: nil,
  refresh_interval_ms: :timer.hours(6)

config :kev_check, KevCheck.Faults, latency_ms: 0, error_rate: 0.0

# Prometheus scrapes this port. The API port never serves /metrics.
config :kev_check, :metrics_server, port: 9568

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
