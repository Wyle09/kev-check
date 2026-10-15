import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/kev_check start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :kev_check, KevCheckWeb.Endpoint, server: true
end

config :kev_check, KevCheckWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))]

if config_env() != :test do
  {error_rate, ""} = Float.parse(System.get_env("KEV_ERROR_RATE", "0"))

  config :kev_check, :metrics_server,
    port: String.to_integer(System.get_env("METRICS_PORT", "9568"))

  config :kev_check, KevCheck.Catalog.Store,
    refresh_url: System.get_env("KEV_REFRESH_URL"),
    refresh_interval_ms:
      :timer.seconds(String.to_integer(System.get_env("KEV_REFRESH_INTERVAL_SECONDS", "21600")))

  config :kev_check, KevCheck.Faults,
    latency_ms: String.to_integer(System.get_env("KEV_LATENCY_MS", "0")),
    error_rate: error_rate
end

if config_env() == :prod do
  # One JSON object per line, for the log pipeline, with the metadata keys
  # config/config.exs lists. new/1 builds the formatter once here instead of on every
  # log call, which is why this isn't in config/prod.exs.
  config :logger, :default_handler,
    formatter:
      LoggerJSON.Formatters.Basic.new(
        metadata: {:from_application_env, {:logger, :default_formatter}, [:metadata]}
      )

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :kev_check, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :kev_check, KevCheckWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://bandit.hexdocs.pm/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :kev_check, KevCheckWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :kev_check, KevCheckWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
