import Config

# No force_ssl: TLS ends at the load balancer, and inside the cluster a forced
# redirect would bounce the probes and the load generator.

# The lookup log line replaces Phoenix's per-request lines. The JSON formatter is
# set in config/runtime.exs.
config :phoenix, :logger, false

# Do not print debug messages in production
config :logger, level: :info

# Runtime production configuration, including reading
# of environment variables, is done on config/runtime.exs.
