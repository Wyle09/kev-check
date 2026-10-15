import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :kev_check, KevCheckWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "FUUlqLqWxRZc0RhrqRXAsIzB6dW2ecgqCEZgkXvUbWGukuDvzPdpB5N66GftaeM1",
  server: false

config :kev_check, KevCheck.Catalog.Store,
  snapshot_path: Path.expand("../test/support/fixtures/kev_fixture.json", __DIR__)

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
