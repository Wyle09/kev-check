defmodule KevCheckWeb.MetricsPlug do
  @moduledoc """
  Serves `/metrics` in Prometheus text format on the metrics port, and 404 for
  anything else.
  """

  @behaviour Plug

  import Plug.Conn

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{method: "GET", request_path: "/metrics"} = conn, _opts) do
    # Prometheus 3 refuses a scrape whose content type is missing or unknown.
    conn
    |> put_resp_content_type("text/plain; version=0.0.4")
    |> send_resp(200, TelemetryMetricsPrometheus.Core.scrape())
  end

  def call(conn, _opts), do: send_resp(conn, 404, "not found")
end
