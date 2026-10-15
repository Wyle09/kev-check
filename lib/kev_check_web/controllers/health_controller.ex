defmodule KevCheckWeb.HealthController do
  @moduledoc "The probe endpoint Kubernetes checks."

  use KevCheckWeb, :controller

  @doc "Liveness and readiness. The app has no outside dependency that could make it unready, so one route covers both."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, "ok")
  end
end
