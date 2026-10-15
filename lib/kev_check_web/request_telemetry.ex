defmodule KevCheckWeb.RequestTelemetry do
  @moduledoc """
  Emits one `[:kev_check, :http, :request]` event per response Phoenix sends, which
  `http_requests_total` counts, with labels from a fixed set of values.

  Phoenix reports a finished request in one of two places. Anything that reached
  the router ends with the endpoint's stop event, crashes included. An error raised
  by a plug before the router, like a query string that isn't valid UTF-8, only
  shows up as `[:phoenix, :error_rendered]`, because Phoenix renders it from a conn
  that `Plug.Telemetry` never saw.
  """

  @handler_id "kev-check-request-telemetry"

  # Any client can send any method, so anything else is counted as "OTHER".
  @known_methods ~w(GET POST PUT PATCH DELETE OPTIONS)

  @doc "Attach the handler. Attaching twice is a no-op."
  @spec attach() :: :ok
  def attach do
    case :telemetry.attach_many(
           @handler_id,
           [[:phoenix, :endpoint, :stop], [:phoenix, :error_rendered]],
           &__MODULE__.handle_event/4,
           nil
         ) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  @doc "Re-emit a finished request as `[:kev_check, :http, :request]`, once per response."
  @spec handle_event([atom()], map(), map(), nil) :: :ok
  def handle_event([:phoenix, :endpoint, :stop], _measurements, %{conn: conn}, _config),
    do: emit(conn, conn.status)

  # The router marks every conn it touches, and a marked conn already got the stop
  # event above. Counting it here too would count a crash twice.
  def handle_event(
        [:phoenix, :error_rendered],
        _measurements,
        %{conn: %Plug.Conn{private: %{phoenix_router: _router}}},
        _config
      ),
      do: :ok

  def handle_event(
        [:phoenix, :error_rendered],
        _measurements,
        %{conn: conn, status: status},
        _config
      ),
      do: emit(conn, status)

  defp emit(conn, status) do
    method = method(conn.method)

    :telemetry.execute([:kev_check, :http, :request], %{}, %{
      method: method,
      route: route(method, conn),
      status: status
    })
  end

  # Plug.Head serves HEAD as GET before the router runs, so count it as GET everywhere.
  defp method("HEAD"), do: "GET"
  defp method(method) when method in @known_methods, do: method
  defp method(_method), do: "OTHER"

  # The route pattern, never the raw path, which would make one series per URL.
  # Segments are decoded first, the way the router decodes them before matching.
  defp route(method, conn) do
    path = Enum.map(conn.path_info, &URI.decode/1)

    case Phoenix.Router.route_info(KevCheckWeb.Router, method, path, conn.host) do
      %{route: route} -> route
      :error -> "unmatched"
    end
  end
end
