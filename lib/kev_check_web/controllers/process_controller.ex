defmodule KevCheckWeb.ProcessController do
  @moduledoc "Answers `GET /process?id=...`: is this CVE on CISA's KEV list?"

  use KevCheckWeb, :controller

  @doc "Run the lookup and render the answer, or the reason it couldn't be answered."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, params) do
    case KevCheck.Lookup.run(params["id"]) do
      {:ok, answer} -> render(conn, :show, answer: answer)
      {:error, reason} -> conn |> put_status(status(reason)) |> render(:error, reason: reason)
    end
  end

  # Bad input is the caller's problem (4xx). Only catalog trouble is ours (5xx).
  defp status(:missing_id), do: 400
  defp status(:invalid_format), do: 400
  defp status(:year_out_of_range), do: 422
  defp status(:catalog_unavailable), do: 503
end
