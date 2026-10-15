defmodule KevCheckWeb.Router do
  use KevCheckWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", KevCheckWeb do
    pipe_through :api

    get "/process", ProcessController, :show
  end

  # Health checks answer plain text, so they skip the JSON-only pipeline.
  scope "/", KevCheckWeb do
    get "/healthz", HealthController, :show
  end
end
