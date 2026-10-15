defmodule KevCheckWeb.Router do
  use KevCheckWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/api", KevCheckWeb do
    pipe_through :api
  end
end
