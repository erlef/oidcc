defmodule Conformance.Router do
  use Phoenix.Router

  pipeline :browser do
    plug(:accepts, ["html"])

    plug(:fetch_session)
  end

  scope "/" do
    pipe_through(:browser)

    get("/authorize", Conformance.AuthController, :authorize)
    get("/callback", Conformance.AuthController, :callback)
    post("/callback", Conformance.AuthController, :callback_form)
  end
end
