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
    get("/logged-out", Conformance.AuthController, :logged_out)
    get("/frontchannel-log-out", Conformance.AuthController, :front_channel_log_out)
  end
end
