#!/usr/bin/env elixir
Mix.install(
  [
    {:oidcc, path: "..", override: true},
    {:oidcc_plug, "~> 0.1.0-alpha"},
    {:plug_cowboy, "~> 2.5"},
    {:phoenix, "~> 1.7"},
    {:jason, "~> 1.4"}
  ],
  config: [
    conformance: [
      {Conformance.Endpoint,
       [
         http: [ip: {127, 0, 0, 1}, port: 4000],
         server: true,
         secret_key_base: String.duplicate("a", 64),
         debug_errors: true
       ]}
    ]
  ]
)

Application.ensure_all_started(:oidcc)
JOSE.unsecured_signing(true)

defmodule Conformance.AuthController do
  use Phoenix.Controller

  alias Oidcc.Token

  plug(
    Oidcc.Plug.AuthorizationCallback,
    [
      provider: :config_worker,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: "http://localhost:4000/callback"
    ]
    when action in [:callback]
  )

  def callback_form(conn, %{"code" => code}) do
    # Redirect neccesary since session does not include nonce
    # on cross origin post
    redirect(conn, to: "/callback?code=" <> code)
  end

  def callback(
        %Plug.Conn{
          private: %{
            Oidcc.Plug.AuthorizationCallback => {:ok, {token, userinfo}}
          }
        } = conn,
        _params
      ) do
    spawn(fn ->
      Process.sleep(5_000)
      System.halt()
    end)

    with {:ok, {refreshed_token, refreshed_userinfo}} <- maybe_refresh(token) do
      send_resp(
        conn,
        200,
        inspect(
          %{
            token: token,
            userinfo: userinfo,
            refreshed_token: refreshed_token,
            refreshed_userinfo: refreshed_userinfo
          },
          pretty: true
        )
      )
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

  def callback(
        %Plug.Conn{
          private: %{
            Oidcc.Plug.AuthorizationCallback => {:error, reason}
          }
        } = conn,
        _params
      ) do
    spawn(fn ->
      Process.sleep(5_000)
      System.halt()
    end)

    error_response(conn, reason)
  end

  defp maybe_refresh(%Token{refresh: %Token.Refresh{token: _refresh_token}} = token) do
    with {:ok, token} <-
           Oidcc.refresh_token(
             token,
             :config_worker,
             "client_id",
             "client_secret"
           ),
         {:ok, userinfo} <-
           Oidcc.retrieve_userinfo(
             token,
             :config_worker,
             "client_id",
             "client_secret",
             %{}
           ) do
      {:ok, {token, userinfo}}
    end
  end

  defp maybe_refresh(%Token{}), do: {:ok, {nil, nil}}

  defp error_response(conn, reason) do
    send_resp(conn, 400, inspect(reason, pretty: true))
  end
end

defmodule Conformance.Router do
  use Phoenix.Router

  pipeline :browser do
    plug(:accepts, ["html"])

    plug(:fetch_session)
  end

  scope "/" do
    pipe_through(:browser)

    forward("/authorize", Oidcc.Plug.Authorize,
      provider: :config_worker,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: "http://localhost:4000/callback"
    )

    get("/callback", Conformance.AuthController, :callback)
    post("/callback", Conformance.AuthController, :callback_form)
  end
end

defmodule Conformance.Endpoint do
  use Phoenix.Endpoint, otp_app: :conformance

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()
  )

  plug(Plug.Head)

  plug(Plug.Session,
    store: :cookie,
    key: "_session",
    signing_salt: "6MKm58UGfKFEgo8M1cx9GuTJX8Vy6nW3",
    same_site: "Lax"
  )

  plug(Conformance.Router)
end

{:ok, _} =
  Supervisor.start_link(
    [
      Conformance.Endpoint,
      {Oidcc.ProviderConfiguration.Worker,
       %{issuer: "https://www.certification.openid.net/test/a/test/", name: :config_worker}}
    ],
    strategy: :one_for_one
  )

Process.sleep(:infinity)
