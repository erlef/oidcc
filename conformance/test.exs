#!/usr/bin/env elixir
Mix.install(
  [
    {:oidcc, path: ".."},
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

  def authorize(conn, _params) do
    nonce = 32 |> :crypto.strong_rand_bytes() |> Base.encode64()

    with {:ok, url} <-
           Oidcc.create_redirect_url(:config_worker, "client_id", "client_secret", %{
             redirect_uri: "http://localhost:4000/callback",
             nonce: nonce,
             scopes: ["profile", "openid"],
             response_type: "code"
           }) do
      conn
      |> put_session(:nonce, nonce)
      |> redirect(external: IO.iodata_to_binary(url))
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

  def callback_form(conn, %{"code" => code}) do
    # Redirect neccesary since session does not include nonce
    # on cross origin post
    redirect(conn, to: "/callback?code=" <> code)
  end

  def callback(conn, %{"code" => code}) do
    nonce = get_session(conn, :nonce) || :any
    conn = put_session(conn, :nonce, nil)

    with {:ok, token} <-
           Oidcc.retrieve_token(
             code,
             :config_worker,
             "client_id",
             "client_secret",
             %{
               redirect_uri: "http://localhost:4000/callback",
               nonce: nonce
             }
           ),
         {:ok, userinfo} <-
           Oidcc.retrieve_userinfo(
             token,
             :config_worker,
             "client_id",
             "client_secret",
             %{}
           ) do
      maybe_refresh =
        case token do
          %Token{refresh: %Token.Refresh{token: token}, id: %Token.Id{claims: %{"sub" => sub}}} ->
            refresh_url =
              URI.to_string(%URI{
                scheme: nil,
                userinfo: nil,
                host: nil,
                port: nil,
                path: "/refresh",
                query: URI.encode_query(%{token: token, expected_subject: sub}),
                fragment: nil
              })

            """
             <a href="#{refresh_url}">Refresh</a>
            """

          %Token{} ->
            nil
        end

      conn
      |> put_resp_header("content-type", "text/html")
      |> send_resp(200, """
        <pre>#{inspect(%{token: token, userinfo: userinfo}, pretty: true)}</pre>
        #{maybe_refresh}
      """)
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

  def refresh(conn, %{"token" => refresh_token, "expected_subject" => sub}) do
    with {:ok, token} <-
           Oidcc.refresh_token(
             refresh_token,
             :config_worker,
             "client_id",
             "client_secret",
             sub
           ),
         {:ok, userinfo} <-
           Oidcc.retrieve_userinfo(
             token,
             :config_worker,
             "client_id",
             "client_secret",
             %{}
           ) do
      send_resp(conn, 200, inspect(%{token: token, userinfo: userinfo}, pretty: true))
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

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

  scope "/", Conformance do
    pipe_through(:browser)

    get("/authorize", AuthController, :authorize)
    get("/callback", AuthController, :callback)
    post("/callback", AuthController, :callback_form)
    get("/refresh", AuthController, :refresh)
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
