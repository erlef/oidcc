#!/usr/bin/env elixir

{:ok, handler_config} = :logger.get_handler_config(:default)

handler_config =
  handler_config
  |> put_in([:config, :type], :standard_error)
  |> put_in([:formatter], Logger.Formatter.new(format: "$message\n"))

:ok = :logger.remove_handler(:default)
:ok = :logger.add_handler(:default, :logger_std_h, handler_config)

Mix.start()
Mix.shell(Mix.Shell.Quiet)

Mix.install([
  {:bandit, "~> 1.0"},
  {:oidcc, path: Path.dirname(__DIR__), override: true},
  {:oidcc_plug, "~> 0.3.1"},
  {:jason, "~> 1.4"},
  {:phoenix_live_view, "~> 1.0"},
  {:phoenix, "~> 1.7"}
])

defmodule Oidcc.CommandAndControl do
  @moduledoc false

  alias Oidcc.Conformance.ProviderConfiguration
  alias Oidcc.ProviderConfiguration.Worker

  require Logger

  defstruct port: nil, public_url: nil, variant: nil, port_reservation: nil, client_jwks: nil

  def start do
    JOSE.unsecured_signing(true)

    IO.stream()
    |> Stream.map(&String.trim/1)
    |> Stream.reject(&(&1 == ""))
    |> Stream.map(fn "CMD " <> command -> JSON.decode!(command) end)
    |> Enum.reduce(%__MODULE__{}, fn command, state ->
      {:ok, response, state} = apply_command(command, state)

      case response do
        nil -> IO.puts("ACK")
        response -> IO.puts("ACK #{JSON.encode!(response)}")
      end

      state
    end)
  end

  defp apply_command(
         %{
           "action" => "init",
           "exposed" => %{"issuer" => issuer},
           "public_url" => public_url,
           "variant" => variant
         },
         state
       ) do
    {:ok, _pid} =
      Worker.start_link(%{
        issuer: issuer,
        name: ProviderConfiguration
      })

    {port, port_reservation} = reserve_port()

    {:ok, %{url: public_url, port: port},
     %{
       state
       | port: port,
         public_url: public_url,
         variant: variant,
         port_reservation: port_reservation
     }}
  end

  defp apply_command(%{"action" => "register_client"}, state) do
    provider_configuration = Worker.get_provider_configuration(ProviderConfiguration)

    rsa_jwk = %{
      JOSE.JWK.generate_key({:rsa, 2048})
      | fields: %{"use" => "sig", "kid" => "the-one-and-only"}
    }

    {_meta, public_jwk} = JOSE.JWK.to_public_map(rsa_jwk)
    {_meta, private_jwk} = JOSE.JWK.to_map(rsa_jwk)
    public_jwks = JOSE.JWK.from_map(%{"keys" => [public_jwk]})
    private_jwks = JOSE.JWK.from_map(%{"keys" => [private_jwk]})

    {:ok, %Oidcc.ClientRegistration.Response{client_id: client_id, client_secret: client_secret}} =
      Oidcc.ClientRegistration.register(provider_configuration, %Oidcc.ClientRegistration{
        initiate_login_uri: "#{state.public_url}/authorize",
        redirect_uris: ["#{state.public_url}/callback"],
        userinfo_signed_response_alg: "RS256",
        token_endpoint_auth_method: state.variant["client_auth_type"] || "client_secret_basic",
        jwks: public_jwks
      })

    {:ok, %{client_id: client_id, client_secret: client_secret},
     %{state | client_jwks: private_jwks}}
  end

  defp apply_command(
         %{
           "action" => "start_server",
           "client_id" => client_id,
           "client_secret" => client_secret
         },
         state
       ) do
    Application.put_env(:oidcc_conformance, Oidcc.Conformance.AuthController,
      client_id: client_id,
      client_secret: client_secret,
      client_context_opts: %{client_jwks: state.client_jwks}
    )

    %URI{host: host, path: path} = URI.new!(state.public_url)

    :gen_tcp.close(state.port_reservation)

    {:ok, _} =
      Supervisor.start_link(
        [
          {Oidcc.Conformance.Endpoint,
           adapter: Bandit.PhoenixAdapter,
           url: [host: host, scheme: "https", port: 443, path: path],
           http: [
             ip: {127, 0, 0, 1},
             port: state.port
           ],
           render_errors: [
             formats: [html: Oidcc.Conformance.ErrorHTML],
             layout: false
           ],
           server: true,
           secret_key_base: String.duplicate("a", 64),
           debug_errors: true}
        ],
        strategy: :one_for_one
      )

    {:ok, nil, state}
  end

  defp apply_command(other, _state) do
    raise "Unknown command: #{inspect(other)}"
  end

  defp reserve_port do
    {:ok, listen} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(listen)

    {port, listen}
  end
end

defmodule Oidcc.Conformance.ErrorHTML do
  use Phoenix.Component

  def render(template, _assigns) do
    Phoenix.Controller.status_message_from_template(template)
  end
end

defmodule Oidcc.Conformance.AuthController do
  use Phoenix.Controller, formats: [:html]

  use Phoenix.VerifiedRoutes,
    endpoint: Oidcc.Conformance.Endpoint,
    router: Oidcc.Conformance.Router,
    statics: []

  alias Oidcc.Conformance.ProviderConfiguration
  alias Oidcc.Plug.AuthorizationCallback

  require Logger

  plug(:put_layout, false)

  plug(
    Oidcc.Plug.Authorize,
    [
      provider: ProviderConfiguration,
      client_id: &__MODULE__.client_id/0,
      client_secret: &__MODULE__.client_secret/0,
      redirect_uri: &__MODULE__.callback_uri/0,
      scopes: ["openid", "profile"],
      client_context_opts: &__MODULE__.client_context_opts/0
    ]
    when action in [:authorize]
  )

  plug(
    AuthorizationCallback,
    [
      provider: ProviderConfiguration,
      client_id: &__MODULE__.client_id/0,
      client_secret: &__MODULE__.client_secret/0,
      redirect_uri: &__MODULE__.callback_uri/0,
      client_context_opts: &__MODULE__.client_context_opts/0
    ]
    when action in [:callback]
  )

  def index(conn, _params) do
    render(conn, "index.html")
  end

  def logged_in(conn, _params) do
    case Plug.Conn.get_session(conn, "oidcc") do
      nil ->
        redirect(conn, to: ~p"/")

      %{token: token, userinfo: userinfo} ->
        render(conn, "logged_in.html", token: token, userinfo: userinfo)
    end
  end

  def authorize(conn, _params) do
    conn
  end

  def callback(
        %Plug.Conn{private: %{AuthorizationCallback => {:ok, {token, userinfo}}}} = conn,
        _params
      ) do
    conn
    |> put_session("oidcc", %{
      userinfo: userinfo,
      token: token
    })
    |> redirect(to: ~p"/logged-in")
  end

  def callback(%Plug.Conn{private: %{AuthorizationCallback => {:error, reason}}} = conn, _params) do
    Logger.error("Authorization error: #{inspect(reason)}")

    conn
    |> put_status(400)
    |> render(:error, reason: reason)
  end

  def callback_form(conn, %{"code" => code}) do
    # Redirect neccesary since session does not include nonce
    # on cross origin post
    redirect(conn, to: ~p"/callback?code=#{code}")
  end

  def refresh(conn, _params) do
    case Plug.Conn.get_session(conn, "oidcc") do
      nil ->
        redirect(conn, to: ~p"/")

      %{token: token} ->
        case refresh_token(token) do
          {:ok, {token, userinfo}} ->
            conn
            |> put_session("oidcc", %{userinfo: userinfo, token: token})
            |> redirect(to: ~p"/logged-in")

          {:error, reason} ->
            Logger.error("Refresh error: #{inspect(reason)}")

            conn
            |> put_status(400)
            |> render(:error, reason: reason)
        end
    end
  end

  defp refresh_token(token) do
    with {:ok, token} <-
           Oidcc.refresh_token(token, ProviderConfiguration, client_id(), client_secret()),
         {:ok, userinfo} <-
           Oidcc.retrieve_userinfo(
             token,
             ProviderConfiguration,
             client_id(),
             client_secret(),
             %{}
           ) do
      {:ok, {token, userinfo}}
    end
  end

  @doc false
  def client_id do
    Application.fetch_env!(:oidcc_conformance, __MODULE__)[:client_id]
  end

  @doc false
  def client_secret do
    Application.fetch_env!(:oidcc_conformance, __MODULE__)[:client_secret]
  end

  def client_context_opts do
    Application.fetch_env!(:oidcc_conformance, __MODULE__)[:client_context_opts]
  end

  @doc false
  def callback_uri do
    url(~p"/callback")
  end
end

defmodule Oidcc.Conformance.AuthHTML do
  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: Oidcc.Conformance.Endpoint,
    router: Oidcc.Conformance.Router,
    statics: []

  def index(assigns) do
    ~H"""
    <h1>Hello to the Oidcc Conformance Test Suite!</h1>

    <h2>Actions</h2>
    <ul>
      <li>
        <.link href={~p"/authorize"} aria-label="Login">Login</.link>
      </li>
    </ul>
    """
  end

  def logged_in(assigns) do
    ~H"""
    <h1>Hello <span aria-label="sub"><%= @userinfo["sub"] %></span>!</h1>

    <h2>Token</h2>
    <pre aria-label="token"><%= inspect(@token, pretty: true) %></pre>

    <h2>Userinfo</h2>
    <pre aria-label="userinfo"><%= inspect(@userinfo, pretty: true) %></pre>

    <h2>Actions</h2>
    <ul>
      <li>
        <.link href={~p"/refresh"} aria-label="Refresh">Refresh Token</.link>
      </li>
    </ul>
    """
  end

  def error(assigns) do
    ~H"""
    <h1>Authorization Error</h1>

    <pre aria-label="error"><%= inspect(@reason, pretty: true) %></pre>
    """
  end
end

defmodule Oidcc.Conformance.Router do
  use Phoenix.Router

  pipeline :browser do
    plug(:fetch_session)
    plug(:accepts, ["html"])
  end

  scope "/", Oidcc.Conformance do
    pipe_through(:browser)

    get("/", AuthController, :index)
    get("/logged-in", AuthController, :logged_in)
    get("/authorize", AuthController, :authorize)
    get("/callback", AuthController, :callback)
    post("/callback", AuthController, :callback_form)
    get("/refresh", AuthController, :refresh)
  end
end

defmodule Oidcc.Conformance.Endpoint do
  use Phoenix.Endpoint, otp_app: :oidcc_conformance

  @session_options [
    store: :cookie,
    key: "_oidcc_conformance_key",
    signing_salt: String.duplicate("a", 64),
    same_site: "Lax"
  ]

  plug(Plug.Session, @session_options)

  plug(Plug.Parsers, parsers: [:urlencoded])

  plug(Plug.Logger, log: :info)

  plug(Oidcc.Conformance.Router)
end

Oidcc.CommandAndControl.start()
