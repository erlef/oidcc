defmodule Oidcc do
  @moduledoc """
  OpenID Connect High Level Interface

  ## Setup

      {:ok, _pid} =
        Oidcc.ProviderConfiguration.Worker.start_link(%{
        issuer: "https://accounts.google.com/",
        name: MyApp.GoogleConfigProvider
      })

  or via a supervisor

      Supervisor.init([
        {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com/"}}
      ], strategy: :one_for_one)

  ## Global Configuration

  * `max_clock_skew` (default `0`) - Maximum allowed clock skew for JWT
    `exp` / `nbf` validation
  """

  @doc """
  Create Auth Redirect URL

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com/"
      ...> })
      ...>
      ...> {:ok, _redirect_uri} =
      ...>   Oidcc.create_redirect_url(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret",
      ...>     %{redirect_uri: "https://my.server/return"}
      ...>   )

  """
  @spec create_redirect_url(
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_authorization.opts()
        ) ::
          {:ok, :uri_string.uri_string()}
          | {:error, :oidcc_client_context.error() | :oidcc_client_context.error()}
  def create_redirect_url(provider_configuration_name, client_id, client_secret, opts),
    do: :oidcc.create_redirect_url(provider_configuration_name, client_id, client_secret, opts)

  @doc """
  retrieve the token using the authcode received before and directly validate
  the result.

  the authcode was sent to the local endpoint by the OpenId Connect provider,
  using redirects

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://login.yahoo.com"
      ...>   })
      ...>
      ...> # Get auth_code fromm redirect
      ...> auth_code = "auth_code"
      ...>
      ...> Oidcc.retrieve_token(
      ...>   auth_code,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{redirect_uri: "https://my.server/return"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @spec retrieve_token(
          auth_code :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.retrieve_opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def retrieve_token(auth_code, provider_configuration_name, client_id, client_secret, opts) do
    with {:ok, token} <-
           :oidcc.retrieve_token(
             auth_code,
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, Oidcc.Token.record_to_struct(token)}
    end
  end

  @doc """
  Refresh Token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://login.yahoo.com"
      ...>   })
      ...>
      ...> # Get refresh_token fromm redirect
      ...> refresh_token = "refresh_token"
      ...>
      ...> Oidcc.refresh_token(
      ...>   refresh_token,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{expected_subject: "sub_from_initial_id_token"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @spec refresh_token(
          refresh_token :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.refresh_opts()
        ) :: {:ok, Oidcc.Token.t()} | {:error, :oidcc_token.error()}
  @spec refresh_token(
          token :: Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.refresh_opts_no_sub()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def refresh_token(token, provider_configuration_name, client_id, client_secret, opts \\ %{}) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    with {:ok, token} <-
           :oidcc.refresh_token(
             token,
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, Oidcc.Token.record_to_struct(token)}
    end
  end

  @doc """
  Introspect the given access token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://login.yahoo.com"
      ...>   })
      ...>
      ...> Oidcc.introspect_token(
      ...>   "access_token",
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret"
      ...> )
      ...> # => {:ok, %Oidcc.TokenIntrospection{}}

  """
  @spec introspect_token(
          access_token :: String.t() | Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token_introspection.opts()
        ) ::
          {:ok, Oidcc.TokenIntrospection.t()}
          | {:error, :oidcc_client_context.error() | :oidcc_token_introspection.error()}
  def introspect_token(
        token,
        provider_configuration_name,
        client_id,
        client_secret,
        opts \\ %{}
      ) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    with {:ok, introspection} <-
           :oidcc.introspect_token(
             token,
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, Oidcc.TokenIntrospection.record_to_struct(introspection)}
    end
  end

  @doc """
  Load userinfo for the given token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://login.yahoo.com"
      ...>   })
      ...>
      ...> # Get access_token from Oidcc.Token.retrieve/3
      ...> access_token = "access_token"
      ...>
      ...> Oidcc.retrieve_userinfo(
      ...>   access_token,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{expected_subject: "sub"}
      ...> )
      ...> # => {:ok, %{"sub" => "sub"}}

  """
  @spec retrieve_userinfo(
          token :: Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_userinfo.retrieve_opts_no_sub()
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_userinfo.error()}
  @spec retrieve_userinfo(
          access_token :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_userinfo.retrieve_opts()
        ) ::
          {:ok, :oidcc_jwt_util.claims()}
          | {:error, :oidcc_client_context.error() | :oidcc_userinfo.error()}
  def retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts \\ %{}) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    :oidcc.retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts)
  end

  @doc """
  Retrieve JSON Web Token (JWT) Profile Token

  https://datatracker.ietf.org/doc/html/rfc7523#section-4

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> %{"key" => key, "keyId" => kid, "userId" => subject} = "JWT_PROFILE"
      ...>   |> System.fetch_env!()
      ...>   |> JOSE.decode()
      ...>
      ...> jwk = JOSE.JWK.from_pem(key)
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.jwt_profile_token(
      ...>     subject,
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret",
      ...>     jwk,
      ...>     %{scope: ["urn:zitadel:iam:org:project:id:zitadel:aud"], kid: kid}
      ...>   )

  """
  @spec jwt_profile_token(
          subject :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          jwk :: JOSE.JWK.t(),
          opts :: :oidcc_token.jwt_profile_opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def jwt_profile_token(subject, provider_configuration_name, client_id, client_secret, jwk, opts) do
    jwk = JOSE.JWK.to_record(jwk)

    with {:ok, token} <-
           :oidcc.jwt_profile_token(
             subject,
             provider_configuration_name,
             client_id,
             client_secret,
             jwk,
             opts
           ) do
      {:ok, Oidcc.Token.record_to_struct(token)}
    end
  end

  @doc """
  Retrieve Client Credential Token

  See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.client_credentials_token(
      ...>     pid,
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_ID"),
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_SECRET"),
      ...>     %{scope: ["scope"]}
      ...>   )

  """
  @spec client_credentials_token(
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.client_credentials_opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def client_credentials_token(provider_configuration_name, client_id, client_secret, opts) do
    with {:ok, token} <-
           :oidcc.client_credentials_token(
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, Oidcc.Token.record_to_struct(token)}
    end
  end
end
