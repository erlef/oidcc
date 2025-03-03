defmodule Oidcc.Logout do
  @moduledoc """
  Logout from the OpenID Provider
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ClientContext
  alias Oidcc.Token

  @doc """
  Initiate URI for Relaying Party initiated Logout

  See https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.initiate_logout_url/4`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     :unauthenticated
      ...>   )
      ...>
      ...> # Get `token` from `Oidcc.retrieve_token/5`
      ...> token = "token"
      ...>
      ...> {:ok, _redirect_uri} =
      ...>   Oidcc.Logout.initiate_url(
      ...>     token,
      ...>     client_context,
      ...>     %{post_logout_redirect_uri: "https://my.server/return"}
      ...>   )
  """
  @doc since: "3.0.0"
  @spec initiate_url(
          token :: id_token | Token.t() | :undefined,
          client_context :: ClientContext.t(),
          opts :: :oidcc_logout.initiate_url_opts()
        ) ::
          {:ok, :uri_string.uri_string()}
          | {:error, :oidcc_logout.error()}
        when id_token: String.t()
  def initiate_url(token, client_context, opts \\ %{}) do
    client_context = ClientContext.struct_to_record(client_context)

    token =
      case token do
        token when is_binary(token) -> token
        %Token{} = token -> Token.struct_to_record(token)
      end

    :oidcc_logout.initiate_url(token, client_context, opts)
  end
end
