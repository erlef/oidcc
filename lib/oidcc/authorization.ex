defmodule Oidcc.Authorization do
  @moduledoc """
  Functions to start an OpenID Connect Authorization
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ClientContext

  @doc """
  Create Auth Redirect URL

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.create_redirect_url/4`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://accounts.google.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> {:ok, _redirect_uri} =
      ...>   Oidcc.Authorization.create_redirect_url(
      ...>     client_context,
      ...>     %{redirect_uri: "https://my.server/return"}
      ...>   )
  """
  @doc since: "3.0.0"
  @spec create_redirect_url(
          client_context :: ClientContext.t(),
          opts :: :oidcc_authorization.opts()
        ) :: {:ok, :uri_string.uri_string()} | {:error, :oidcc_authorization.error()}
  def create_redirect_url(client_context, opts),
    do:
      client_context
      |> ClientContext.struct_to_record()
      |> :oidcc_authorization.create_redirect_url(opts)
end
