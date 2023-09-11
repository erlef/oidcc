defmodule Oidcc.TokenIntrospection do
  @moduledoc """
  OAuth Token Introspection

  See https://datatracker.ietf.org/doc/html/rfc7662
  """

  use Oidcc.RecordStruct,
    internal_name: :introspection,
    record_name: :oidcc_token_introspection,
    hrl: "include/oidcc_token_introspection.hrl"

  alias Oidcc.ClientContext
  alias Oidcc.Token

  @type t() :: %__MODULE__{
          active: boolean(),
          client_id: binary(),
          exp: pos_integer(),
          scope: :oidcc_scope.scopes(),
          username: binary()
        }

  @doc """
  Introspect the given access token

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.introspect_token/5`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://login.yahoo.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> Oidcc.TokenIntrospection.introspect(
      ...>   "access_token",
      ...>   client_context
      ...> )
      ...> # => {:ok, %Oidcc.TokenIntrospection{}}
  """
  @spec introspect(
          token :: String.t() | Token.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token_introspection.opts()
        ) :: {:ok, t()} | {:error, :oidcc_token_introspection.error()}
  def introspect(token, client_context, opts \\ %{}) do
    client_context = ClientContext.struct_to_record(client_context)

    token =
      case token do
        token when is_binary(token) -> token
        %Token{} = token -> Token.struct_to_record(token)
      end

    with {:ok, introspection} <-
           :oidcc_token_introspection.introspect(token, client_context, opts) do
      {:ok, record_to_struct(introspection)}
    end
  end
end
