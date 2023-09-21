defmodule Oidcc.ClientContext do
  @moduledoc """
  Client Configuration for authorization, token exchange and userinfo

  For most projects, it makes sense to use
  `Oidcc.ProviderConfiguration.Worker` and the high-level
  interface of `Oidcc`. In that case direct usage of this
  module is not needed.
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :context,
    record_name: :oidcc_client_context,
    hrl: "include/oidcc_client_context.hrl"

  alias Oidcc.ProviderConfiguration

  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          provider_configuration: ProviderConfiguration.t(),
          jwks: JOSE.JWK.t(),
          client_id: String.t(),
          client_secret: String.t(),
          client_jwks: JOSE.JWK.t() | none
        }

  @doc """
  Create Client Context from a `Oidcc.ProviderConfiguration.Worker`

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com",
      ...>   name: __MODULE__.GoogleConfigProvider
      ...> })
      ...>
      ...> {:ok, %Oidcc.ClientContext{}} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     __MODULE__.GoogleConfigProvider,
      ...>     "client_id",
      ...>     "client_Secret"
      ...>   )
      ...>
      ...> {:ok, %Oidcc.ClientContext{}} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_Secret",
      ...>     %{client_jwks: JOSE.JWK.generate_key(16)}
      ...>   )
  """
  @doc since: "3.0.0"
  @spec from_configuration_worker(
          provider_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_client_context.opts()
        ) :: {:ok, t()} | {:error, :oidcc_client_context.t()}
  def from_configuration_worker(provider_name, client_id, client_secret, opts \\ %{}) do
    opts = Map.update(opts, :client_jwks, :none, &JOSE.JWK.to_record/1)

    with {:ok, client_context} <-
           :oidcc_client_context.from_configuration_worker(
             provider_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, record_to_struct(client_context)}
    end
  end

  @doc """
  Create Client Context manually

  ## Examples

      iex> {:ok, {configuration, _expiry}} =
      ...>   Oidcc.ProviderConfiguration.load_configuration(
      ...>     "https://login.salesforce.com"
      ...>   )
      ...>
      ...> {:ok, {jwks, _expiry}} =
      ...>   Oidcc.ProviderConfiguration.load_jwks(
      ...>     configuration.jwks_uri
      ...>   )
      ...>
      ...> %Oidcc.ClientContext{} =
      ...>   Oidcc.ClientContext.from_manual(
      ...>     configuration,
      ...>     jwks,
      ...>     "client_id",
      ...>     "client_Secret",
      ...>     %{client_jwks: JOSE.JWK.generate_key(16)}
      ...>   )
  """
  @doc since: "3.0.0"
  @spec from_manual(
          configuration :: ProviderConfiguration.t(),
          jwks :: JOSE.JWK.t(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_client_context.opts()
        ) :: t()
  def from_manual(configuration, jwks, client_id, client_secret, opts \\ %{}) do
    configuration = ProviderConfiguration.struct_to_record(configuration)
    jwks = JOSE.JWK.to_record(jwks)
    opts = Map.update(opts, :client_jwks, :none, &JOSE.JWK.to_record/1)

    configuration
    |> :oidcc_client_context.from_manual(jwks, client_id, client_secret, opts)
    |> record_to_struct()
  end

  @impl Oidcc.RecordStruct
  def record_to_struct(record) do
    record
    |> super()
    |> Map.update!(:provider_configuration, &ProviderConfiguration.record_to_struct/1)
    |> Map.update!(:jwks, &JOSE.JWK.from_record/1)
    |> update_if_not_none(:client_jwks, &JOSE.JWK.from_record/1)
  end

  @impl Oidcc.RecordStruct
  def struct_to_record(struct) do
    struct
    |> Map.update!(:provider_configuration, &ProviderConfiguration.struct_to_record/1)
    |> Map.update!(:jwks, &JOSE.JWK.to_record/1)
    |> update_if_not_none(:client_jwks, &JOSE.JWK.to_record/1)
    |> super()
  end

  defp update_if_not_none(map, key, callback) do
    Map.update!(map, key, fn
      :none -> :none
      other -> callback.(other)
    end)
  end
end
