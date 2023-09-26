defmodule Conformance.RegisterClient do
  use GenServer
  use Conformance, :verified_routes

  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl GenServer
  def init(opts) do
    token_endpoint_auth_method = Keyword.fetch!(opts, :token_endpoint_auth_method)

    {:ok,
     %Oidcc.ClientRegistration.Response{client_id: client_id, client_secret: client_secret} =
       response} =
      Oidcc.ClientRegistration.register(
        Oidcc.ProviderConfiguration.Worker.get_provider_configuration(Conformance.ConfigWorker),
        %Oidcc.ClientRegistration{
          redirect_uris: [url(~p"/callback")],
          initiate_login_uri: url(~p"/authorize"),
          token_endpoint_auth_method: token_endpoint_auth_method,
          post_logout_redirect_uris: [url(~p"/logged-out")],
          extra_fields: %{
            "frontchannel_logout_uri" => url(~p"/frontchannel-log-out")
          }
        }
      )

    Logger.info("Registered Client: #{inspect(response)}")

    {:ok, {client_id, client_secret}}
  end

  @impl GenServer
  def handle_call(:client_id, _from, {client_id, client_secret}),
    do: {:reply, client_id, {client_id, client_secret}}

  def handle_call(:client_secret, _from, {client_id, client_secret}),
    do: {:reply, client_secret, {client_id, client_secret}}

  def client_id, do: GenServer.call(__MODULE__, :client_id)
  def client_secret, do: GenServer.call(__MODULE__, :client_secret)
end
