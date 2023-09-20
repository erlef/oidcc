defmodule Conformance.RegisterClient do
  use GenServer
  use Conformance, :verified_routes

  require Logger

  def start_link(_opts), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl GenServer
  def init(_init_opt) do
    {:ok,
     %Oidcc.ClientRegistration.Response{client_id: client_id, client_secret: client_secret} =
       response} =
      Oidcc.ClientRegistration.register(
        Oidcc.ProviderConfiguration.Worker.get_provider_configuration(Conformance.ConfigWorker),
        %Oidcc.ClientRegistration{
          redirect_uris: [url(~p"/callback")],
          initiate_login_uri: url(~p"/authorize")
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
