defmodule Conformance.LogConfiguration do
  use GenServer

  require Logger

  def start_link(_opts), do: GenServer.start_link(__MODULE__, nil, [])

  @impl GenServer
  def init(_init_opt) do
    ref =
      :telemetry_test.attach_event_handlers(self(), [
        [:oidcc, :load_configuration, :stop],
        [:oidcc, :load_jwks, :stop]
      ])

    {:ok, ref}
  end

  @impl GenServer
  def handle_info({[:oidcc, :load_configuration, :stop], ref, _measurement, _meta}, ref) do
    configuration =
      Oidcc.ProviderConfiguration.Worker.get_provider_configuration(Conformance.ConfigWorker)

    Logger.info("""
    Loaded Provider Configuration: #{inspect(configuration, pretty: true)}
    """)

    {:noreply, ref}
  end

  def handle_info({[:oidcc, :load_jwks, :stop], ref, _measurement, _meta}, ref) do
    jwks =
      Conformance.ConfigWorker
      |> Oidcc.ProviderConfiguration.Worker.get_jwks()
      |> JOSE.JWK.to_map()

    Logger.info("""
    Loaded Jwks: #{inspect(jwks, pretty: true)}
    """)

    {:noreply, ref}
  end
end
