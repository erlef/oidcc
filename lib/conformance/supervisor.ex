defmodule Conformance.Supervisor do
  use Supervisor

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl Supervisor
  def init(opts) do
    alias_name = Keyword.fetch!(opts, :alias)
    register_client? = Keyword.fetch!(opts, :register_client?)
    start_server? = Keyword.fetch!(opts, :start_server?)

    register_client_opts = Keyword.take(opts, [:token_endpoint_auth_method])

    Application.put_env(
      :conformance,
      Conformance.Endpoint,
      Application.get_env(:conformance, Conformance.Endpoint) ++ [server: start_server?]
    )

    [
      if(register_client? or start_server?, do: {Ngrok, port: 4000, name: Conformance.Ngrok}),
      if(register_client? or start_server?, do: Conformance.Endpoint),
      Conformance.LogConfiguration,
      {Oidcc.ProviderConfiguration.Worker,
       %{
         issuer: "https://www.certification.openid.net/test/a/#{alias_name}/",
         name: Conformance.ConfigWorker
       }},
      if(register_client?, do: {Conformance.RegisterClient, register_client_opts}),
      unless(start_server?, do: Conformance.AutoStopper)
    ]
    |> Enum.reject(&is_nil/1)
    |> Supervisor.init(strategy: :one_for_one)
  end
end
