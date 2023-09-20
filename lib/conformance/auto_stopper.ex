defmodule Conformance.AutoStopper do
  use GenServer

  def start_link(_opts), do: GenServer.start_link(__MODULE__, nil, [])

  @impl GenServer
  def init(_opts) do
    Process.send_after(Conformance.Runner, :stop, 2_000)

    {:ok, nil}
  end
end
