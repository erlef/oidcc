defmodule Conformance do
  def static_paths, do: ~w()

  def verified_routes do
    quote do
      use Phoenix.VerifiedRoutes,
        router: Conformance.Router,
        endpoint: Conformance.Endpoint,
        statics: Conformance.static_paths()
    end
  end

  defmacro __using__(which) when is_atom(which) do
    apply(__MODULE__, which, [])
  end
end
