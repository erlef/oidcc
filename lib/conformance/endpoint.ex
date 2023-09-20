defmodule Conformance.Endpoint do
  use Phoenix.Endpoint, otp_app: :conformance

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()
  )

  plug(Plug.Head)

  plug(Plug.Session,
    store: :cookie,
    key: "_session",
    signing_salt: "6MKm58UGfKFEgo8M1cx9GuTJX8Vy6nW3",
    same_site: "Lax"
  )

  plug(Conformance.Router)

  @impl Phoenix.Endpoint
  def init(_context, config) do
    %URI{host: host, port: port, scheme: scheme} =
      URI.new!(Ngrok.public_url(Conformance.Ngrok))

    {:ok, Keyword.put(config, :url, path: "/", host: host, port: port, scheme: scheme)}
  end
end
