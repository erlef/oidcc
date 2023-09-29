defmodule Conformance.MixProject do
  use Mix.Project

  def project do
    [
      app: :conformance,
      version: "0.0.0-dev",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [extra_applications: [:logger]]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oidcc, "~> 3.0"},
      {:oidcc_plug, "~> 0.1.0"},
      {:plug_cowboy, "~> 2.5"},
      {:phoenix, "~> 1.7"},
      {:jason, "~> 1.4"},
      {:logger_file_backend, "~> 0.0.13"},
      {:ngrok, "~> 1.1"}
    ]
  end
end
