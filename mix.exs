defmodule Oidcc.Mixfile do
  use Mix.Project

  {:ok, [{:application, :oidcc, props}]} = :file.consult(~c"src/oidcc.app.src")
  @props Keyword.take(props, [:applications, :description, :env, :mod, :licenses, :vsn])

  def project() do
    [
      app: :oidcc,
      version: to_string(@props[:vsn]),
      elixir: "~> 1.15",
      erlc_options: erlc_options(Mix.env()),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Oidcc",
      source_url: "https://github.com/erlef/oidcc",
      docs: &docs/0,
      description: to_string(@props[:description]),
      package: package(),
      aliases: [docs: ["compile", &rebar3_doc_chunks/1, "docs"]],
      test_coverage: [ignore_modules: [Oidcc.RecordStruct]]
    ]
  end

  def application() do
    [extra_applications: [:inets, :ssl]]
  end

  defp deps() do
    [
      {:telemetry, "~> 1.2"},
      {:telemetry_registry, "~> 0.3.1"},
      {:jose, "~> 1.11"},
      {:jsx, "~> 3.1", only: :test},
      {:mock, "~> 0.3.8", only: :test},
      {:ex_doc, "~> 0.29.4", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: :dev, runtime: false}
    ]
  end

  defp erlc_options(:prod), do: []

  defp erlc_options(_enc),
    do: [:debug_info, :warn_unused_import, :warn_export_vars, :warnings_as_errors, :verbose]

  defp package() do
    [
      maintainers: ["Jonatan Männchen"],
      build_tools: ["rebar3", "mix"],
      files: [
        "include",
        "lib",
        "LICENSE*",
        "mix.exs",
        "README*",
        "rebar.config",
        "src"
      ],
      licenses: Enum.map(@props[:licenses], &to_string/1),
      links: %{"Github" => "https://github.com/erlef/oidcc"}
    ]
  end

  defp docs do
    {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])

    [
      source_ref: ref,
      main: "Oidcc",
      extras: ["README.md"],
      groups_for_modules: [Erlang: [~r/oidcc/], "Elixir": [~r/Oidcc/]]
    ]
  end

  defp rebar3_doc_chunks(_args) do
    {_out, 0} = System.cmd("rebar3", ["edoc"], into: IO.stream())
  end
end
