defmodule Mix.Tasks.RunCertification do
  @shortdoc "Run Certification"

  @moduledoc """
  Run Certification

  See `README.md` for options
  """

  use Mix.Task

  @switches [
    alias: :string,
    profile: :string,
    version: :string,
    test_name: :string,
    register_client: :boolean,
    start_server: :boolean,
    auto_stop: :boolean,
    auto_open: :boolean,
    auto_screenshot: :boolean
  ]

  @project_root __ENV__.file |> Path.dirname() |> Path.join("../../..") |> Path.expand()

  @impl Mix.Task
  def run(args) do
    opts =
      case OptionParser.parse!(args, strict: @switches) do
        {opts, []} ->
          opts

        {__opts, parsed} ->
          Mix.raise("""
          Unknown args #{inspect(parsed)}
          """)
      end

    %{
      alias: alias_name,
      profile: profile,
      version: version,
      test_name: test_name,
      register_client: register_client?,
      start_server: start_server?,
      auto_stop: auto_stop?,
      auto_open: auto_open?,
      auto_screenshot: auto_screenshot?
    } =
      opts
      |> Keyword.put_new(:alias, "test")
      |> Keyword.put_new_lazy(:profile, fn ->
        "What profile are you currently executing?"
        |> Mix.Shell.IO.prompt()
        |> String.trim()
      end)
      |> Keyword.put_new(:version, "dev")
      |> Keyword.put_new_lazy(:test_name, fn ->
        "What test are you currently executing?"
        |> Mix.Shell.IO.prompt()
        |> String.trim()
      end)
      |> Keyword.put_new(:register_client, true)
      |> Keyword.put_new(:start_server, true)
      |> Keyword.put_new(:auto_stop, true)
      |> Keyword.put_new(:auto_open, false)
      |> Keyword.put_new(:auto_screenshot, false)
      |> Map.new()



    artifact_out_dir = Path.join([@project_root, version, profile])
    log_file = Path.join(artifact_out_dir, "#{test_name}.log")

    if File.exists?(log_file) do
      Mix.Shell.IO.yes?("Log already exist, append?") || System.halt(1)
    end

    Application.put_env(:logger, :log, path: log_file, level: :debug)
    Logger.add_backend({LoggerFileBackend, :log})

    Application.ensure_all_started(:conformance)
    JOSE.unsecured_signing(true)

    Process.register(self(), Conformance.Runner)

    Application.put_env(:conformance, Conformance.Screenshot, [
      enable: auto_screenshot?,
      path: Path.join(artifact_out_dir, "#{test_name}.png"),
    ])

    {:ok, _pid} =
      Conformance.Supervisor.start_link(
        alias: alias_name,
        register_client?: register_client?,
        start_server?: start_server?
      )

      if start_server? and auto_open? do
        System.cmd("xdg-open", [Conformance.Endpoint.url() <> "/authorize"])
      end

    if auto_stop? do
      receive do
        :stop -> :ok
      end
    else
      Process.sleep(:infinity)
    end
  end
end
