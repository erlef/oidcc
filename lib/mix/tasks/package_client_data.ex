defmodule Mix.Tasks.PackageClientData do
  @shortdoc "Package Client Data"

  @moduledoc """
  Package Client Data
  """

  use Mix.Task

  @switches [
    profile: :string,
    version: :string
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
      profile: profile,
      version: version
    } =
      opts
      |> Keyword.put_new_lazy(:profile, fn ->
        "What profile are you currently executing?"
        |> Mix.Shell.IO.prompt()
        |> String.trim()
      end)
      |> Keyword.put_new(:version, "dev")
      |> Map.new()

    artifact_out_dir = Path.join([@project_root, "test_plans", version, profile])

    client_data_files =
      artifact_out_dir
      |> Path.join("*")
      |> Path.wildcard()
      # Screenshots should be added to the test log via `Upload Images`
      |> Enum.reject(&(Path.extname(&1) == ".png"))
      |> Enum.map(&Path.basename/1)
      |> Enum.map(&to_charlist/1)

    client_data_out_file = "#{artifact_out_dir}-client-data.zip"

    {:ok, _out_file} =
      client_data_out_file
      |> to_charlist()
      |> :zip.create(client_data_files, [
        :verbose,
        cwd: to_charlist(artifact_out_dir),
        compress: :all
      ])

    Mix.Shell.IO.info("""
    Client Data exported to #{client_data_out_file}
    """)

    Mix.Shell.IO.yes?("""
    This task will delete all intermediate file. Are you sure that you uploaded
    all images?
    """) || Mix.raise("aborted")

    File.rm_rf!(artifact_out_dir)
  end
end
