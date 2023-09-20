defmodule Conformance.Screenshot do
  def take do
    config =
      Application.get_env(:conformance, __MODULE__, [])
      |> IO.inspect()

    if Keyword.get(config, :enable, false) do
      path = adjust_path(Keyword.fetch!(config, :path))
      {_out, 0} = System.cmd("gnome-screenshot", ["--window", "--file", path])
      {_out, 0} = System.cmd("optipng", [path])
    end
  end

  defp adjust_path(path, num \\ 1) do
    if File.exists?(path) do
      new_path = "#{Path.rootname(path)}-#{num}#{Path.extname(path)}"

      if File.exists?(new_path) do
        adjust_path(path, num + 1)
      else
        new_path
      end
    else
      path
    end
  end
end
