if Code.ensure_loaded?(Req) do
  defmodule Oidcc.HttpClient.Req do
    @moduledoc """
    HTTP client implementation using Req.

    This module is only available when `req` is included as a dependency in your project.

    ## Installation

    Add `req` to your dependencies in `mix.exs`:

        {:req, "~> 0.5"}

    ## Usage

    Configure as the default HTTP client:

        # config/config.exs
        config :oidcc, http_client: Oidcc.HttpClient.Req

    Or use per-request:

        Oidcc.ProviderConfiguration.Worker.start_link(%{
          issuer: "https://example.com",
          provider_configuration_opts: %{
            request_opts: %{http_client: Oidcc.HttpClient.Req}
          }
        })

    ## Options

    Standard options from `Oidcc.HttpClient`:
    * `:timeout` - Request timeout in milliseconds (default: 1 minute)
    * `:ssl` - SSL/TLS options (passed to Req's `:connect_options`)
    """
    @moduledoc since: "3.8.0"

    @behaviour Oidcc.HttpClient

    @impl true
    def request(request, opts) do
      %{method: method, url: url, headers: headers} = request
      body = Map.get(request, :body)
      timeout = Map.get(opts, :timeout, :timer.minutes(1))

      req_opts =
        [
          method: method,
          url: to_string(url),
          headers: normalize_request_headers(headers),
          body: body,
          receive_timeout: timeout,
          decode_body: false
        ]
        |> maybe_add_ssl_opts(opts)

      case Req.request(req_opts) do
        {:ok, %Req.Response{status: status, headers: resp_headers, body: resp_body}} ->
          {:ok,
           %{
             status: status,
             headers: normalize_response_headers(resp_headers),
             body: resp_body
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end

    defp maybe_add_ssl_opts(req_opts, %{ssl: ssl_opts}) when is_list(ssl_opts) do
      Keyword.put(req_opts, :connect_options, ssl: ssl_opts)
    end

    defp maybe_add_ssl_opts(req_opts, _opts), do: req_opts

    # Convert request headers from Erlang charlists to Elixir strings
    defp normalize_request_headers(headers) do
      Enum.map(headers, fn {key, value} ->
        {to_string(key), to_string(value)}
      end)
    end

    # Req returns headers as a map %{binary => [binary]}
    # We need to convert them to [{charlist, charlist}] to match httpc format
    # that oidcc_http_util expects
    defp normalize_response_headers(headers) when is_map(headers) do
      Enum.flat_map(headers, fn {key, values} ->
        Enum.map(List.wrap(values), fn value ->
          {to_charlist(String.downcase(key)), to_charlist(value)}
        end)
      end)
    end
  end
end
