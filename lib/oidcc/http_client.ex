defmodule Oidcc.HttpClient do
  @moduledoc """
  HTTP Client behaviour for OIDC requests.

  Implement this behaviour to use a custom HTTP client with oidcc.
  By default, oidcc uses Erlang's built-in `httpc` via `:oidcc_http_client_httpc`.

  ## Included Implementations

  * `:oidcc_http_client_httpc` - Default, uses Erlang's built-in `httpc`
  * `Oidcc.HttpClient.Req` - Uses [Req](https://hex.pm/packages/req) (requires `{:req, "~> 0.5"}` dependency)

  ## Configuration

  Set as application config:

      # config/config.exs
      config :oidcc, http_client: Oidcc.HttpClient.Req

  Or per-request via `request_opts`:

      Oidcc.ProviderConfiguration.Worker.start_link(%{
        issuer: "https://example.com",
        provider_configuration_opts: %{
          request_opts: %{http_client: Oidcc.HttpClient.Req}
        }
      })

  ## Implementing a Custom Client

  See `Oidcc.HttpClient.Req` for a complete implementation example.

  Key considerations:

  * Convert `url` to string - it may be an Erlang charlist
  * Normalize request headers from charlists to strings
  * Return response headers as `[{charlist(), charlist()}]` (lowercase keys)
  * Return the raw response body as binary (set `decode_body: false` or equivalent)

  For Erlang examples, see `:oidcc_http_client`.
  """
  @moduledoc since: "3.8.0"

  @typedoc """
  HTTP request specification.

  * `:method` - HTTP method
  * `:url` - Request URL
  * `:headers` - Request headers as list of tuples
  * `:body` - Optional request body (for POST, PUT, PATCH)
  """
  @typedoc since: "3.8.0"
  @type request :: %{
          required(:method) => :head | :get | :put | :patch | :post | :trace | :options | :delete,
          required(:url) => :uri_string.uri_string(),
          required(:headers) => [{String.t() | charlist(), iodata()}],
          optional(:body) => iodata()
        }

  @typedoc """
  HTTP response specification.

  * `:status` - HTTP status code
  * `:headers` - Response headers as list of tuples
  * `:body` - Response body as binary
  """
  @typedoc since: "3.8.0"
  @type response :: %{
          required(:status) => pos_integer(),
          required(:headers) => [{String.t() | charlist(), iodata()}],
          required(:body) => binary()
        }

  @typedoc """
  Options passed to the HTTP client implementation.

  Standard options:
  * `:timeout` - Request timeout in milliseconds
  * `:ssl` - SSL/TLS options (see `:ssl.tls_option()`)

  For the default `:oidcc_http_client_httpc`:
  * `:httpc_profile` - httpc profile to use
  """
  @typedoc since: "3.8.0"
  @type opts :: %{
          optional(:timeout) => timeout(),
          optional(:ssl) => [:ssl.tls_option()],
          optional(:httpc_profile) => atom() | pid(),
          optional(atom()) => term()
        }

  @doc """
  Perform an HTTP request.

  The implementation should:
  1. Execute the HTTP request according to `request`
  2. Return `{:ok, response}` on success (HTTP 1xx-5xx)
  3. Return `{:error, reason}` on connection/transport errors
  """
  @doc since: "3.8.0"
  @callback request(request :: request(), opts :: opts()) ::
              {:ok, response()} | {:error, term()}
end
