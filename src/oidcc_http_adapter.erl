%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_http_adapter).

-hank([{unused_callbacks, [{request, 5}]}]).

-include("internal/doc.hrl").
?MODULEDOC("""
HTTP transport adapter.

Adapters perform the transport operation for `oidcc_http_util` and return the
raw response representation used by `httpc:request/5`. OIDCC remains
responsible for telemetry, response decoding, content-type validation, DPoP
nonce handling, and error normalization.

Configure an adapter through the `request_opts` for each outbound operation:

```erlang
Adapter = {my_http_adapter, #{}},

{ok, ProviderPid} =
  oidcc_provider_configuration_worker:start_link(#{
    issuer => <<"https://my.provider">>,
    provider_configuration_opts => #{
      request_opts => #{
        http_adapter => Adapter
      }
    }
  }),

{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(
    ProviderPid,
    <<"client_id">>,
    <<"client_secret">>
  ),

oidcc_token:retrieve(
  AuthCode,
  ClientContext,
  #{
    request_opts => #{
      http_adapter => Adapter
    }
  }
).
```

Elixir modules can implement the same behavior:

```elixir
defmodule MyHttpAdapter do
  @behaviour :oidcc_http_adapter

  @impl true
  def request(method, request, http_options, request_options, config) do
    # Return {:ok, {{http_version, status, reason}, headers, binary_body}}
    # or {:error, reason}.
  end
end

adapter = {MyHttpAdapter, %{}}

{:ok, provider_pid} =
  Oidcc.ProviderConfiguration.Worker.start_link(%{
    issuer: "https://my.provider",
    provider_configuration_opts: %{
      request_opts: %{
        http_adapter: adapter
      }
    }
  })

{:ok, client_context} =
  Oidcc.ClientContext.from_configuration_worker(
    provider_pid,
    "client_id",
    "client_secret"
  )

Oidcc.Token.retrieve(auth_code, client_context, %{
  request_opts: %{
    http_adapter: adapter
  }
})
```

The provider worker's `provider_configuration_opts.request_opts` apply only to
provider discovery and JWKS requests. They are not copied into token, userinfo,
introspection, registration, or authorization options. Configure
`request_opts.http_adapter` for both paths when both need the adapter.

The complete request tuple, including its original URL, is passed to the
adapter unchanged. An adapter must return:

* the raw status-line tuple `{HttpVersion, Status, Reason}`;
* headers in the representation expected by `oidcc_http_util`;
* a binary response body; or
* `{error, Reason}` for a transport failure.

Response header names must be lower-case byte strings as returned by `httpc`.
Header values may be any iodata accepted by `httpc`.

Adapters control redirect handling and response-body collection. Security-aware
adapters must not follow redirects implicitly. They must resolve and validate
each redirect destination before connecting, and enforce response-size limits
while receiving the body.

Adapters may emit their own telemetry. The telemetry span owned by
`oidcc_http_util` remains authoritative for OIDCC HTTP operations.
""").

-export_type([config/0]).
-export_type([header/0]).
-export_type([http_options/0]).
-export_type([method/0]).
-export_type([request/0]).
-export_type([request_body/0]).
-export_type([request_options/0]).
-export_type([response/0]).

?DOC("Adapter module and adapter-specific configuration.").
-type config() :: {module(), map()}.

?DOC("HTTP method accepted by `httpc:request/5`.").
-type method() :: head | get | put | patch | post | trace | options | delete.

?DOC("HTTP header representation accepted and returned by `httpc:request/5`.").
-type header() :: {Field :: [byte()], Value :: binary() | iolist()}.

?DOC("HTTP request tuple accepted by `httpc:request/5`.").
-type request() ::
    {uri_string:uri_string(), [header()]}
    | {
        uri_string:uri_string(),
        [header()],
        ContentType :: string(),
        request_body()
    }.

?DOC("HTTP request body accepted by `httpc:request/5`.").
-type request_body() ::
    iolist()
    | binary()
    | {
        fun((Accumulator :: term()) -> eof | {ok, iolist(), Accumulator :: term()}),
        Accumulator :: term()
    }
    | {
        chunkify,
        fun((Accumulator :: term()) -> eof | {ok, iolist(), Accumulator :: term()}),
        Accumulator :: term()
    }.

?DOC("""
HTTP options constructed by `oidcc_http_util`.

The list includes the request timeout and, when configured, TLS options.
""").
-type http_options() :: [
    {timeout, timeout()} | {ssl, [ssl:tls_option()]}
].

?DOC("Request options passed to adapters.").
-type request_options() :: [{body_format, binary}].

?DOC("Raw `httpc`-compatible response.").
-type response() ::
    {ok, {
        {
            HttpVersion :: string(),
            Status :: non_neg_integer(),
            Reason :: string()
        },
        [header()],
        binary()
    }}
    | {error, term()}.

?DOC("""
Perform an HTTP request.

`Request` contains the original URL and is passed without transformation.
`HttpOptions` and `RequestOptions` are the values constructed by
`oidcc_http_util`. `AdapterConfig` is the map paired with the adapter module in
`request_opts.http_adapter`.
""").
-callback request(
    Method :: method(),
    Request :: request(),
    HttpOptions :: http_options(),
    RequestOptions :: request_options(),
    AdapterConfig :: map()
) -> response().
