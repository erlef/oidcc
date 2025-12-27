-module(oidcc_http_client).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
HTTP Client Behaviour for OIDC requests.

Implement this behaviour to use a custom HTTP client with oidcc.

## Example

```erlang
-module(my_hackney_client).
-behaviour(oidcc_http_client).
-export([request/2]).

request(#{method := Method, url := Url, headers := Headers} = Request, Opts) ->
    Body = maps:get(body, Request, <<>>),
    Timeout = maps:get(timeout, Opts, 60000),

    case hackney:request(Method, Url, Headers, Body, [{recv_timeout, Timeout}]) of
        {ok, Status, RespHeaders, ClientRef} ->
            {ok, RespBody} = hackney:body(ClientRef),
            {ok, #{status => Status, headers => RespHeaders, body => RespBody}};
        {error, Reason} ->
            {error, Reason}
    end.
```

## Configuration

Set as application config:

```erlang
application:set_env(oidcc, http_client, my_hackney_client).
```

Or per-request via `request_opts`:

```erlang
oidcc_provider_configuration:load_configuration(Issuer, #{
    request_opts => #{http_client => my_hackney_client}
}).
```
""").
?MODULEDOC(#{since => <<"3.8.0">>}).

-export_type([request/0, response/0, header/0, http_client/0, http_client_opts/0, error/0]).

?DOC("HTTP request specification").
?DOC(#{since => <<"3.8.0">>}).
-type request() :: #{
    method := head | get | put | patch | post | trace | options | delete,
    url := uri_string:uri_string(),
    headers := [header()],
    body => iodata()
}.

?DOC("HTTP header tuple").
?DOC(#{since => <<"3.8.0">>}).
-type header() :: {binary() | string(), iodata()}.

?DOC("HTTP response specification").
?DOC(#{since => <<"3.8.0">>}).
-type response() :: #{
    status := pos_integer(),
    headers := [header()],
    body := binary()
}.

?DOC("HTTP client module or tuple with module and extra options").
?DOC(#{since => <<"3.8.0">>}).
-type http_client() :: module() | {module(), http_client_opts()}.

?DOC("""
Options passed to the HTTP client implementation.

Standard options:
* `timeout` - Request timeout in milliseconds
* `ssl` - SSL/TLS options (see `ssl:tls_option()`)

For the default `oidcc_http_client_httpc`:
* `httpc_profile` - httpc profile to use (see `httpc:request/5`)
""").
?DOC(#{since => <<"3.8.0">>}).
-type http_client_opts() :: #{
    timeout => timeout(),
    ssl => [ssl:tls_option()],
    httpc_profile => atom() | pid(),
    atom() => term()
}.

?DOC("HTTP client error").
?DOC(#{since => <<"3.8.0">>}).
-type error() :: term().

?DOC("""
Perform an HTTP request.

The implementation should:
1. Execute the HTTP request according to `Request`
2. Return `{ok, Response}` on success (HTTP 1xx-5xx)
3. Return `{error, Reason}` on connection/transport errors
""").
?DOC(#{since => <<"3.8.0">>}).
-callback request(Request, Opts) -> {ok, Response} | {error, Error} when
    Request :: request(),
    Opts :: http_client_opts(),
    Response :: response(),
    Error :: error().
