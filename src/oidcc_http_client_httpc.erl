-module(oidcc_http_client_httpc).

-feature(maybe_expr, enable).

-behaviour(oidcc_http_client).

-include("internal/doc.hrl").
?MODULEDOC("""
Default HTTP client implementation using Erlang's built-in `httpc`.

This is the default HTTP client used by oidcc. It wraps `httpc:request/5` from
the `inets` application.

## Options

* `timeout` - Request timeout in milliseconds (default: 1 minute)
* `ssl` - SSL/TLS options (see `ssl:tls_option()`)
* `httpc_profile` - httpc profile to use (default: `default`)

## Example

```erlang
oidcc_provider_configuration:load_configuration(Issuer, #{
    request_opts => #{
        timeout => 30000,
        ssl => [{verify, verify_peer}, {cacerts, public_key:cacerts_get()}],
        httpc_profile => my_profile
    }
}).
```
""").
?MODULEDOC(#{since => <<"3.8.0">>}).

-export([request/2]).

?DOC(false).
-spec request(Request, Opts) -> {ok, Response} | {error, Error} when
    Request :: oidcc_http_client:request(),
    Opts :: oidcc_http_client:http_client_opts(),
    Response :: oidcc_http_client:response(),
    Error :: oidcc_http_client:error().
request(Request, Opts) ->
    #{method := Method, url := Url, headers := Headers} = Request,
    Body = maps:get(body, Request, <<>>),

    Timeout = maps:get(timeout, Opts, timer:minutes(1)),
    SslOpts = maps:get(ssl, Opts, undefined),
    HttpProfile = maps:get(httpc_profile, Opts, default),

    HttpcRequest = build_httpc_request(Method, Url, Headers, Body),
    HttpOpts = build_http_opts(Timeout, SslOpts),

    case httpc:request(Method, HttpcRequest, HttpOpts, [{body_format, binary}], HttpProfile) of
        {ok, {{_HttpVersion, Status, _Reason}, RespHeaders, RespBody}} ->
            {ok, #{
                status => Status,
                headers => RespHeaders,
                body => RespBody
            }};
        {error, Reason} ->
            {error, Reason}
    end.

-spec build_httpc_request(Method, Url, Headers, Body) -> HttpcRequest when
    Method :: head | get | put | patch | post | trace | options | delete,
    Url :: uri_string:uri_string(),
    Headers :: [oidcc_http_client:header()],
    Body :: iodata(),
    HttpcRequest :: {uri_string:uri_string(), [oidcc_http_client:header()]}
        | {uri_string:uri_string(), [oidcc_http_client:header()], string(), iodata()}.
build_httpc_request(Method, Url, Headers, _Body) when
    Method =:= get; Method =:= head; Method =:= options; Method =:= delete; Method =:= trace
->
    {Url, Headers};
build_httpc_request(_Method, Url, Headers, Body) ->
    ContentType = proplists:get_value("content-type", Headers, "application/x-www-form-urlencoded"),
    {Url, Headers, ContentType, Body}.

-spec build_http_opts(Timeout, SslOpts) -> HttpOpts when
    Timeout :: timeout(),
    SslOpts :: [ssl:tls_option()] | undefined,
    HttpOpts :: [{atom(), term()}].
build_http_opts(Timeout, undefined) ->
    [{timeout, Timeout}];
build_http_opts(Timeout, SslOpts) ->
    [{timeout, Timeout}, {ssl, SslOpts}].
