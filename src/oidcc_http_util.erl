-module(oidcc_http_util).

-export([async_http/3, async_http/5]).
-export([sync_http/3, sync_http/5]).
-export([sync_http/4, sync_http/6]).
-export([uncompress_body_if_needed/2]).
-export([request_timeout/1]).

-include_lib("public_key/include/public_key.hrl").

sync_http(Method, Url, Header) ->
    sync_http(Method, Url, Header, false).

sync_http(Method, Url, Header, ContentType, Body) ->
    sync_http(Method, Url, Header, ContentType, Body, false).

sync_http(Method, Url, Header, UseCache) ->
    perform_request(Method,
                    Url,
                    Header,
                    undefined,
                    undefined,
                    [{body_format, binary}],
                    UseCache).

sync_http(Method, Url, Header, ContentType, Body, UseCache) ->
    perform_request(Method,
                    Url,
                    Header,
                    ContentType,
                    Body,
                    [{body_format, binary}],
                    UseCache).

async_http(Method, Url, Header) ->
    perform_request(Method, Url, Header, undefined, undefined, [{sync, false}], false).

async_http(Method, Url, Header, ContentType, Body) ->
    perform_request(Method, Url, Header, ContentType, Body, [{sync, false}], false).

request_timeout(Unit) ->
    Timeout =
        case application:get_env(oidcc, http_request_timeout, undefined) of
            T when is_integer(T), T > 0 ->
                T;
            _ ->
                300
        end,
    case Unit of
        ms ->
            Timeout * 1000;
        s ->
            Timeout
    end.

perform_request(Method, Url, Header, ContentType, Body, Options, UseCache) ->
    case options(Url) of
        {ok, HttpOptions} ->
            Request = gen_request(Url, Header, ContentType, Body),
            perform_request_or_lookup_cache(Method, Request, HttpOptions, Options, UseCache);
        Error ->
            Error
    end.

perform_request_or_lookup_cache(Method, Request, HttpOptions, Options, true) ->
    case oidcc_http_cache:lookup_http_call(Method, Request) of
        {ok, pending} ->
            wait_for_cache(Method, Request);
        {ok, Res} ->
            Res;
        {error, _} ->
            request_or_wait(Method, Request, HttpOptions, Options)
    end;
perform_request_or_lookup_cache(Method, Request, HttpOptions, Options, false) ->
    perform_http_request(Method, Request, HttpOptions, Options).

perform_http_request(Method, Request, HttpOptions, Options) ->
    Res = httpc:request(Method, Request, HttpOptions, Options),
    normalize_result(Res).

request_or_wait(Method, Request, HttpOpts, Opts) ->
    case oidcc_http_cache:enqueue_http_call(Method, Request) of
        true ->
            Result = perform_http_request(Method, Request, HttpOpts, Opts),
            ok = oidcc_http_cache:cache_http_result(Method, Request, Result),
            Result;
        _ ->
            wait_for_cache(Method, Request)
    end.

wait_for_cache(Method, Request) ->
    case oidcc_http_cache:lookup_http_call(Method, Request) of
        {ok, pending} ->
            timer:sleep(500),
            wait_for_cache(Method, Request);
        {ok, Result} ->
            Result
    end.

gen_request(Url, Header, undefined, undefined) ->
    {normalize(Url), normalize_headers(Header)};
gen_request(Url, Header, ContentType, Body) ->
    {normalize(Url), normalize_headers(Header), normalize(ContentType), Body}.

normalize_result({ok, {{_Proto, Status, _StatusName}, RespHeaders, Body}}) ->
    {ok,
     #{status => Status,
       header => RespHeaders,
       body => Body}};
normalize_result({ok, StreamId}) ->
    {ok, StreamId};
normalize_result({error, _} = Error) ->
    Error.

uncompress_body_if_needed(Body, Header) when is_list(Header) ->
    Encoding = lists:keyfind(<<"content-encoding">>, 1, Header),
    uncompress_body_if_needed(Body, Encoding);
uncompress_body_if_needed(Body, false) ->
    {ok, Body};
uncompress_body_if_needed(Body, {_, <<"gzip">>}) ->
    {ok, zlib:gunzip(Body)};
uncompress_body_if_needed(Body, {_, <<"deflate">>}) ->
    Z = zlib:open(),
    ok = zlib:inflateInit(Z),
    {ok, zlib:inflate(Z, Body)};
uncompress_body_if_needed(_Body, {_, Compression}) ->
    erlang:error({unsupported_encoding, Compression}).

options(Url) when is_list(Url) ->
    #{scheme := Schema} = uri_string:parse(normalize(Url)),
    BaseOptions = [{timeout, request_timeout(ms)}],
    case Schema of
        "http" ->
            {ok, BaseOptions};
        "https" ->
            ssl_options(BaseOptions)
    end;
options(Url) when is_binary(Url) ->
    options(binary_to_list(Url)).

ssl_options(BaseOptions) ->
    CaCert = application:get_env(oidcc, cacertfile),
    Depth = application:get_env(oidcc, cert_depth, 1),
    case CaCert of
        {ok, CaCertFile} ->
            {ok,
             [{ssl,
               [{verify, verify_peer},
                {verify_fun, {fun ssl_verify_hostname:verify_fun/3, []}},
                {customize_hostname_check,
                 [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]},
                {cacertfile, CaCertFile},
                {depth, Depth}]}]
             ++ BaseOptions};
        _ ->
            {error, missing_cacertfile}
    end.

normalize(L) when is_list(L) ->
    L;
normalize(B) when is_binary(B) ->
    binary_to_list(B).

normalize_headers(L) when is_list(L) ->
    [normalize_header(K, V) || {K, V} <- L].

normalize_header(K, V) ->
    {normalize(K), normalize(V)}.
