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
    perform_request(Method, Url, Header, undefined, <<>>, [], UseCache).

sync_http(Method, Url, Header, ContentType, Body, UseCache) ->
    perform_request(Method, Url, Header, ContentType, Body, [], UseCache).

async_http(Method, Url, Header) ->
    async_http(Method, Url, Header, undefined, <<>>).

async_http(Method, Url, Header, ContentType, Body) ->
    RequestId = erlang:make_ref(),
    Caller = self(),
    spawn_link(fun() ->
                  async_http_perform(Caller, RequestId, Method, Url, Header, ContentType, Body)
               end),
    {ok, RequestId}.

async_http_perform(Caller, RequestId, Method, Url, Header, ContentType, Body) ->
    Response =
        case perform_request(Method, Url, Header, ContentType, Body, [], false) of
            {error, _} = Error ->
                Error;
            {ok,
             #{status := StatusCode,
               header := RespHeaders,
               body := InBody}} ->
                {{<<>>, StatusCode, <<>>}, RespHeaders, InBody}
        end,
    Caller ! {http, {RequestId, Response}}.

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

perform_request(Method, Url, Header, ContentType, Body, Options, true) ->
    case oidcc_http_cache:lookup_http_call(Method, {Method, Url, Header, ContentType, Body})
    of
        {ok, pending} ->
            wait_for_cache(Method, {Method, Url, Header, ContentType, Body});
        {ok, Res} ->
            Res;
        {error, _} ->
            request_or_wait(Method, Url, Header, ContentType, Body, Options)
    end;
perform_request(Method, Url, Header, ContentType, Body, Options, false) ->
    perform_http_request(Method, Url, Header, ContentType, Body, Options).

perform_http_request(Method, Url, Header, ContentType, Body, Options) ->
    Headers1 =
        case ContentType of
            undefined ->
                Header;
            _ ->
                [{<<"content-type">>, ContentType} | Header]
        end,
    Res = hackney:request(Method, Url, Headers1, Body, Options ++ [{follow_redirect, true}]),
    normalize_result(Res).

request_or_wait(Method, Url, Header, ContentType, Body, Options) ->
    case oidcc_http_cache:enqueue_http_call(Method, {Method, Url, Header, ContentType, Body})
    of
        true ->
            Result = perform_http_request(Method, Url, Header, ContentType, Body, Options),
            ok =
                oidcc_http_cache:cache_http_result(Method,
                                                   {Method, Url, Header, ContentType, Body},
                                                   Result),
            Result;
        _ ->
            wait_for_cache(Method, {Method, Url, Header, ContentType, Body})
    end.

wait_for_cache(Method, Request) ->
    case oidcc_http_cache:lookup_http_call(Method, Request) of
        {ok, pending} ->
            timer:sleep(500),
            wait_for_cache(Method, Request);
        {ok, Result} ->
            Result
    end.

normalize_result({ok, StatusCode, RespHeaders, ClientRef}) ->
    {ok, Body} = hackney:body(ClientRef),
    {ok,
     #{status => StatusCode,
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
