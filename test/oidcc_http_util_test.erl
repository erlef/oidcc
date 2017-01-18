-module(oidcc_http_util_test).
-include_lib("eunit/include/eunit.hrl").


https_sync_get_test() ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, "/etc/ssl/certs/ca-certificates.crt"),
    Url = <<"https://www.google.com">>,
    {ok,#{status := 200} } = oidcc_http_util:sync_http(get,Url,[]),
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok.

https_async_get_test() ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, "/etc/ssl/certs/ca-certificates.crt"),
    Url = <<"https://www.google.com">>,
    {ok, Id} = oidcc_http_util:async_http(get,Url,[]),
    receive
        {http, {Id, _Result}} ->
            ok
    end,
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok.

http_sync_get_test() ->
    Url1 = <<"http://google.de">>,
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, []).

http_async_get_test() ->
    Url1 = <<"http://google.de">>,
    {ok, Id} = oidcc_http_util:async_http(get, Url1, []),
    receive
        {http, {Id, _Result}} ->
            ok
    end.
