-module(oidcc_http_util_test).
-include_lib("eunit/include/eunit.hrl").


https_sync_get_test() ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, "/etc/ssl/certs/ca-certificates.crt"),
    Url = <<"https://www.openid.net">>,
    {ok,#{status := 200} } = oidcc_http_util:sync_http(get,Url,[]),
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok.

https_async_get_test() ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, "/etc/ssl/certs/ca-certificates.crt"),
    Url = <<"https://www.openid.net">>,
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


http_cache_test() ->
    application:set_env(oidcc, http_cache_duration, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:unset_env(oidcc, http_cache_duration),

    Url1 = <<"http://google.de">>,
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, [], true),
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, [], true),
    timer:sleep(1),
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, [], true),


    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 50),
    ok.
