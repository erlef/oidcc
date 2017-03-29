-module(oidcc_http_util_test).
-include_lib("eunit/include/eunit.hrl").

ca_file() ->
    code:where_is_file("cacert.pem").

https_bad_config_test() ->
    Url = <<"https://www.openid.net">>,
    ?assertEqual({error, missing_cacertfile},
                 oidcc_http_util:sync_http(get,Url,[])),
    ok.


https_sync_get_openid_test() ->
    Url = <<"https://www.openid.net">>,
    https_sync_request(Url, 2).

https_sync_get_google_test() ->
    Url = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    https_sync_request(Url, 2).

https_sync_request(Url, Depth) ->
    application:set_env(oidcc, cert_depth, Depth),
    application:set_env(oidcc, cacertfile, ca_file()),
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get,Url,[]),
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok.

https_sync_get_cache_test() ->
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, ca_file()),
    Url = <<"https://www.openid.net">>,
    {ok,#{status := 200} } = oidcc_http_util:sync_http(get,Url,[], true),
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 50),
    ok.

https_async_get_test() ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, ca_file()),
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
    application:set_env(oidcc, http_cache_duration, 2),
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:unset_env(oidcc, http_cache_duration),

    Url1 = <<"http://google.de">>,
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, [], true),
    timer:sleep(1),
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, [], true),


    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 50),
    ok.


basic_parallel_test() ->
    parallel_request(50).

advanced_parallel_test() ->
    parallel_request(1000).

extreme_parallel_test() ->
    parallel_request(10000).

parallel_request(NumRequests) ->
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, cacertfile, ca_file()),
    application:set_env(oidcc, http_cache_duration, 60),
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:unset_env(oidcc, http_cache_duration),

    Url = <<"https://openid.net">>,
    ok = start_requests(self(), Url, NumRequests),
    timer:sleep(1),
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url, [], true),

    ok = receive_oks(NumRequests),
    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 50),
    application:unset_env(oidcc, cert_depth),
    application:unset_env(oidcc, cacertfile),
    ok.

start_requests(_Pid, _Url, 0) ->
    ok;
start_requests(Pid, Url, Num) ->
    start_request(Pid, Url),
    start_requests(Pid, Url, Num - 1).

start_request(Pid, Url) ->
    Fun = fun() ->
                  case oidcc_http_util:sync_http(get, Url, [], true) of
                      {ok, #{status := 200}} ->
                          Pid ! ok;
                      Other ->
                          Pid ! {error, Other}
                  end
          end,
    spawn(Fun).

receive_oks(0) ->
    ok;
receive_oks(Num) ->
    ok = receive
             ok ->
                 ok;
             Other  ->
                 Other
         end,
    receive_oks(Num -1).
