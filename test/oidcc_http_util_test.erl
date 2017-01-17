-module(oidcc_http_util_test).
-include_lib("eunit/include/eunit.hrl").


https_sync_get_test() ->
    application:set_env(oidcc, cacertfile, "./test/GeoTrust_Primary_CA.pem"),
    Url = <<"https://www.geotrust.com">>,
    {ok,#{status := 200} } = oidcc_http_util:sync_http(get,Url,[]),
    application:unset_env(oidcc, cacertfile),
    ok.

http_sync_get_test() ->
    Url1 = <<"http://google.de">>,
    {ok, #{status := 200}} = oidcc_http_util:sync_http(get, Url1, []).

http_async_get_test() ->
    Url1 = <<"http://google.de">>,
    {ok, _Id} = oidcc_http_util:async_http(get, Url1, []),
    receive
        {http, Message} ->
            io:format("received ~p~n",[Message]),
            ok
    end.
