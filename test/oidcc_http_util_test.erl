-module(oidcc_http_util_test).

-include_lib("eunit/include/eunit.hrl").

headers_to_cache_deadline_test() ->
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline([], 1000)
    ),
    ?assertEqual(
        timer:seconds(300),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "no-store, no-cache, max-age=300"}], 1000
        )
    ),
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "no-store, no-cache, max-age=0"}], 1000
        )
    ),

    ok.
