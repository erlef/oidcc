%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

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

    %% RFC 7234 §5.2 — directive names are case-insensitive.
    ?assertEqual(
        timer:seconds(300),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "Public, Max-Age=300"}], 1000
        )
    ),
    ?assertEqual(
        timer:seconds(300),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "MAX-AGE=300"}], 1000
        )
    ),

    %% `max-age' present but with no following value -> fall back.
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age"}], 1000
        )
    ),
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age="}], 1000
        )
    ),

    %% Non-numeric value -> fall back.
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=forever"}], 1000
        )
    ),

    %% Over-eager providers may advertise a max-age beyond what
    %% `erlang:send_after/3,4' / `timer:send_after/2,3' accept
    %% (16#FFFFFFFF ms ~ 49.7 d). Clamp to the safe upper bound.
    ?assertEqual(
        16#FFFFFFFF,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=99999999999"}], 1000
        )
    ),

    ok.
