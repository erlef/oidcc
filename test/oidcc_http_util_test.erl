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

headers_to_cache_deadline_age_test() ->
    %% RFC 7234 §5.1 / §4.2: a document a shared cache has already held for
    %% `Age' seconds has that much less of its stated lifetime left.
    ?assertEqual(
        timer:seconds(240),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=300"}, {"age", "60"}], 1000
        )
    ),

    %% Nothing left. Zero is honest here; holding the deadline above a usable
    %% refresh interval is the caller's job.
    ?assertEqual(
        0,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=300"}, {"age", "300"}], 1000
        )
    ),
    ?assertEqual(
        0,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=300"}, {"age", "3600"}], 1000
        )
    ),

    %% `Age' never reduces the caller's fallback, which is a refresh interval
    %% rather than a lifetime the server claimed.
    ?assertEqual(
        timer:seconds(1000),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "public"}, {"age", "60"}], timer:seconds(1000)
        )
    ),
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline([{"age", "60"}], 1000)
    ),
    ?assertEqual(
        1000,
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=0"}, {"age", "60"}], 1000
        )
    ),

    %% A malformed, negative or multi-valued `Age' contributes nothing rather
    %% than shortening the lifetime.
    lists:foreach(
        fun(Age) ->
            ?assertEqual(
                timer:seconds(300),
                oidcc_http_util:headers_to_cache_deadline(
                    [{"cache-control", "max-age=300"}, {"age", Age}], 1000
                ),
                Age
            )
        end,
        ["later", "-60", "60.5", "60, 120", ""]
    ),

    %% The upper clamp still applies, and is applied before the subtraction.
    ?assertEqual(
        16#FFFFFFFF - timer:seconds(10),
        oidcc_http_util:headers_to_cache_deadline(
            [{"cache-control", "max-age=99999999999"}, {"age", "10"}], 1000
        )
    ),

    ok.
