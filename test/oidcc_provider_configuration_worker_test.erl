%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_worker_test).

-include_lib("eunit/include/eunit.hrl").

does_not_start_without_issuer_test() ->
    ?assertMatch(
        {error, issuer_required},
        oidcc_provider_configuration_worker:start_link(#{})
    ).

stops_with_invalid_issuer_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    process_flag(trap_exit, true),

    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{issuer => <<"http://example.com">>}),

    receive
        {'EXIT', Pid, {configuration_load_failed, _Error}} -> ok
    after 10000 ->
        ?assert(false)
    end,

    meck:unload(httpc),

    ok.

retries_with_backoff_with_invalid_issuer_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    process_flag(trap_exit, true),

    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => <<"http://example.com">>,
        backoff_type => random,
        backoff_min => 500,
        backoff_max => 500
    }),

    receive
        {'EXIT', Pid, {configuration_load_failed, _Error}} -> ct:fail(should_not_exit)
    after 1_000 -> ok
    end,

    ?assertMatch(
        {error, provider_not_ready},
        oidcc:create_redirect_url(Pid, <<"client_id">>, <<"client_secret">>, #{
            redirect_uri => "http://example.com"
        })
    ),

    ?assert(meck:num_calls(httpc, request, '_') >= 2),

    meck:unload(httpc),

    ok.

refreshes_with_empty_key_set_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun
            (
                get,
                {"https://example.com/.well-known/openid-configuration", []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"}],
                    jsx:encode(#{
                        issuer => <<"https://example.com">>,
                        jwks_uri => <<"https://example.com/keys">>,
                        authorization_endpoint => <<"https://example.com/authorize">>,
                        scopes_supported => [<<"openid">>],
                        response_types_supported => [<<"code">>],
                        subject_types_supported => [<<"public">>],
                        id_token_signing_alg_values_supported => [<<"RS256">>]
                    })
                }};
            (
                get,
                {<<"https://example.com/keys">>, []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"}],
                    jsx:encode(#{keys => []})
                }}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    process_flag(trap_exit, true),

    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => <<"https://example.com">>,
        backoff_type => random,
        backoff_min => 500,
        backoff_max => 500
    }),

    ok = oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(Pid, <<"kid">>),

    % Once for Metadata, once for JWKs, and once for JWK refresh
    ?assert(meck:num_calls(httpc, request, '_') >= 3),

    meck:unload(httpc),

    ok.

%% Discovery / JWKS responses carrying `Cache-Control: max-age=0' used to
%% crash the worker because the parser returned the atom `true' as the
%% expiry, which then failed `timer:send_after/2'. After the parser fix
%% (#371) plus the worker's `safe_send_after/2' guard, any such bad
%% expiry — including the literal `max-age=0' — flows through the
%% backoff/retry path and the worker keeps running.
survives_cache_control_max_age_zero_test() ->
    ok = meck:new(httpc, [no_link]),
    DiscoveryBody = jsx:encode(#{
        issuer => <<"https://example.com">>,
        jwks_uri => <<"https://example.com/keys">>,
        authorization_endpoint => <<"https://example.com/authorize">>,
        scopes_supported => [<<"openid">>],
        response_types_supported => [<<"code">>],
        subject_types_supported => [<<"public">>],
        id_token_signing_alg_values_supported => [<<"RS256">>]
    }),
    HttpFun =
        fun
            (
                get,
                {"https://example.com/.well-known/openid-configuration", []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [
                        {"content-type", "application/json"},
                        {"cache-control", "max-age=0, no-store"}
                    ],
                    DiscoveryBody
                }};
            (
                get,
                {<<"https://example.com/keys">>, []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [
                        {"content-type", "application/json"},
                        {"cache-control", "max-age=0, no-store"}
                    ],
                    jsx:encode(#{keys => []})
                }}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    process_flag(trap_exit, true),

    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => <<"https://example.com">>,
        backoff_type => random,
        backoff_min => 500,
        backoff_max => 500
    }),

    ?assertNotEqual(
        undefined,
        wait_until(fun() -> oidcc_provider_configuration_worker:get_provider_configuration(Pid) end)
    ),
    ?assert(is_process_alive(Pid)),

    meck:unload(httpc),
    ok.

wait_until(Fun) ->
    wait_until(Fun, 20).

wait_until(Fun, 0) ->
    Fun();
wait_until(Fun, Retries) ->
    case Fun() of
        undefined ->
            timer:sleep(50),
            wait_until(Fun, Retries - 1);
        Value ->
            Value
    end.
