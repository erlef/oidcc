%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_worker_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").

does_not_start_without_issuer_test() ->
    ?assertMatch(
        {error, issuer_required},
        oidcc_provider_configuration_worker:start_link(#{})
    ).

stops_with_invalid_issuer_test() ->
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,

    with_httpc_mock(HttpFun, fun() ->
        with_stopping_provider_worker(#{issuer => <<"http://example.com">>}, fun(Pid) ->
            receive
                {'EXIT', Pid, {configuration_load_failed, _Error}} ->
                    ok;
                {'EXIT', Pid, Reason} ->
                    ct:fail({unexpected_exit, Reason})
            after 1_000 ->
                ?assert(false)
            end
        end)
    end).

retries_with_backoff_with_invalid_issuer_test() ->
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,

    with_httpc_mock(HttpFun, fun() ->
        with_live_provider_worker(
            #{
                issuer => <<"http://example.com">>,
                backoff_type => random,
                backoff_min => 500,
                backoff_max => 500
            },
            fun(Pid) ->
                receive
                    {'EXIT', Pid, Reason} ->
                        ct:fail({unexpected_exit, Reason})
                after 1_000 ->
                    ok
                end,

                ?assertMatch(
                    {error, provider_not_ready},
                    oidcc:create_redirect_url(Pid, <<"client_id">>, <<"client_secret">>, #{
                        redirect_uri => "http://example.com"
                    })
                ),

                ?assert(meck:num_calls(httpc, request, '_') >= 2)
            end
        )
    end).

refreshes_with_empty_key_set_test() ->
    Adapter = provider_adapter(self()),

    with_live_provider_worker(
        #{
            issuer => <<"https://example.com">>,
            provider_configuration_opts => #{
                request_opts => #{http_adapter => Adapter}
            },
            backoff_type => random,
            backoff_min => 500,
            backoff_max => 500
        },
        fun(Pid) ->
            ?assertMatch(
                #jose_jwk{keys = {jose_jwk_set, []}},
                wait_until(fun() -> oidcc_provider_configuration_worker:get_jwks(Pid) end)
            ),
            assert_adapter_request(<<"https://example.com/.well-known/openid-configuration">>),
            assert_adapter_request(<<"https://example.com/keys">>),

            ok = oidcc_provider_configuration_worker:refresh_configuration(Pid),
            assert_adapter_request(<<"https://example.com/.well-known/openid-configuration">>),

            ok = oidcc_provider_configuration_worker:refresh_jwks(Pid),
            assert_adapter_request(<<"https://example.com/keys">>),

            ok = oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(Pid, <<"kid">>),
            assert_adapter_request(<<"https://example.com/keys">>)
        end
    ).

refreshes_in_background_with_adapter_test() ->
    Adapter = background_provider_adapter(self()),

    with_live_provider_worker(
        #{
            issuer => <<"https://example.com">>,
            provider_configuration_opts => #{
                fallback_expiry => 50,
                request_opts => #{http_adapter => Adapter}
            }
        },
        fun(Pid) ->
            ?assertMatch(
                #jose_jwk{keys = {jose_jwk_set, []}},
                wait_until(fun() -> oidcc_provider_configuration_worker:get_jwks(Pid) end)
            ),
            assert_adapter_request(1, <<"https://example.com/.well-known/openid-configuration">>),
            assert_adapter_request(2, <<"https://example.com/keys">>),
            assert_background_adapter_refresh()
        end
    ).

%% Discovery / JWKS responses carrying `Cache-Control: max-age=0' used to
%% crash the worker because the parser returned the atom `true' as the
%% expiry, which then failed `timer:send_after/2'. After the parser fix
%% (#371) plus the worker's `safe_send_after/2' guard, any such bad
%% expiry — including the literal `max-age=0' — flows through the
%% backoff/retry path and the worker keeps running.
survives_cache_control_max_age_zero_test() ->
    DiscoveryBody = iolist_to_binary(
        json:encode(#{
            issuer => <<"https://example.com">>,
            jwks_uri => <<"https://example.com/keys">>,
            authorization_endpoint => <<"https://example.com/authorize">>,
            scopes_supported => [<<"openid">>],
            response_types_supported => [<<"code">>],
            subject_types_supported => [<<"public">>],
            id_token_signing_alg_values_supported => [<<"RS256">>]
        })
    ),
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
                    iolist_to_binary(json:encode(#{keys => []}))
                }}
        end,

    with_httpc_mock(HttpFun, fun() ->
        with_live_provider_worker(
            #{
                issuer => <<"https://example.com">>,
                backoff_type => random,
                backoff_min => 500,
                backoff_max => 500
            },
            fun(Pid) ->
                ?assertNotEqual(
                    undefined,
                    wait_until(fun() ->
                        oidcc_provider_configuration_worker:get_provider_configuration(Pid)
                    end)
                ),
                ?assert(is_process_alive(Pid))
            end
        )
    end).

%% RFC 6838 §4.2.8 — `application/<subtype>+json' content-types are JSON
%% with extra contract. Previously only `application/jwk-set+json' was
%% special-cased; any other `+json' subtype (`application/jose+json',
%% vendor-prefixed variants, etc.) fell into the `unknown' branch and
%% the JWKS load failed with `invalid_content_type'.
accepts_generic_plus_json_content_type_test() ->
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
                    iolist_to_binary(
                        json:encode(#{
                            issuer => <<"https://example.com">>,
                            jwks_uri => <<"https://example.com/keys">>,
                            authorization_endpoint => <<"https://example.com/authorize">>,
                            scopes_supported => [<<"openid">>],
                            response_types_supported => [<<"code">>],
                            subject_types_supported => [<<"public">>],
                            id_token_signing_alg_values_supported => [<<"RS256">>]
                        })
                    )
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
                    [{"content-type", "application/vnd.example+json; charset=utf-8"}],
                    iolist_to_binary(json:encode(#{keys => []}))
                }}
        end,

    with_httpc_mock(HttpFun, fun() ->
        with_live_provider_worker(
            #{
                issuer => <<"https://example.com">>,
                backoff_type => random,
                backoff_min => 500,
                backoff_max => 500
            },
            fun(Pid) ->
                ?assertMatch(
                    #jose_jwk{keys = {jose_jwk_set, []}},
                    wait_until(fun() -> oidcc_provider_configuration_worker:get_jwks(Pid) end)
                )
            end
        )
    end).

with_httpc_mock(HttpFun, TestFun) ->
    ok = meck:new(httpc, [no_link]),
    try
        ok = meck:expect(httpc, request, HttpFun),
        TestFun()
    after
        meck:unload(httpc)
    end.

with_live_provider_worker(Options, TestFun) ->
    with_trap_exit(fun() ->
        {ok, Pid} = oidcc_provider_configuration_worker:start_link(Options),
        try
            Result = TestFun(Pid),
            assert_provider_worker_alive(Pid),
            ok = gen_server:stop(Pid),
            ?assertEqual({exit, normal}, receive_provider_worker_exit(Pid)),
            Result
        catch
            Class:Reason:Stacktrace ->
                case stop_provider_worker(Pid) of
                    {exit, normal} ->
                        erlang:raise(Class, Reason, Stacktrace);
                    {exit, WorkerReason} ->
                        ct:fail({provider_worker_exited, WorkerReason});
                    none ->
                        erlang:raise(Class, Reason, Stacktrace)
                end
        end
    end).

with_stopping_provider_worker(Options, TestFun) ->
    with_trap_exit(fun() ->
        {ok, Pid} = oidcc_provider_configuration_worker:start_link(Options),
        try
            TestFun(Pid)
        after
            stop_provider_worker(Pid)
        end
    end).

with_trap_exit(TestFun) ->
    PreviousTrapExit = process_flag(trap_exit, true),
    try
        TestFun()
    after
        process_flag(trap_exit, PreviousTrapExit)
    end.

assert_provider_worker_alive(Pid) ->
    receive
        {'EXIT', Pid, Reason} ->
            ct:fail({provider_worker_exited, Reason})
    after 0 ->
        ?assert(is_process_alive(Pid))
    end.

stop_provider_worker(Pid) ->
    _ = catch gen_server:stop(Pid),
    receive_provider_worker_exit(Pid).

receive_provider_worker_exit(Pid) ->
    receive
        {'EXIT', Pid, Reason} ->
            {exit, Reason}
    after 100 ->
        none
    end.

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

assert_adapter_request(ExpectedUrl) ->
    receive
        {adapter_request, ExpectedUrl} ->
            ok
    after 1_000 ->
        ?assert(false)
    end.

assert_adapter_request(ExpectedRequestNumber, ExpectedUrl) ->
    ?assertEqual(
        {ExpectedRequestNumber, ExpectedUrl},
        receive_adapter_request()
    ).

assert_background_adapter_refresh() ->
    ?assertEqual(
        lists:sort([
            {3, <<"https://example.com/.well-known/openid-configuration">>},
            {4, <<"https://example.com/keys">>}
        ]),
        lists:sort([receive_adapter_request(), receive_adapter_request()])
    ).

receive_adapter_request() ->
    receive
        {adapter_request, RequestNumber, Url} ->
            {RequestNumber, Url}
    after 1_000 ->
        ?assert(false)
    end.

provider_adapter(TestPid) ->
    provider_adapter(TestPid, uncounted).

background_provider_adapter(TestPid) ->
    Counter = atomics:new(1, []),
    provider_adapter(TestPid, {counted, Counter}).

provider_adapter(TestPid, AdapterState) ->
    HttpFun =
        fun
            (
                get,
                {"https://example.com/.well-known/openid-configuration", []},
                _HttpOpts,
                _Opts,
                _AdapterConfig
            ) ->
                Url = <<"https://example.com/.well-known/openid-configuration">>,
                AdditionalHeaders = adapter_response_headers(TestPid, AdapterState, Url),
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"} | AdditionalHeaders],
                    iolist_to_binary(
                        json:encode(#{
                            issuer => <<"https://example.com">>,
                            jwks_uri => <<"https://example.com/keys">>,
                            authorization_endpoint => <<"https://example.com/authorize">>,
                            scopes_supported => [<<"openid">>],
                            response_types_supported => [<<"code">>],
                            subject_types_supported => [<<"public">>],
                            id_token_signing_alg_values_supported => [<<"RS256">>]
                        })
                    )
                }};
            (
                get,
                {<<"https://example.com/keys">>, []},
                _HttpOpts,
                _Opts,
                _AdapterConfig
            ) ->
                Url = <<"https://example.com/keys">>,
                AdditionalHeaders = adapter_response_headers(TestPid, AdapterState, Url),
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"} | AdditionalHeaders],
                    iolist_to_binary(json:encode(#{keys => []}))
                }}
        end,
    {oidcc_http_adapter_test, #{request => HttpFun}}.

adapter_response_headers(TestPid, uncounted, Url) ->
    TestPid ! {adapter_request, Url},
    [];
adapter_response_headers(TestPid, {counted, Counter}, Url) ->
    RequestNumber = atomics:add_get(Counter, 1, 1),
    TestPid ! {adapter_request, RequestNumber, Url},
    case RequestNumber =< 2 of
        true ->
            [];
        false ->
            [{"cache-control", "max-age=3600"}]
    end.
