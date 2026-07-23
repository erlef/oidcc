%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_http_adapter_test).

-behaviour(oidcc_http_adapter).

-export([request/5]).

-include_lib("eunit/include/eunit.hrl").

request(Method, Request, HttpOptions, RequestOptions, AdapterConfig) ->
    RequestFun = maps:get(request, AdapterConfig),
    RequestFun(Method, Request, HttpOptions, RequestOptions, AdapterConfig).

behaviour_test() ->
    ?assert(lists:member({request, 5}, oidcc_http_adapter:behaviour_info(callbacks))).

adapter_receives_request_test() ->
    TestPid = self(),
    Method = post,
    Request =
        {<<"https://example.com/token">>, [{"accept", "application/json"}], "application/json",
            <<"{}">>},
    SslOptions = [{verify, verify_none}],
    RequestFun =
        fun(ReceivedMethod, ReceivedRequest, HttpOptions, RequestOptions, AdapterConfig) ->
            TestPid !
                {adapter_request, ReceivedMethod, ReceivedRequest, HttpOptions, RequestOptions,
                    AdapterConfig},
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", <<"application/json">>}],
                <<"{\"ok\":true}">>
            }}
        end,
    AdapterConfig = #{request => RequestFun, custom => #{option => value}},

    ?assertEqual(
        {ok, {{json, #{<<"ok">> => true}}, [{"content-type", <<"application/json">>}]}},
        oidcc_http_util:request(Method, Request, telemetry_opts(adapter_request), #{
            timeout => 1_234,
            ssl => SslOptions,
            http_adapter => {?MODULE, AdapterConfig}
        })
    ),

    receive
        {adapter_request, Method, Request, [{ssl, SslOptions}, {timeout, 1_234}],
            [{body_format, binary}], AdapterConfig} ->
            ok
    after 1_000 ->
        ?assert(false)
    end.

adapter_jwt_response_test() ->
    RequestFun =
        fun(get, {<<"https://example.com/userinfo">>, []}, _HttpOptions, _RequestOptions, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/jwt"}],
                <<"header.payload.signature">>
            }}
        end,

    ?assertEqual(
        {ok, {{jwt, <<"header.payload.signature">>}, [{"content-type", "application/jwt"}]}},
        oidcc_http_util:request(
            get,
            {<<"https://example.com/userinfo">>, []},
            telemetry_opts(adapter_jwt_response),
            #{http_adapter => {?MODULE, #{request => RequestFun}}}
        )
    ).

adapter_error_normalization_test() ->
    TransportErrorFun =
        fun(_Method, _Request, _HttpOptions, _RequestOptions, _Config) ->
            {error, transport_failed}
        end,
    ?assertEqual(
        {error, transport_failed},
        oidcc_http_util:request(
            get,
            {<<"https://example.com">>, []},
            telemetry_opts(adapter_transport_error),
            #{http_adapter => {?MODULE, #{request => TransportErrorFun}}}
        )
    ),

    ProtocolErrorFun =
        fun(_Method, _Request, _HttpOptions, _RequestOptions, _Config) ->
            {ok, {
                {"HTTP/1.1", 429, "Too Many Requests"},
                [{"content-type", "application/json"}],
                <<"{\"error\":\"slow_down\"}">>
            }}
        end,
    ?assertEqual(
        {error, {http_error, 429, #{<<"error">> => <<"slow_down">>}}},
        oidcc_http_util:request(
            get,
            {<<"https://example.com">>, []},
            telemetry_opts(adapter_protocol_error),
            #{http_adapter => {?MODULE, #{request => ProtocolErrorFun}}}
        )
    ).

adapter_telemetry_test() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Topic = [oidcc, adapter_telemetry],
    HandlerId = {?MODULE, make_ref()},
    Events = [Topic ++ [start], Topic ++ [stop], Topic ++ [exception]],
    ok = telemetry:attach_many(
        HandlerId,
        Events,
        fun(Event, Measurements, Metadata, TestPid) ->
            TestPid ! {telemetry, Event, Measurements, Metadata}
        end,
        self()
    ),

    try
        SuccessMetadata = #{issuer => <<"https://success.example">>},
        SuccessFun =
            fun(_Method, _Request, _HttpOptions, _RequestOptions, _Config) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{}">>
                }}
            end,
        ?assertMatch(
            {ok, _},
            oidcc_http_util:request(
                get,
                {<<"https://success.example">>, []},
                #{topic => Topic, extra_meta => SuccessMetadata},
                #{http_adapter => {?MODULE, #{request => SuccessFun}}}
            )
        ),
        assert_span(Topic, SuccessMetadata, SuccessMetadata),

        FailureMetadata = #{issuer => <<"https://failure.example">>},
        FailureFun =
            fun(_Method, _Request, _HttpOptions, _RequestOptions, _Config) ->
                {error, transport_failed}
            end,
        ?assertEqual(
            {error, transport_failed},
            oidcc_http_util:request(
                get,
                {<<"https://failure.example">>, []},
                #{topic => Topic, extra_meta => FailureMetadata},
                #{http_adapter => {?MODULE, #{request => FailureFun}}}
            )
        ),
        assert_span(
            Topic,
            FailureMetadata,
            FailureMetadata#{error => transport_failed}
        ),

        ProtocolFailureMetadata = #{issuer => <<"https://protocol-failure.example">>},
        ProtocolFailure = {http_error, 503, <<"unavailable">>},
        ProtocolFailureFun =
            fun(_Method, _Request, _HttpOptions, _RequestOptions, _Config) ->
                {ok, {{"HTTP/1.1", 503, "Service Unavailable"}, [], <<"unavailable">>}}
            end,
        ?assertEqual(
            {error, ProtocolFailure},
            oidcc_http_util:request(
                get,
                {<<"https://protocol-failure.example">>, []},
                #{topic => Topic, extra_meta => ProtocolFailureMetadata},
                #{http_adapter => {?MODULE, #{request => ProtocolFailureFun}}}
            )
        ),
        assert_span(
            Topic,
            ProtocolFailureMetadata,
            ProtocolFailureMetadata#{error => ProtocolFailure}
        )
    after
        telemetry:detach(HandlerId)
    end.

default_adapter_test() ->
    Request = {<<"https://example.com">>, []},
    ok = meck:new(oidcc_http_adapter_httpc, [passthrough]),
    try
        ok = meck:expect(
            oidcc_http_adapter_httpc,
            request,
            fun(
                get,
                ReceivedRequest,
                [{timeout, 60_000}],
                [{body_format, binary}],
                ReceivedAdapterConfig
            ) ->
                ?assertEqual(Request, ReceivedRequest),
                ?assertEqual(#{profile => default}, ReceivedAdapterConfig),
                {ok, {
                    {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{}">>
                }}
            end
        ),

        ?assertMatch(
            {ok, _},
            oidcc_http_util:request(get, Request, telemetry_opts(default_adapter), #{})
        ),

        ?assert(meck:validate(oidcc_http_adapter_httpc))
    after
        meck:unload(oidcc_http_adapter_httpc)
    end.

legacy_httpc_options_test() ->
    Method = post,
    Request =
        {<<"https://example.com/token">>, [{"accept", "application/json"}],
            "application/x-www-form-urlencoded", <<"grant_type=client_credentials">>},
    SslOptions = [{verify, verify_none}, {server_name_indication, "example.com"}],
    Profile = test_profile,
    ok = meck:new(httpc, [no_link]),
    try
        ok = meck:expect(
            httpc,
            request,
            fun(
                ReceivedMethod,
                ReceivedRequest,
                [{ssl, ReceivedSslOptions}, {timeout, 4_321}],
                [{body_format, binary}],
                ReceivedProfile
            ) ->
                ?assertEqual(Method, ReceivedMethod),
                ?assertEqual(Request, ReceivedRequest),
                ?assertEqual(SslOptions, ReceivedSslOptions),
                ?assertEqual(Profile, ReceivedProfile),
                {ok, {
                    {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{}">>
                }}
            end
        ),

        ?assertMatch(
            {ok, _},
            oidcc_http_util:request(Method, Request, telemetry_opts(legacy_httpc_options), #{
                timeout => 4_321,
                ssl => SslOptions,
                httpc_profile => Profile
            })
        ),

        ?assert(meck:validate(httpc))
    after
        meck:unload(httpc)
    end.

telemetry_opts(Name) ->
    #{topic => [oidcc, Name]}.

assert_span(Topic, StartMetadata, StopMetadata) ->
    ActualStartMetadata =
        receive
            {telemetry, StartEvent, #{system_time := _}, ReceivedStartMetadata} ->
                ?assertEqual(Topic ++ [start], StartEvent),
                ReceivedStartMetadata
        after 1_000 ->
            ?assert(false)
        end,
    ActualStopMetadata =
        receive
            {telemetry, StopEvent, #{duration := _, monotonic_time := _}, ReceivedStopMetadata} ->
                ?assertEqual(Topic ++ [stop], StopEvent),
                ReceivedStopMetadata
        after 1_000 ->
            ?assert(false)
        end,
    ?assertEqual(
        StartMetadata,
        maps:without([telemetry_span_context], ActualStartMetadata)
    ),
    ?assertEqual(
        StopMetadata,
        maps:without([telemetry_span_context], ActualStopMetadata)
    ),
    ?assertEqual(
        maps:get(telemetry_span_context, ActualStartMetadata),
        maps:get(telemetry_span_context, ActualStopMetadata)
    ).
