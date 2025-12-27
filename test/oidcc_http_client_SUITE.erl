-module(oidcc_http_client_SUITE).

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([custom_http_client_via_request_opts/1]).
-export([custom_http_client_via_app_config/1]).
-export([http_client_with_extra_opts/1]).
-export([default_http_client_backwards_compat/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        custom_http_client_via_request_opts,
        custom_http_client_via_app_config,
        http_client_with_extra_opts,
        default_http_client_backwards_compat
    ].

init_per_suite(_Config) ->
    {ok, _} = application:ensure_all_started(oidcc),
    [].

end_per_suite(_Config) ->
    ok = application:stop(oidcc).

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    application:unset_env(oidcc, http_client),
    meck:unload(),
    ok.

telemetry_opts() ->
    #{
        topic => [oidcc, oidcc_http_client_SUITE]
    }.

custom_http_client_via_request_opts(_Config) ->
    meck:new(mock_http_client, [non_strict]),
    meck:expect(mock_http_client, request, fun(Request, _Opts) ->
        #{method := get, url := "https://example.com/.well-known/openid-configuration"} = Request,
        {ok, #{
            status => 200,
            headers => [{"content-type", "application/json"}],
            body => <<"{\"issuer\":\"https://example.com\"}">>
        }}
    end),

    Result = oidcc_http_util:request(
        get,
        {"https://example.com/.well-known/openid-configuration", []},
        telemetry_opts(),
        #{http_client => mock_http_client}
    ),

    ?assertMatch({ok, {{json, #{<<"issuer">> := <<"https://example.com">>}}, _}}, Result),
    ?assert(meck:validate(mock_http_client)),
    ok.

custom_http_client_via_app_config(_Config) ->
    meck:new(mock_http_client, [non_strict]),
    meck:expect(mock_http_client, request, fun(_Request, _Opts) ->
        {ok, #{
            status => 200,
            headers => [{"content-type", "application/json"}],
            body => <<"{\"test\":true}">>
        }}
    end),

    application:set_env(oidcc, http_client, mock_http_client),

    Result = oidcc_http_util:request(
        get,
        {"https://example.com/test", []},
        telemetry_opts(),
        #{}
    ),

    ?assertMatch({ok, {{json, #{<<"test">> := true}}, _}}, Result),
    ?assert(meck:validate(mock_http_client)),
    ok.

http_client_with_extra_opts(_Config) ->
    meck:new(mock_http_client, [non_strict]),
    meck:expect(mock_http_client, request, fun(_Request, Opts) ->
        %% Verify that extra opts are passed through
        #{custom_option := custom_value} = Opts,
        {ok, #{
            status => 200,
            headers => [{"content-type", "application/json"}],
            body => <<"{\"extra_opts\":\"received\"}">>
        }}
    end),

    Result = oidcc_http_util:request(
        get,
        {"https://example.com/test", []},
        telemetry_opts(),
        #{http_client => {mock_http_client, #{custom_option => custom_value}}}
    ),

    ?assertMatch({ok, {{json, #{<<"extra_opts">> := <<"received">>}}, _}}, Result),
    ?assert(meck:validate(mock_http_client)),
    ok.

default_http_client_backwards_compat(_Config) ->
    %% Test that default httpc client still works with existing options
    meck:new(httpc, [unstick, passthrough]),
    meck:expect(httpc, request, fun(get, {Url, []}, HttpOpts, [{body_format, binary}], default) ->
        %% Verify standard options are passed
        {timeout, _} = lists:keyfind(timeout, 1, HttpOpts),
        case Url of
            "https://httpbin.org/get" ->
                {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{\"ok\":true}">>}};
            _ ->
                meck:passthrough([get, {Url, []}, HttpOpts, [{body_format, binary}], default])
        end
    end),

    Result = oidcc_http_util:request(
        get,
        {"https://httpbin.org/get", []},
        telemetry_opts(),
        #{timeout => 5000}
    ),

    ?assertMatch({ok, {{json, #{<<"ok">> := true}}, _}}, Result),
    ok.
