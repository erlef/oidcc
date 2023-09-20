-module(oidcc_client_registration_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_client_registration.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

register_test() ->
    {ok, _} = application:ensure_all_started(oidcc),

    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{registration_endpoint = RegistrationEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    RedirectUri = <<"https://example.com/oidcc/callback">>,

    Registration = #oidcc_client_registration{
        redirect_uris = [RedirectUri]
    },

    ClientId = <<"client_id">>,

    ResponseJson = jose:encode(#{
        client_id => ClientId
    }),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, register_client, start],
                [oidcc, register_client, stop]
            ]
        ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/json", Body},
            _HttpOpts,
            _Opts
        ) ->
            RegistrationEndpoint = ReqEndpoint,
            ?assertMatch(
                #{
                    <<"application_type">> := <<"web">>,
                    <<"extra_fields">> := #{},
                    <<"redirect_uris">> := [RedirectUri],
                    <<"require_auth_time">> := false,
                    <<"token_endpoint_auth_method">> := <<"client_secret_basic">>
                },
                jose:decode(Body)
            ),
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], ResponseJson}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    {ok, Response} = oidcc_client_registration:register(Configuration, Registration, #{}),

    ?assertMatch(#oidcc_client_registration_response{client_id = ClientId}, Response),

    receive
        {[oidcc, register_client, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    receive
        {[oidcc, register_client, stop], TelemetryRef, #{duration := _Duration}, #{
            issuer := <<"https://my.provider">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.
