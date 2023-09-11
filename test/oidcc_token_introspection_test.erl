-module(oidcc_token_introspection_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token_introspection.hrl").

introspect_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{introspection_endpoint = IntrospectionEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(oidcc_http_util, [passthrough]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _TelemetryOpts,
            _RequestOpts
        ) ->
            IntrospectionEndpoint = ReqEndpoint,
            {ok, {{json, #{<<"active">> => true, <<"client_id">> => ClientId}}, []}}
        end,
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = true}},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{}
        )
    ),

    true = meck:validate(oidcc_http_util),

    meck:unload(oidcc_http_util),

    ok.
