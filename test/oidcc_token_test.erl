-module(oidcc_token_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

retrieve_none_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorythm for test
    jose:unsecured_signing(true),

    {ok, _} = application:ensure_all_started(oidcc),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, request_token, start],
                [oidcc, request_token, stop]
            ]
        ),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    JwkSet = #jose_jwk{keys = {jose_jwk_set, [Jwks]}},

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10
        },

    Jwk = jose_jwk:generate_key(16),
    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"none">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, JwkSet, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error,
            {none_alg_used, #oidcc_token{
                id = #oidcc_token_id{token = Token, claims = Claims},
                access = #oidcc_token_access{token = AccessToken},
                refresh = none,
                scope = [<<"profile">>, <<"openid">>]
            }}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    receive
        {[oidcc, request_token, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>,
            client_id := ClientId
        }} ->
            ok
    after 2_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

retrieve_rs256_with_rotation_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, request_token, start],
                [oidcc, request_token, stop]
            ]
        ),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    JwkBeforeRefresh0 = jose_jwk:generate_key(16),
    JwkBeforeRefresh = JwkBeforeRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid1">>}},

    JwkAfterRefresh0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    JwkAfterRefresh = JwkAfterRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid2">>}},

    RefreshJwksFun = fun(_OldJwk, <<"kid2">>) -> {ok, JwkAfterRefresh} end,

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"kid2">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(JwkAfterRefresh, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(
        Configuration, JwkBeforeRefresh, ClientId, ClientSecret
    ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, refresh_jwks => RefreshJwksFun}
        )
    ),

    receive
        {[oidcc, request_token, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>,
            client_id := ClientId
        }} ->
            ok
    after 2_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.
