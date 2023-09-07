-module(oidcc_userinfo_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

json_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    GoodSub = <<"123456">>,
    BadSub = <<"123789">>,

    HttpFun =
        fun(get, {Url, _Header}, _HttpOpts, _Opts) ->
            Url = UserInfoEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    AccessToken = <<"opensesame">>,
    GoodToken =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },
    BadToken =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123457">>}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(GoodToken, ClientContext, #{})
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => GoodSub}
        )
    ),

    ?assertMatch(
        {error, bad_subject},
        oidcc_userinfo:retrieve(BadToken, ClientContext, #{})
    ),
    ?assertMatch(
        {error, bad_subject},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => BadSub}
        )
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

distirbuted_claims_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorythm for test
    jose:unsecured_signing(true),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    Sub = <<"123456">>,

    Jwk = jose_jwk:generate_key(16),
    Jws = #{<<"alg">> => <<"none">>},

    LocalClaims = #{<<"last_name">> => <<"Armstrong">>},
    LocalJwt = jose_jwt:from(LocalClaims),
    {_, LocalToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, LocalJwt)
        ),

    RemoteClaims = #{<<"first_name">> => <<"Joe">>},
    RemoteJwt = jose_jwt:from(RemoteClaims),
    {_, RemoteToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, RemoteJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _TelemetryOpts, _RequestOpts) ->
            case Url of
                UserInfoEndpoint ->
                    {ok,
                        {
                            {json, #{
                                <<"sub">> => Sub,
                                <<"_claim_names">> => #{
                                    <<"first_name">> => <<"remote">>,
                                    <<"last_name">> => <<"local">>
                                },
                                <<"_claim_sources">> => #{
                                    <<"remote">> => #{
                                        <<"endpoint">> =>
                                            <<"https://my.provider/distributed-claim">>,
                                        <<"access_token">> => <<"acces_token">>
                                    },
                                    <<"local">> => #{
                                        <<"JWT">> => LocalToken
                                    }
                                }
                            }},
                            []
                        }};
                <<"https://my.provider/distributed-claim">> ->
                    {ok, {{jwt, RemoteToken}, []}}
            end
        end,
    ok = meck:new(oidcc_http_util, [passthrough]),
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },

    ?assertMatch(
        {ok, #{<<"first_name">> := <<"Joe">>, <<"last_name">> := <<"Armstrong">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),
    ?assertMatch(
        {ok, #{<<"first_name">> := <<"Joe">>, <<"last_name">> := <<"Armstrong">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => Sub}
        )
    ),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),

    ok.
