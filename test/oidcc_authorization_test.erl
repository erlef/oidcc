-module(oidcc_authorization_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwe.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

create_redirect_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),
    PkcePlainConfiguration = Configuration#oidcc_provider_configuration{
        code_challenge_methods_supported = [<<"plain">>]
    },
    NoPkceConfiguration = Configuration#oidcc_provider_configuration{
        code_challenge_methods_supported = undefined
    },

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    State = <<"someimportantstate">>,
    Nonce = <<"noncenonce">>,
    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, <<"client_secret">>),
    PkcePlainClientContext =
        oidcc_client_context:from_manual(
            PkcePlainConfiguration, Jwks, ClientId, <<"client_secret">>
        ),
    NoPkceClientContext =
        oidcc_client_context:from_manual(NoPkceConfiguration, Jwks, ClientId, <<"client_secret">>),

    BaseOpts =
        #{
            redirect_uri => RedirectUri,
            client_id => ClientId,
            url_extension => [{<<"test">>, <<"id">>}]
        },
    Opts1 = maps:merge(BaseOpts, #{scopes => ["email", <<"openid">>, profile]}),
    Opts2 = maps:merge(BaseOpts, #{scopes => ["email", <<"profile">>], state => State}),
    Opts3 =
        maps:merge(
            BaseOpts,
            #{
                scopes => [email, profile, openid],
                state => State,
                nonce => Nonce
            }
        ),
    Opts4 =
        maps:merge(
            BaseOpts,
            #{
                scopes => ["email", <<"openid">>],
                url_extension => [{<<"test">>, <<"id">>}, {<<"other">>, <<"green">>}]
            }
        ),
    Opts5 = maps:merge(BaseOpts, #{pkce_verifier => <<"foo">>}),

    {ok, Url1} = oidcc_authorization:create_redirect_url(ClientContext, BaseOpts),
    {ok, Url2} = oidcc_authorization:create_redirect_url(ClientContext, Opts1),
    {ok, Url3} = oidcc_authorization:create_redirect_url(ClientContext, Opts2),
    {ok, Url4} = oidcc_authorization:create_redirect_url(ClientContext, Opts3),
    {ok, Url5} = oidcc_authorization:create_redirect_url(ClientContext, Opts4),
    {ok, Url6} = oidcc_authorization:create_redirect_url(ClientContext, Opts5),
    {ok, Url7} = oidcc_authorization:create_redirect_url(PkcePlainClientContext, Opts5),
    {ok, Url8} = oidcc_authorization:create_redirect_url(NoPkceClientContext, Opts5),

    ExpUrl1 =
        <<"https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl1, iolist_to_binary(Url1)),

    ExpUrl2 =
        <<"https://my.provider/auth?scope=email+openid+profile&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl2, iolist_to_binary(Url2)),

    ExpUrl3 =
        <<"https://my.provider/auth?scope=email+profile&state=someimportantstate&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl3, iolist_to_binary(Url3)),

    ExpUrl4 =
        <<"https://my.provider/auth?scope=email+profile+openid&nonce=noncenonce&state=someimportantstate&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl4, iolist_to_binary(Url4)),

    ExpUrl5 =
        <<"https://my.provider/auth?scope=email+openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id&other=green">>,
    ?assertEqual(ExpUrl5, iolist_to_binary(Url5)),

    ExpUrl6 =
        <<"https://my.provider/auth?scope=openid&code_challenge=LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564&code_challenge_method=S256&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl6, iolist_to_binary(Url6)),

    ExpUrl7 =
        <<"https://my.provider/auth?scope=openid&code_challenge=foo&code_challenge_method=plain&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl7, iolist_to_binary(Url7)),

    ExpUrl8 =
        <<"https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl8, iolist_to_binary(Url8)),

    ok.

create_redirect_url_with_request_object_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{issuer = Issuer} = Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"none">>,
            <<"HS256">>,
            <<"RS256">>,
            <<"PS256">>,
            <<"ES256">>,
            <<"EdDSA">>
        ],
        request_object_encryption_alg_values_supported = [
            <<"RSA1_5">>,
            <<"RSA-OAEP">>,
            <<"RSA-OAEP-256">>,
            <<"RSA-OAEP-384">>,
            <<"RSA-OAEP-512">>,
            <<"ECDH-ES">>,
            <<"ECDH-ES+A128KW">>,
            <<"ECDH-ES+A192KW">>,
            <<"ECDH-ES+A256KW">>,
            <<"A128KW">>,
            <<"A192KW">>,
            <<"A256KW">>,
            <<"A128GCMKW">>,
            <<"A192GCMKW">>,
            <<"A256GCMKW">>,
            <<"dir">>
        ],
        request_object_encryption_enc_values_supported = [
            <<"A128CBC-HS256">>,
            <<"A192CBC-HS384">>,
            <<"A256CBC-HS512">>,
            <<"A128GCM">>,
            <<"A192GCM">>,
            <<"A256GCM">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    ?assertMatch(<<"https://my.provider/auth?request=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertMatch(
        #{
            <<"client_id">> := <<"client_id">>,
            <<"redirect_uri">> := <<"https://my.server/return">>,
            <<"response_type">> := <<"code">>,
            <<"scope">> := <<"openid">>,
            <<"request">> := _
        },
        QueryParams
    ),

    {SignedToken, Jwe} = jose_jwe:block_decrypt(Jwks, maps:get(<<"request">>, QueryParams)),

    ?assertMatch(#jose_jwe{alg = {jose_jwe_alg_rsa, _}}, Jwe),

    {true, Jwt, Jws} = jose_jwt:verify(jose_jwk:from_oct(ClientSecret), SignedToken),

    ?assertMatch(#jose_jws{alg = {jose_jws_alg_hmac, 'HS256'}}, Jws),

    ?assertMatch(
        #jose_jwt{
            fields = #{
                <<"aud">> := Issuer,
                <<"client_id">> := ClientId,
                <<"exp">> := _,
                <<"iat">> := _,
                <<"iss">> := ClientId,
                <<"jti">> := _,
                <<"nbf">> := _,
                <<"redirect_uri">> := RedirectUri,
                <<"response_type">> := <<"code">>,
                <<"scope">> := <<"openid">>
            }
        },
        Jwt
    ),

    ok.
