-module(oidcc_authorization_test).

-include_lib("eunit/include/eunit.hrl").

create_redirect_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    State = <<"someimportantstate">>,
    Nonce = <<"noncenonce">>,
    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, <<"client_secret">>),

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
    Opts5 =
        maps:merge(BaseOpts, #{pkce => #{challenge => <<"foo">>, method => <<"plain">>}}),

    {ok, Url1} = oidcc_authorization:create_redirect_url(ClientContext, BaseOpts),
    {ok, Url2} = oidcc_authorization:create_redirect_url(ClientContext, Opts1),
    {ok, Url3} = oidcc_authorization:create_redirect_url(ClientContext, Opts2),
    {ok, Url4} = oidcc_authorization:create_redirect_url(ClientContext, Opts3),
    {ok, Url5} = oidcc_authorization:create_redirect_url(ClientContext, Opts4),
    {ok, Url6} = oidcc_authorization:create_redirect_url(ClientContext, Opts5),

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
        <<"https://my.provider/auth?scope=openid&code_challenge=foo&code_challenge_method=plain&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl6, iolist_to_binary(Url6)),

    ok.
