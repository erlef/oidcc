%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_client_context_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

provider_not_running_test() ->
    ?assertMatch(
        {error, provider_not_ready},
        oidcc_client_context:from_configuration_worker(
            invalid,
            <<"client_id">>,
            <<"client_secret">>
        )
    ),
    ok.

from_configuration_worker_reads_from_ets_test() ->
    Name = from_configuration_worker_reads_from_ets_test,
    with_provider_mock(fun() ->
        {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://example.com">>,
            name => {local, Name}
        }),
        try
            #jose_jwk{} = oidcc_provider_configuration_worker:get_jwks(Pid),
            with_suspended_worker(Pid, fun() ->
                ?assertMatch(
                    {ok, #oidcc_client_context{}},
                    oidcc_client_context:from_configuration_worker(
                        Name, <<"client_id">>, <<"client_secret">>
                    )
                )
            end)
        after
            ok = gen_server:stop(Pid)
        end
    end).

from_configuration_worker_global_name_test() ->
    Name = {global, from_configuration_worker_global_name_test},
    with_provider_mock(fun() ->
        {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://example.com">>,
            name => Name
        }),
        try
            ?assertMatch(
                {ok, #oidcc_client_context{}},
                oidcc_client_context:from_configuration_worker(
                    Name, <<"client_id">>, <<"client_secret">>
                )
            )
        after
            ok = gen_server:stop(Pid)
        end
    end).

with_suspended_worker(Pid, TestFun) ->
    ok = sys:suspend(Pid),
    try
        TestFun()
    after
        ok = sys:resume(Pid)
    end.

with_provider_mock(TestFun) ->
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
    JwksBody = iolist_to_binary(json:encode(#{keys => []})),
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
                    {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], DiscoveryBody
                }};
            (get, {<<"https://example.com/keys">>, []}, _HttpOpts, _Opts, _Profile) ->
                {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], JwksBody}}
        end,
    ok = meck:new(httpc, [no_link]),
    try
        ok = meck:expect(httpc, request, HttpFun),
        TestFun()
    after
        meck:unload(httpc)
    end.

apply_profiles_fapi2_security_profile_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_security_profile]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                response_types_supported = [<<"code">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    #{request_opts := #{ssl := SslOpts}} = Opts,

    ?assertEqual(
        {ciphers, [
            #{
                cipher => 'aes_128_gcm',
                mac => aead,
                key_exchange => dhe_rsa,
                prf => sha256
            },
            #{
                cipher => 'aes_128_gcm',
                mac => aead,
                key_exchange => ecdhe_rsa,
                prf => sha256
            },
            #{
                cipher => 'aes_256_gcm',
                mac => aead,
                key_exchange => dhe_rsa,
                prf => sha384
            },
            #{
                cipher => 'aes_256_gcm',
                mac => aead,
                key_exchange => ecdhe_rsa,
                prf => sha384
            }
        ]},
        lists:keyfind(ciphers, 1, SslOpts)
    ),

    ?assertEqual(
        {verify, verify_peer},
        lists:keyfind(verify, 1, SslOpts)
    ),

    ?assertMatch(
        {cacerts, _},
        lists:keyfind(cacerts, 1, SslOpts)
    ),

    ok.

apply_profiles_fapi2_message_signing_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_message_signing]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                response_types_supported = [<<"code">>],
                response_modes_supported = [<<"jwt">>, <<"query.jwt">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    ok.

apply_profiles_mtls_constrain_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [mtls_constrain]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                token_endpoint = <<"https://my.provider/tls/token">>,
                userinfo_endpoint = <<"https://my.provider/tls/userinfo">>
            }
        },
        ClientContext
    ),

    ?assertEqual(
        #{},
        Opts
    ),

    ok.

apply_profiles_fapi2_connectid_au_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_connectid_au]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                token_endpoint = <<"https://my.provider/tls/token">>,
                userinfo_endpoint = <<"https://my.provider/tls/userinfo">>,
                response_types_supported = [<<"code">>],
                response_modes_supported = [<<"jwt">>, <<"query.jwt">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                pushed_authorization_request_endpoint = undefined,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            require_purpose := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    ok.

apply_profiles_unknown_test() ->
    ClientContext = client_context_fixture(),
    Opts = #{
        profiles => [unknown]
    },

    ?assertMatch(
        {error, {unknown_profile, unknown}},
        oidcc_client_context:apply_profiles(ClientContext, Opts)
    ),

    ok.

client_context_fixture() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/fapi2-metadata.json"),
    {ok, #oidcc_provider_configuration{} = Configuration} =
        oidcc_provider_configuration:decode_configuration(json:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk-ed25519.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret).
