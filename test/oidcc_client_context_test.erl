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
            preferred_auth_methods := [private_key_jwt],
            require_pkce := true,
            trusted_audiences := []
        },
        Opts
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
                require_signed_request_object = true,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt],
            require_pkce := true,
            trusted_audiences := []
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
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk-ed25519.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret).
