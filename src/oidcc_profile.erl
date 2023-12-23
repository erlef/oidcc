%%%-------------------------------------------------------------------
%% @doc OpenID Profile Utilities
%% @end
%% @since 3.2.0
%%%-------------------------------------------------------------------
-module(oidcc_profile).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-export([apply_profiles/2]).

%% @private
-spec apply_profiles(ClientContext, Opts) ->
    {ok, ClientContext, Opts} | {error, oidcc_client_context:error()}
when
    ClientContext :: oidcc_client_context:t(),
    Opts :: map().
apply_profiles(
    #oidcc_client_context{} = ClientContext0, #{profiles := [fapi2 | RestProfiles]} = Opts0
) ->
    %% FAPI2:
    %% - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html
    %% - https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html
    {ClientContext1, Opts1} = enforce_s256_pkce(ClientContext0, Opts0),
    ClientContext2 = limit_response_types([<<"code">>], ClientContext1),
    ClientContext3 = enforce_par(ClientContext2),
    ClientContext4 = enforce_iss_parameter(ClientContext3),
    ClientContext = limit_signing_alg_values(
        [
            <<"PS256">>,
            <<"PS384">>,
            <<"PS512">>,
            <<"ES256">>,
            <<"ES384">>,
            <<"ES512">>,
            <<"EdDSA">>
        ],
        ClientContext4
    ),
    Opts2 = Opts1#{profiles => RestProfiles},
    Opts3 = map_put_new(trusted_audiences, [], Opts2),
    %% TODO include <<"tls_client_auth">> here when it's supported by the library.
    Opts = map_put_new(preferred_auth_methods, [private_key_jwt], Opts3),
    apply_profiles(ClientContext, Opts);
apply_profiles(#oidcc_client_context{}, #{profiles := [UnknownProfile | _]}) ->
    {error, {unknown_profile, UnknownProfile}};
apply_profiles(#oidcc_client_context{} = ClientContext, #{profiles := []} = Opts0) ->
    Opts = maps:remove(profiles, Opts0),
    apply_profiles(ClientContext, Opts);
apply_profiles(#oidcc_client_context{} = ClientContext, #{} = Opts) ->
    {ok, ClientContext, Opts}.

enforce_s256_pkce(ClientContext0, Opts0) ->
    #oidcc_client_context{
        provider_configuration =
            ProviderConfiguration0 = #oidcc_provider_configuration{
                code_challenge_methods_supported = CodeChallengeMethodsSupported
            }
    } = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        code_challenge_methods_supported = limit_values([<<"S256">>], CodeChallengeMethodsSupported)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    Opts = Opts0#{require_pkce => true},
    {ClientContext, Opts}.

limit_response_types(Types, ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    #oidcc_provider_configuration{
        response_types_supported = ResponseTypes
    } = ProviderConfiguration0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        response_types_supported = limit_values(Types, ResponseTypes)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

enforce_par(ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        require_pushed_authorization_requests = true
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

enforce_iss_parameter(ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        authorization_response_iss_parameter_supported = true
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

limit_signing_alg_values(AlgSupported, ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    #oidcc_provider_configuration{
        id_token_signing_alg_values_supported = IdAlg,
        userinfo_signing_alg_values_supported = UserinfoAlg,
        request_object_signing_alg_values_supported = RequestObjectAlg,
        token_endpoint_auth_signing_alg_values_supported = TokenAlg,
        revocation_endpoint_auth_signing_alg_values_supported = RevocationAlg,
        introspection_endpoint_auth_signing_alg_values_supported = IntrospectionAlg,
        authorization_signing_alg_values_supported = AuthorizationAlg,
        dpop_signing_alg_values_supported = DpopAlg
    } = ProviderConfiguration0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        id_token_signing_alg_values_supported = limit_values(AlgSupported, IdAlg),
        userinfo_signing_alg_values_supported = limit_values(AlgSupported, UserinfoAlg),
        request_object_signing_alg_values_supported = limit_values(AlgSupported, RequestObjectAlg),
        token_endpoint_auth_signing_alg_values_supported = limit_values(AlgSupported, TokenAlg),
        revocation_endpoint_auth_signing_alg_values_supported = limit_values(
            AlgSupported, RevocationAlg
        ),
        introspection_endpoint_auth_signing_alg_values_supported = limit_values(
            AlgSupported, IntrospectionAlg
        ),
        authorization_signing_alg_values_supported = limit_values(AlgSupported, AuthorizationAlg),
        dpop_signing_alg_values_supported = limit_values(AlgSupported, DpopAlg)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

limit_values(_Limit, undefined) ->
    undefined;
limit_values(Limit, Values) ->
    case [V || V <- Values, lists:member(V, Limit)] of
        [] ->
            undefined;
        Filtered ->
            Filtered
    end.

map_put_new(Key, Value, Map) ->
    case Map of
        #{Key := _} ->
            Map;
        _ ->
            Map#{Key => Value}
    end.
