%%%-------------------------------------------------------------------
%% @doc Functions to start an OpenID Connect Authorization
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_authorization).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export([create_redirect_url/2]).

-export_type([error/0]).
-export_type([opts/0]).

-type opts() ::
    #{
        scopes => oidcc_scope:scopes(),
        state => binary(),
        nonce => binary(),
        pkce_verifier => binary(),
        redirect_uri := uri_string:uri_string(),
        url_extension => oidcc_http_util:query_params()
    }.
%% Configure authorization redirect url
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest]
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`scopes' - list of scopes to request (defaults to `[<<"openid">>]')</li>
%%   <li>`state' - state to pass to the provider</li>
%%   <li>`nonce' - nonce to pass to the provider</li>
%%   <li>`pkce_verifier' - pkce verifier (random string), see
%%     [https://datatracker.ietf.org/doc/html/rfc7636#section-4.1]</li>
%%   <li>`redirect_uri' - redirect target after authorization is completed</li>
%%   <li>`url_extension' - add custom query parameters to the authorization url</li>
%% </ul>

-type error() :: {grant_type_not_supported, authorization_code}.

%% @doc
%% Create Auth Redirect URL
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:create_redirect_url/4}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%     oidcc_client_context:from_configuration_worker(provider_name,
%%                                                    <<"client_id">>,
%%                                                    <<"client_secret">>),
%%
%% {ok, RedirectUri} =
%%     oidcc_authorization:create_redirect_url(ClientContext,
%%                                             #{redirect_uri: <<"https://my.server/return"}),
%%
%% %% RedirectUri = https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn
%% '''
%% @end
%% @since 3.0.0
-spec create_redirect_url(ClientContext, Opts) -> {ok, Uri} | {error, error()} when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts(),
    Uri :: uri_string:uri_string().
create_redirect_url(#oidcc_client_context{} = ClientContext, Opts) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration} = ClientContext,

    #oidcc_provider_configuration{
        authorization_endpoint = AuthEndpoint, grant_types_supported = GrantTypesSupported
    } =
        ProviderConfiguration,

    case lists:member(<<"authorization_code">>, GrantTypesSupported) of
        true ->
            QueryParams0 = redirect_params(ClientContext, Opts),
            QueryParams = QueryParams0 ++ maps:get(url_extension, Opts, []),
            QueryString = uri_string:compose_query(QueryParams),

            {ok, [AuthEndpoint, <<"?">>, QueryString]};
        false ->
            {error, {grant_type_not_supported, authorization_code}}
    end.

-spec redirect_params(ClientContext, Opts) -> oidcc_http_util:query_params() when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
redirect_params(#oidcc_client_context{client_id = ClientId} = ClientContext, Opts) ->
    QueryParams =
        [
            {<<"response_type">>, maps:get(response_type, Opts, <<"code">>)},
            {<<"client_id">>, ClientId},
            {<<"redirect_uri">>, maps:get(redirect_uri, Opts)}
        ],
    QueryParams1 = maybe_append(<<"state">>, maps:get(state, Opts, undefined), QueryParams),
    QueryParams2 = maybe_append(<<"nonce">>, maps:get(nonce, Opts, undefined), QueryParams1),
    QueryParams3 = append_code_challenge(
        maps:get(pkce_verifier, Opts, none), QueryParams2, ClientContext
    ),
    QueryParams4 = oidcc_scope:query_append_scope(
        maps:get(scopes, Opts, [openid]), QueryParams3
    ),
    attempt_request_object(QueryParams4, ClientContext).

-spec append_code_challenge(PkceVerifier, QueryParams, ClientContext) ->
    oidcc_http_util:query_params()
when
    PkceVerifier :: binary() | none,
    QueryParams :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t().
append_code_challenge(none, QueryParams, _ClientContext) ->
    QueryParams;
append_code_challenge(CodeVerifier, QueryParams, ClientContext) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration} = ClientContext,
    #oidcc_provider_configuration{code_challenge_methods_supported = CodeChallengeMethodsSupported} =
        ProviderConfiguration,
    case CodeChallengeMethodsSupported of
        undefined ->
            QueryParams;
        Methods when is_list(Methods) ->
            case
                {
                    lists:member(<<"S256">>, CodeChallengeMethodsSupported),
                    lists:member(<<"plain">>, CodeChallengeMethodsSupported)
                }
            of
                {true, _PlainSupported} ->
                    CodeChallenge = base64:encode(crypto:hash(sha256, CodeVerifier), #{
                        mode => urlsafe, padding => false
                    }),
                    [
                        {"code_challenge", CodeChallenge},
                        {"code_challenge_method", <<"S256">>}
                        | QueryParams
                    ];
                {false, true} ->
                    [
                        {"code_challenge", CodeVerifier},
                        {"code_challenge_method", <<"plain">>}
                        | QueryParams
                    ];
                {false, false} ->
                    QueryParams
            end
    end.

-spec maybe_append(Key, Value, QueryParams) -> QueryParams when
    Key :: unicode:chardata(),
    Value :: unicode:chardata() | true | undefined,
    QueryParams :: oidcc_http_util:query_params().
maybe_append(_Key, undefined, QueryParams) ->
    QueryParams;
maybe_append(Key, Value, QueryParams) ->
    [{Key, Value} | QueryParams].

-spec attempt_request_object(QueryParams, ClientContext) -> QueryParams when
    QueryParams :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t().
attempt_request_object(QueryParams, #oidcc_client_context{
    provider_configuration = #oidcc_provider_configuration{request_parameter_supported = false}
}) ->
    QueryParams;
attempt_request_object(QueryParams, #oidcc_client_context{client_secret = unauthenticated}) ->
    QueryParams;
attempt_request_object(QueryParams, #oidcc_client_context{
    client_id = ClientId,
    client_secret = ClientSecret,
    client_jwks = ClientJwks,
    provider_configuration = #oidcc_provider_configuration{
        issuer = Issuer,
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = SigningAlgSupported0,
        request_object_encryption_alg_values_supported = EncryptionAlgSupported0,
        request_object_encryption_enc_values_supported = EncryptionEncSupported0
    },
    jwks = Jwks
}) ->
    SigningAlgSupported =
        case SigningAlgSupported0 of
            undefined -> [];
            SigningAlgs -> SigningAlgs
        end,
    EncryptionAlgSupported =
        case EncryptionAlgSupported0 of
            undefined -> [];
            EncryptionAlgs -> EncryptionAlgs
        end,
    EncryptionEncSupported =
        case EncryptionEncSupported0 of
            undefined -> [];
            EncryptionEncs -> EncryptionEncs
        end,

    JwksWithClientJwks =
        case ClientJwks of
            none -> Jwks;
            #jose_jwk{} -> oidcc_jwt_util:merge_jwks(Jwks, ClientJwks)
        end,

    SigningJwks =
        case oidcc_jwt_util:client_secret_oct_keys(SigningAlgSupported, ClientSecret) of
            none ->
                Jwks;
            SigningOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, SigningOctJwk)
        end,
    EncryptionJwks =
        case oidcc_jwt_util:client_secret_oct_keys(EncryptionAlgSupported, ClientSecret) of
            none ->
                Jwks;
            EncryptionOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, EncryptionOctJwk)
        end,

    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,

    Claims = maps:merge(
        #{
            <<"iss">> => ClientId,
            <<"aud">> => Issuer,
            <<"jti">> => random_string(32),
            <<"iat">> => os:system_time(seconds),
            <<"exp">> => os:system_time(seconds) + 30,
            <<"nbf">> => os:system_time(seconds) - MaxClockSkew
        },
        maps:from_list(QueryParams)
    ),
    Jwt = jose_jwt:from(Claims),

    case oidcc_jwt_util:sign(Jwt, SigningJwks, deprioritize_none_alg(SigningAlgSupported)) of
        {error, no_supported_alg_or_key} ->
            QueryParams;
        {ok, SignedRequestObject} ->
            case
                oidcc_jwt_util:encrypt(
                    SignedRequestObject,
                    EncryptionJwks,
                    deprioritize_none_alg(EncryptionAlgSupported),
                    EncryptionEncSupported
                )
            of
                {ok, EncryptedRequestObject} ->
                    [{<<"request">>, EncryptedRequestObject} | essential_params(QueryParams)];
                {error, no_supported_alg_or_key} ->
                    [{<<"request">>, SignedRequestObject} | essential_params(QueryParams)]
            end
    end.

-spec essential_params(QueryParams :: oidcc_http_util:query_params()) ->
    oidcc_http_util:query_params().
essential_params(QueryParams) ->
    lists:filter(
        fun
            ({<<"scope">>, _Value}) -> true;
            ({<<"response_type">>, _Value}) -> true;
            ({<<"client_id">>, _Value}) -> true;
            ({<<"redirect_uri">>, _Value}) -> true;
            (_Other) -> false
        end,
        QueryParams
    ).

-spec deprioritize_none_alg(Algorithms :: [binary()]) -> [binary()].
deprioritize_none_alg(Algorithms) ->
    {WithNone, WithoutNone} = lists:partition(
        fun
            (<<"none">>) -> true;
            (_) -> false
        end,
        Algorithms
    ),
    WithoutNone ++ WithNone.

-spec random_string(Bytes :: pos_integer()) -> binary().
random_string(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).
