%%%-------------------------------------------------------------------
%% @doc Facilitate OpenID Code/Token Exchanges
%%
%% <h2>Records</h2>
%%
%% To use the records, import the definition:
%%
%% ```
%% -include_lib(["oidcc/include/oidcc_token.hrl"]).
%% '''
%%
%% <h2>Telemetry</h2>
%%
%% See {@link 'Elixir.Oidcc.Token'}
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_token).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-export([client_credentials/2]).
-export([jwt_profile/4]).
-export([refresh/3]).
-export([retrieve/3]).
-export([validate_jarm/3]).
-export([validate_id_token/3]).
-export([authorization_headers/4]).
-export([authorization_headers/5]).

-export_type([access/0]).
-export_type([client_credentials_opts/0]).
-export_type([error/0]).
-export_type([id/0]).
-export_type([jwt_profile_opts/0]).
-export_type([refresh/0]).
-export_type([refresh_opts/0]).
-export_type([refresh_opts_no_sub/0]).
-export_type([retrieve_opts/0]).
-export_type([validate_jarm_opts/0]).
-export_type([t/0]).

-type id() :: #oidcc_token_id{token :: binary(), claims :: oidcc_jwt_util:claims()}.

%% ID Token Wrapper
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`token' - The retrieved token</li>
%%   <li>`claims' - Unpacked claims of the verified token</li>
%% </ul>

-type access() ::
    #oidcc_token_access{token :: binary(), expires :: pos_integer() | undefined, type :: binary()}.
%% Access Token Wrapper
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`token' - The retrieved token</li>
%%   <li>`expires' - Number of seconds the token is valid</li>
%% </ul>

-type refresh() :: #oidcc_token_refresh{token :: binary()}.
%% Refresh Token Wrapper
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`token' - The retrieved token</li>
%% </ul>

-type t() ::
    #oidcc_token{
        id :: oidcc_token:id() | none,
        access :: oidcc_token:access() | none,
        refresh :: oidcc_token:refresh() | none,
        scope :: oidcc_scope:scopes()
    }.
%% Token Response Wrapper
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`id' - {@link id()}</li>
%%   <li>`access' - {@link access()}</li>
%%   <li>`refresh' - {@link refresh()}</li>
%%   <li>`scope' - {@link oidcc_scope:scopes()}</li>
%% </ul>

-type retrieve_opts() ::
    #{
        pkce_verifier => binary(),
        require_pkce => boolean(),
        nonce => binary() | any,
        scope => oidcc_scope:scopes(),
        preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        redirect_uri => uri_string:uri_string(),
        request_opts => oidcc_http_util:request_opts(),
        url_extension => oidcc_http_util:query_params(),
        body_extension => oidcc_http_util:query_params(),
        dpop_nonce => binary(),
        trusted_audiences => [binary()] | any
    }.
%% Options for retrieving a token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3]
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`pkce_verifier' - pkce verifier (random string previously given to
%%     `oidcc_authorization'), see
%%     [https://datatracker.ietf.org/doc/html/rfc7636#section-4.1]</li>
%%   <li>`require_pkce' - whether to require PKCE when getting the token</li>
%%   <li>`nonce' - Nonce to check</li>
%%   <li>`scope' - Scope to store with the token</li>
%%   <li>`refresh_jwks' - How to handle tokens with an unknown `kid'.
%%     See {@link oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun()}</li>
%%   <li>`redirect_uri' - Redirect uri given to {@link oidcc_authorization:create_redirect_url/2}</li>
%%   <li>`dpop_nonce' - if using DPoP, the `nonce' value to use in the
%%     proof claim</li>
%%   <li>`trusted_audiences' - if present, a list of additional audience values to
%%     accept. Defaults to `any' which allows any additional values</li>
%% </ul>

-type refresh_opts_no_sub() ::
    #{
        scope => oidcc_scope:scopes(),
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        request_opts => oidcc_http_util:request_opts(),
        url_extension => oidcc_http_util:query_params(),
        body_extension => oidcc_http_util:query_params()
    }.
%% See {@link refresh_opts_no_sub()}

-type refresh_opts() ::
    #{
        scope => oidcc_scope:scopes(),
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        expected_subject := binary(),
        request_opts => oidcc_http_util:request_opts(),
        url_extension => oidcc_http_util:query_params(),
        body_extension => oidcc_http_util:query_params()
    }.

-type validate_jarm_opts() ::
    #{
        trusted_audiences => [binary()] | any
    }.
%% Options for refreshing a token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3]
%%
%% <h2>Fields</h2>
%%
%% <ul>
%%   <li>`scope' - Scope to store with the token</li>
%%   <li>`refresh_jwks' - How to handle tokens with an unknown `kid'.
%%     See {@link oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun()}</li>
%%   <li>`expected_subject' - `sub' of the original token</li>
%% </ul>

-type jwt_profile_opts() :: #{
    scope => oidcc_scope:scopes(),
    refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    request_opts => oidcc_http_util:request_opts(),
    kid => binary(),
    url_extension => oidcc_http_util:query_params(),
    body_extension => oidcc_http_util:query_params()
}.

-type client_credentials_opts() :: #{
    scope => oidcc_scope:scopes(),
    refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    request_opts => oidcc_http_util:request_opts(),
    url_extension => oidcc_http_util:query_params(),
    body_extension => oidcc_http_util:query_params()
}.

-type error() ::
    {missing_claim, MissingClaim :: binary(), Claims :: oidcc_jwt_util:claims()}
    | pkce_verifier_required
    | no_supported_auth_method
    | bad_access_token_hash
    | sub_invalid
    | token_expired
    | token_not_yet_valid
    | {none_alg_used, Token :: t()}
    | {missing_claim, ExpClaim :: {binary(), term()}, Claims :: oidcc_jwt_util:claims()}
    | {grant_type_not_supported,
        authorization_code | refresh_token | jwt_bearer | client_credentials}
    | {invalid_property, {
        Field :: id_token | refresh_token | access_token | expires_in | scopes, GivenValue :: term()
    }}
    | oidcc_jwt_util:error()
    | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, request_token, start],
    description => <<"Emitted at the start of requesting a code token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, request_token, stop],
    description => <<"Emitted at the end of requesting a code token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, request_token, exception],
    description => <<"Emitted at the end of requesting a code token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, refresh_token, start],
    description => <<"Emitted at the start of refreshing a token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, refresh_token, stop],
    description => <<"Emitted at the end of refreshing a token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, refresh_token, exception],
    description => <<"Emitted at the end of refreshing a token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, jwt_profile_token, start],
    description => <<"Emitted at the start of exchanging a JWT profile token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, jwt_profile_token, stop],
    description => <<"Emitted at the end of exchanging a JWT profile token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, jwt_profile_token, exception],
    description => <<"Emitted at the end of exchanging a JWT profile token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, client_credentials, start],
    description => <<"Emitted at the start of exchanging a client credentials token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, client_credentials, stop],
    description => <<"Emitted at the end of exchanging a client credentials token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, client_credentials, exception],
    description => <<"Emitted at the end of exchanging a client credentials token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

%% @doc
%% retrieve the token using the authcode received before and directly validate
%% the result.
%%
%% the authcode was sent to the local endpoint by the OpenId Connect provider,
%% using redirects
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:retrieve_token/5}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get AuthCode from Redirect
%%
%% {ok, #oidcc_token{}} =
%%   oidcc:retrieve(AuthCode, ClientContext, #{
%%     redirect_uri => <<"https://example.com/callback">>}).
%% '''
%% @end
%% @since 3.0.0
-spec retrieve(AuthCode, ClientContext, Opts) ->
    {ok, t()} | {error, error()}
when
    AuthCode :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
retrieve(AuthCode, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{issuer = Issuer, grant_types_supported = GrantTypesSupported} =
        Configuration,

    case lists:member(<<"authorization_code">>, GrantTypesSupported) of
        true ->
            PkceVerifier = maps:get(pkce_verifier, Opts, none),
            QsBody =
                [
                    {<<"grant_type">>, <<"authorization_code">>},
                    {<<"code">>, AuthCode},
                    {<<"redirect_uri">>, maps:get(redirect_uri, Opts)}
                ],

            TelemetryOpts = #{
                topic => [oidcc, request_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },

            maybe
                {ok, Token} ?=
                    retrieve_a_token(
                        QsBody, PkceVerifier, ClientContext, Opts, TelemetryOpts, true
                    ),
                extract_response(Token, ClientContext, Opts)
            end;
        false ->
            {error, {grant_type_not_supported, authorization_code}}
    end.

%% @doc
%% Validate the JARM response, returning the valid claims as a map.
%%
%% The response was sent to the local endpoint by the OpenId Connect provider,
%% using redirects
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get Response from Redirect
%%
%% {ok, #{<<"code">> := AuthCode}} =
%%   oidcc:validate_jarm(Response, ClientContext, #{}),
%%
%% {ok, #oidcc_token{}} = oidcc:retrieve(AuthCode, ClientContext,
%%   #{redirect_uri => <<"https://redirect.example/">>}.
%% '''
%% @end
%% @since 3.2.0
-spec validate_jarm(Response, ClientContext, Opts) ->
    {ok, oidcc_jwt_util:claims()} | {error, error()}
when
    Response :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: validate_jarm_opts().
validate_jarm(Response, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId,
        client_secret = ClientSecret,
        client_jwks = ClientJwks,
        jwks = Jwks
    } = ClientContext,
    #oidcc_provider_configuration{
        issuer = Issuer,
        authorization_signing_alg_values_supported = SigningAlgSupported0,
        authorization_encryption_alg_values_supported = EncryptionAlgSupported0,
        authorization_encryption_enc_values_supported = EncryptionEncSupported0
    } =
        Configuration,

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
                JwksWithClientJwks;
            SigningOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, SigningOctJwk)
        end,
    EncryptionJwks =
        case oidcc_jwt_util:client_secret_oct_keys(EncryptionAlgSupported, ClientSecret) of
            none ->
                JwksWithClientJwks;
            EncryptionOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, EncryptionOctJwk)
        end,
    %% https://openid.net/specs/oauth-v2-jarm-final.html#name-processing-rules
    %% 1. decrypt if necessary
    %% 2. validate <<"iss">> claim
    %% 3. validate <<"aud">> claim
    %% 4. validate <<"exp">> claim
    %% 5. validate signature (valid, not <<"none">> alg)
    %% 6. continue processing
    maybe
        {ok, DecryptedResponse} ?=
            oidcc_jwt_util:decrypt_if_needed(
                Response,
                EncryptionJwks,
                EncryptionAlgSupported,
                EncryptionEncSupported
            ),
        ExpClaims = [
            {<<"iss">>, Issuer}
        ],
        TrustedAudience = maps:get(trusted_audiences, Opts, any),
        {ok, #jose_jwt{fields = PeekClaims}} ?=
            oidcc_jwt_util:peek_payload(DecryptedResponse),
        ok ?= oidcc_jwt_util:verify_claims(PeekClaims, ExpClaims),
        ok ?= verify_aud_claim(PeekClaims, ClientId, TrustedAudience),
        ok ?= verify_exp_claim(PeekClaims),
        ok ?= verify_nbf_claim(PeekClaims),
        {ok, {#jose_jwt{fields = Claims}, Jws}} ?=
            oidcc_jwt_util:verify_signature(
                DecryptedResponse, SigningAlgSupported, SigningJwks
            ),
        ok ?= oidcc_jwt_util:verify_not_none_alg(Jws),
        {ok, Claims}
    end.

%% @doc Refresh Token
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:refresh_token/5}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get AuthCode from Redirect
%%
%% {ok, Token} =
%%   oidcc_token:retrieve(AuthCode, ClientContext, #{
%%     redirect_uri => <<"https://example.com/callback">>}).
%%
%% %% Later
%%
%% {ok, #oidcc_token{}} =
%%   oidcc_token:refresh(Token,
%%                       ClientContext,
%%                       #{expected_subject => <<"sub_from_initial_id_token>>}).
%% '''
%% @end
%% @since 3.0.0
-spec refresh
    (RefreshToken, ClientContext, Opts) ->
        {ok, t()} | {error, error()}
    when
        RefreshToken :: binary(),
        ClientContext :: oidcc_client_context:t(),
        Opts :: refresh_opts();
    (Token, ClientContext, Opts) ->
        {ok, t()} | {error, error()}
    when
        Token :: oidcc_token:t(),
        ClientContext :: oidcc_client_context:t(),
        Opts :: refresh_opts_no_sub().
refresh(
    #oidcc_token{
        refresh = #oidcc_token_refresh{token = RefreshToken},
        id = #oidcc_token_id{claims = #{<<"sub">> := ExpectedSubject}}
    },
    ClientContext,
    Opts
) ->
    refresh(RefreshToken, ClientContext, maps:put(expected_subject, ExpectedSubject, Opts));
refresh(RefreshToken, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{issuer = Issuer, grant_types_supported = GrantTypesSupported} =
        Configuration,

    case lists:member(<<"refresh_token">>, GrantTypesSupported) of
        true ->
            ExpectedSub = maps:get(expected_subject, Opts),
            Scope = maps:get(scope, Opts, []),
            QueryString =
                [{<<"refresh_token">>, RefreshToken}, {<<"grant_type">>, <<"refresh_token">>}],
            QueryString1 = oidcc_scope:query_append_scope(Scope, QueryString),

            TelemetryOpts = #{
                topic => [oidcc, refresh_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },

            maybe
                {ok, Token} ?=
                    retrieve_a_token(QueryString1, none, ClientContext, Opts, TelemetryOpts, true),
                {ok, TokenRecord} ?=
                    extract_response(Token, ClientContext, maps:put(nonce, any, Opts)),
                case TokenRecord of
                    #oidcc_token{id = #oidcc_token_id{claims = #{<<"sub">> := ExpectedSub}}} ->
                        {ok, TokenRecord};
                    #oidcc_token{} ->
                        {error, sub_invalid}
                end
            end;
        false ->
            {error, {grant_type_not_supported, refresh_token}}
    end.

%% @doc Retrieve JSON Web Token (JWT) Profile Token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7523#section-4]
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:jwt_profile_token/6}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% {ok, KeyJson} = file:read_file("jwt-profile.json"),
%% KeyMap = jose:decode(KeyJson),
%% Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),
%%
%% {ok, #oidcc_token{}} =
%%   oidcc_token:jwt_profile(<<"subject">>,
%%                           ClientContext,
%%                           Key,
%%                           #{scope => [<<"scope">>],
%%                             kid => maps:get(<<"keyId">>, KeyMap)}).
%% '''
%% @end
%% @since 3.0.0
-spec jwt_profile(Subject, ClientContext, Jwk, Opts) -> {ok, t()} | {error, error()} when
    Subject :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Jwk :: jose_jwk:key(),
    Opts :: jwt_profile_opts().
jwt_profile(Subject, ClientContext, Jwk, Opts) ->
    #oidcc_client_context{provider_configuration = Configuration, client_id = ClientId} =
        ClientContext,
    #oidcc_provider_configuration{issuer = Issuer, grant_types_supported = GrantTypesSupported} =
        Configuration,

    case lists:member(<<"urn:ietf:params:oauth:grant-type:jwt-bearer">>, GrantTypesSupported) of
        true ->
            Iat = os:system_time(seconds),
            Exp = Iat + 60,

            AssertionClaims = #{
                <<"iss">> => Subject,
                <<"sub">> => Subject,
                <<"aud">> => [Issuer],
                <<"exp">> => Exp,
                <<"iat">> => Iat,
                <<"nbf">> => Iat
            },
            AssertionJwt = jose_jwt:from(AssertionClaims),

            AssertionJws0 = #{
                <<"alg">> => <<"RS256">>,
                <<"typ">> => <<"JWT">>
            },
            AssertionJws =
                case maps:get(kid, Opts, none) of
                    none -> AssertionJws0;
                    Kid -> maps:put(<<"kid">>, Kid, AssertionJws0)
                end,

            {_Jws, Assertion} = jose_jws:compact(jose_jwt:sign(Jwk, AssertionJws, AssertionJwt)),

            Scope = maps:get(scope, Opts, []),
            QueryString =
                [
                    {<<"assertion">>, Assertion},
                    {<<"grant_type">>, <<"urn:ietf:params:oauth:grant-type:jwt-bearer">>}
                ],
            QueryString1 = oidcc_scope:query_append_scope(Scope, QueryString),

            TelemetryOpts = #{
                topic => [oidcc, jwt_profile_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },

            maybe
                {ok, Token} ?=
                    retrieve_a_token(QueryString1, none, ClientContext, Opts, TelemetryOpts, false),
                {ok, TokenRecord} ?=
                    extract_response(Token, ClientContext, maps:put(nonce, any, Opts)),
                case TokenRecord of
                    #oidcc_token{id = none} ->
                        {ok, TokenRecord};
                    #oidcc_token{id = #oidcc_token_id{claims = #{<<"sub">> := Subject}}} ->
                        {ok, TokenRecord};
                    #oidcc_token{} ->
                        {error, sub_invalid}
                end
            end;
        false ->
            {error, {grant_type_not_supported, jwt_bearer}}
    end.

%% @doc Retrieve Client Credential Token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4]
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:client_credentials_token/4}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% {ok, #oidcc_token{}} =
%%   oidcc_token:client_credentials(ClientContext,
%%                                  #{scope => [<<"scope">>]}).
%% '''
%% @end
%% @since 3.0.0
-spec client_credentials(ClientContext, Opts) -> {ok, t()} | {error, error()} when
    ClientContext :: oidcc_client_context:authenticated_t(),
    Opts :: client_credentials_opts().
client_credentials(ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{issuer = Issuer, grant_types_supported = GrantTypesSupported} =
        Configuration,

    case lists:member(<<"client_credentials">>, GrantTypesSupported) of
        true ->
            Scope = maps:get(scope, Opts, []),
            QueryString = [{<<"grant_type">>, <<"client_credentials">>}],
            QueryString1 = oidcc_scope:query_append_scope(Scope, QueryString),

            TelemetryOpts = #{
                topic => [oidcc, client_credentials],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },

            maybe
                {ok, Token} ?=
                    retrieve_a_token(QueryString1, none, ClientContext, Opts, TelemetryOpts, true),
                extract_response(Token, ClientContext, maps:put(nonce, any, Opts))
            end;
        false ->
            {error, {grant_type_not_supported, client_credentials}}
    end.

-spec extract_response(TokenResponseBody, ClientContext, Opts) ->
    {ok, t()} | {error, error()}
when
    TokenResponseBody :: map(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
extract_response(TokenResponseBody, ClientContext, Opts) ->
    RefreshJwksFun = maps:get(refresh_jwks, Opts, undefined),
    maybe
        {ok, Token} ?= int_extract_response(TokenResponseBody, ClientContext, Opts),
        {ok, Token}
    else
        {error, {no_matching_key_with_kid, Kid}} when RefreshJwksFun =/= undefined ->
            #oidcc_client_context{jwks = OldJwks} = ClientContext,
            maybe
                {ok, RefreshedJwks} ?= RefreshJwksFun(OldJwks, Kid),
                RefreshedClientContext = ClientContext#oidcc_client_context{jwks = RefreshedJwks},
                int_extract_response(TokenResponseBody, RefreshedClientContext, Opts)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec int_extract_response(TokenMap, ClientContext, Opts) ->
    {ok, t()} | {error, error()}
when
    TokenMap :: map(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
int_extract_response(TokenMap, ClientContext, Opts) ->
    maybe
        {ok, Scopes} ?= extract_scope(TokenMap, Opts),
        {ok, AccessExpire} ?= extract_expiry(TokenMap),
        {ok, AccessTokenRecord} ?= extract_access_token(TokenMap, AccessExpire),
        {ok, RefreshTokenRecord} ?= extract_refresh_token(TokenMap),
        {ok, {IdTokenRecord, NoneUsed}} ?= extract_id_token(TokenMap, ClientContext, Opts),
        TokenRecord = #oidcc_token{
            id = IdTokenRecord,
            access = AccessTokenRecord,
            refresh = RefreshTokenRecord,
            scope = Scopes
        },
        ok ?= verify_access_token_map_hash(TokenRecord),
        %% If none alg was used, continue with checks to allow the user to decide
        %% if he wants to use the result
        case NoneUsed of
            true ->
                {error, {none_alg_used, TokenRecord}};
            false ->
                {ok, TokenRecord}
        end
    end.

-spec extract_scope(TokenMap, Opts) -> {ok, oidcc_scope:scopes()} | {error, error()} when
    TokenMap :: map(), Opts :: retrieve_opts().
extract_scope(TokenMap, Opts) ->
    Scopes = maps:get(scope, Opts, []),
    case maps:get(<<"scope">>, TokenMap, oidcc_scope:scopes_to_bin(Scopes)) of
        ScopeBinary when is_binary(ScopeBinary) ->
            {ok, oidcc_scope:parse(ScopeBinary)};
        ScopeOther ->
            {error, {invalid_property, {scope, ScopeOther}}}
    end.

-spec extract_expiry(TokenMap) -> {ok, undefined | integer()} | {error, error()} when
    TokenMap :: map().
extract_expiry(TokenMap) ->
    case maps:get(<<"expires_in">>, TokenMap, undefined) of
        undefined ->
            {ok, undefined};
        ExpiresInNum when is_integer(ExpiresInNum) ->
            {ok, ExpiresInNum};
        ExpiresInBinary when is_binary(ExpiresInBinary) ->
            try
                {ok, binary_to_integer(ExpiresInBinary)}
            catch
                error:badarg ->
                    {error, {invalid_property, {expires_in, ExpiresInBinary}}}
            end;
        ExpiresInOther ->
            {error, {invalid_property, {expires_in, ExpiresInOther}}}
    end.

-spec extract_access_token(TokenMap, Expiry) -> {ok, access()} | {error, error()} when
    TokenMap :: map(),
    Expiry :: integer().
extract_access_token(TokenMap, Expiry) ->
    case maps:get(<<"access_token">>, TokenMap, none) of
        none ->
            {ok, none};
        Token when is_binary(Token) ->
            TokenType = maps:get(<<"token_type">>, TokenMap, <<"Bearer">>),
            {ok, #oidcc_token_access{token = Token, expires = Expiry, type = TokenType}};
        Other ->
            {error, {invalid_property, {access_token, Other}}}
    end.

-spec extract_refresh_token(TokenMap) -> {ok, refresh()} | {error, error()} when
    TokenMap :: map().
extract_refresh_token(TokenMap) ->
    case maps:get(<<"refresh_token">>, TokenMap, none) of
        none ->
            {ok, none};
        Token when is_binary(Token) ->
            {ok, #oidcc_token_refresh{token = Token}};
        Other ->
            {error, {invalid_property, {refresh_token, Other}}}
    end.

-spec extract_id_token(TokenMap, ClientContext, Opts) ->
    {ok, {TokenRecord, NoneUsed}} | {error, error()}
when
    TokenMap :: map(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts(),
    TokenRecord :: id(),
    NoneUsed :: boolean().
extract_id_token(TokenMap, ClientContext, Opts) ->
    case maps:get(<<"id_token">>, TokenMap, none) of
        none ->
            {ok, {none, false}};
        Token when is_binary(Token) ->
            case validate_id_token(Token, ClientContext, Opts) of
                {ok, OkClaims} ->
                    {ok, {#oidcc_token_id{token = Token, claims = OkClaims}, false}};
                {error, {none_alg_used, NoneClaims}} ->
                    {ok, {#oidcc_token_id{token = Token, claims = NoneClaims}, true}};
                {error, Reason} ->
                    {error, Reason}
            end;
        Other ->
            {error, {invalid_property, {id_token, Other}}}
    end.

-spec verify_access_token_map_hash(TokenRecord :: t()) ->
    ok | {error, error()}.
verify_access_token_map_hash(#oidcc_token{
    id =
        #oidcc_token_id{
            claims =
                #{<<"at_hash">> := ExpectedHash}
        },
    access = #oidcc_token_access{token = AccessToken}
}) ->
    <<BinHash:16/binary, _Rest/binary>> = crypto:hash(sha256, AccessToken),
    case base64:encode(BinHash, #{mode => urlsafe, padding => false}) of
        ExpectedHash ->
            ok;
        _Other ->
            {error, bad_access_token_hash}
    end;
verify_access_token_map_hash(#oidcc_token{}) ->
    ok.

%% @doc Validate ID Token
%%
%% Usually the id token is validated using {@link retrieve/3}.
%% If you get the token passed from somewhere else, this function can validate it.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get IdToken from somewhere
%%
%% {ok, Claims} =
%%   oidcc:validate_id_token(IdToken, ClientContext, ExpectedNonce).
%% '''
%% @end
%% @since 3.0.0
-spec validate_id_token(IdToken, ClientContext, NonceOrOpts) ->
    {ok, Claims} | {error, error()}
when
    IdToken :: binary(),
    ClientContext :: oidcc_client_context:t(),
    NonceOrOpts :: Nonce | retrieve_opts(),
    Nonce :: binary() | any,
    Claims :: oidcc_jwt_util:claims().
validate_id_token(IdToken, ClientContext, Nonce) when is_binary(Nonce) ->
    validate_id_token(IdToken, ClientContext, #{nonce => Nonce});
validate_id_token(IdToken, ClientContext, any) ->
    validate_id_token(IdToken, ClientContext, #{nonce => any});
validate_id_token(IdToken, ClientContext, Opts) when is_map(Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = #jose_jwk{} = Jwks,
        client_id = ClientId,
        client_secret = ClientSecret
    } =
        ClientContext,
    #oidcc_provider_configuration{
        id_token_signing_alg_values_supported = AllowAlgorithms,
        issuer = Issuer
    } =
        Configuration,

    Nonce = maps:get(nonce, Opts, any),
    TrustedAudience = maps:get(trusted_audiences, Opts, any),

    maybe
        ExpClaims0 = [{<<"iss">>, Issuer}],
        ExpClaims =
            case Nonce of
                any ->
                    ExpClaims0;
                Bin when is_binary(Bin) ->
                    [{<<"nonce">>, Nonce} | ExpClaims0]
            end,
        JwksInclOct =
            case ClientSecret of
                unauthenticated ->
                    Jwks;
                Secret ->
                    case oidcc_jwt_util:client_secret_oct_keys(AllowAlgorithms, Secret) of
                        none ->
                            Jwks;
                        OctJwk ->
                            oidcc_jwt_util:merge_jwks(Jwks, OctJwk)
                    end
            end,
        MaybeVerified = oidcc_jwt_util:verify_signature(IdToken, AllowAlgorithms, JwksInclOct),
        {ok, {#jose_jwt{fields = Claims}, Jws}} ?=
            case MaybeVerified of
                {ok, Valid} ->
                    {ok, Valid};
                {error, {none_alg_used, Jwt0, Jws0}} ->
                    {ok, {Jwt0, Jws0}};
                Other ->
                    Other
            end,
        ok ?= oidcc_jwt_util:verify_claims(Claims, ExpClaims),
        ok ?= verify_missing_required_claims(Claims),
        ok ?= verify_aud_claim(Claims, ClientId, TrustedAudience),
        ok ?= verify_azp_claim(Claims, ClientId),
        ok ?= verify_exp_claim(Claims),
        ok ?= verify_nbf_claim(Claims),
        case Jws of
            #jose_jws{alg = {jose_jws_alg_none, none}} ->
                {error, {none_alg_used, Claims}};
            #jose_jws{} ->
                {ok, Claims}
        end
    end.

%% @doc Authorization headers
%%
%%   Generate a map of authorization headers to use when using the given
%%   access token to access an API endpoint.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get Access Token record from somewhere
%%
%% Headers =
%%   oidcc:authorization_headers(AccessTokenRecord, :get, Url, ClientContext).
%% '''
%% @end
%% @since 3.2.0
-spec authorization_headers(AccessTokenRecord, Method, Endpoint, ClientContext) -> HeaderMap when
    AccessTokenRecord :: access(),
    Method :: post | get,
    Endpoint :: uri_string:uri_string(),
    ClientContext :: oidcc_client_context:t(),
    HeaderMap :: #{binary() => binary()}.
-spec authorization_headers(AccessTokenRecord, Method, Endpoint, ClientContext, Opts) ->
    HeaderMap
when
    AccessTokenRecord :: access(),
    Method :: post | get,
    Endpoint :: uri_string:uri_string(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: #{dpop_nonce => binary()},
    HeaderMap :: #{binary() => binary()}.
authorization_headers(AccessTokenRecord, Method, Endpoint, ClientContext) ->
    authorization_headers(AccessTokenRecord, Method, Endpoint, ClientContext, #{}).

authorization_headers(
    #oidcc_token_access{} = AccessTokenRecord,
    Method,
    Endpoint,
    #oidcc_client_context{} = ClientContext,
    Opts
) ->
    #oidcc_token_access{token = AccessToken, type = AccessTokenType} = AccessTokenRecord,
    Header = oidcc_auth_util:add_authorization_header(
        AccessToken, AccessTokenType, Method, Endpoint, Opts, ClientContext
    ),
    maps:from_list([{list_to_binary(Key), list_to_binary([Value])} || {Key, Value} <- Header]).

-spec verify_aud_claim(Claims, ClientId, TrustedAudience) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), ClientId :: binary(), TrustedAudience :: [binary()] | any.
verify_aud_claim(#{<<"aud">> := ClientId}, ClientId, _TrustedAudience) ->
    ok;
verify_aud_claim(#{<<"aud">> := Audience} = Claims, ClientId, any) when is_list(Audience) ->
    case lists:member(ClientId, Audience) of
        true -> ok;
        false -> {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}
    end;
verify_aud_claim(#{<<"aud">> := Audience} = Claims, ClientId, TrustedAudience0) when
    is_list(Audience)
->
    TrustedAudience = [ClientId | TrustedAudience0],
    maybe
        true ?= lists:member(ClientId, Audience),
        [] ?= [A || A <- Audience, not lists:member(A, TrustedAudience)],
        ok
    else
        _ -> {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}
    end;
verify_aud_claim(Claims, ClientId, _TrustedAudience) ->
    {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}.

-spec verify_azp_claim(Claims, ClientId) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), ClientId :: binary().
verify_azp_claim(#{<<"azp">> := ClientId}, ClientId) ->
    ok;
verify_azp_claim(#{<<"azp">> := _Azp} = Claims, ClientId) ->
    {error, {missing_claim, {<<"azp">>, ClientId}, Claims}};
verify_azp_claim(_Claims, _ClientId) ->
    ok.

-spec verify_exp_claim(Claims) -> ok | {error, error()} when Claims :: oidcc_jwt_util:claims().
verify_exp_claim(#{<<"exp">> := Expiry}) ->
    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,
    case erlang:system_time(second) > Expiry + MaxClockSkew of
        true -> {error, token_expired};
        false -> ok
    end;
verify_exp_claim(Claims) ->
    {error, {missing_claim, <<"exp">>, Claims}}.

-spec verify_nbf_claim(Claims) -> ok | {error, error()} when Claims :: oidcc_jwt_util:claims().
verify_nbf_claim(#{<<"nbf">> := Expiry}) ->
    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,
    case erlang:system_time(second) < Expiry - MaxClockSkew of
        true -> {error, token_not_yet_valid};
        false -> ok
    end;
verify_nbf_claim(_Claims) ->
    ok.

-spec verify_missing_required_claims(Claims) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims().
verify_missing_required_claims(Claims) ->
    Required = [<<"iss">>, <<"sub">>, <<"aud">>, <<"exp">>, <<"iat">>],
    CheckKeys = fun(Key, _Val, Acc) -> lists:delete(Key, Acc) end,
    case maps:fold(CheckKeys, Required, Claims) of
        [] ->
            ok;
        [MissingClaim | _Rest] ->
            {error, {missing_claim, MissingClaim, Claims}}
    end.

-spec retrieve_a_token(
    QsBodyIn, PkceVerifier, ClientContext, Opts, TelemetryOpts, AuthenticateClient
) ->
    {ok, map()} | {error, error()}
when
    QsBodyIn :: oidcc_http_util:query_params(),
    PkceVerifier :: binary() | none,
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts() | refresh_opts(),
    TelemetryOpts :: oidcc_http_util:telemetry_opts(),
    AuthenticateClient :: boolean().
retrieve_a_token(
    _QsBodyIn, none, _ClientContext, #{require_pkce := true}, _TelemetryOpts, _AuthenticateClient
) ->
    {error, pkce_verifier_required};
retrieve_a_token(QsBodyIn, PkceVerifier, ClientContext, Opts, TelemetryOpts, AuthenticateClient) ->
    #oidcc_client_context{provider_configuration = Configuration} =
        ClientContext,
    #oidcc_provider_configuration{
        token_endpoint = TokenEndpoint,
        token_endpoint_auth_methods_supported = SupportedAuthMethods0,
        token_endpoint_auth_signing_alg_values_supported = SigningAlgs
    } =
        Configuration,

    QueryParams = maps:get(url_extension, Opts, []),

    Endpoint =
        case QueryParams of
            [] -> TokenEndpoint;
            _ -> [TokenEndpoint, <<"?">>, uri_string:compose_query(QueryParams)]
        end,

    Header0 = [{"accept", "application/jwt, application/json"}],

    QsBody0 = QsBodyIn ++ maps:get(body_extension, Opts, []),
    QsBody = add_pkce_verifier(QsBody0, PkceVerifier),

    SupportedAuthMethods =
        case AuthenticateClient of
            true -> SupportedAuthMethods0;
            false -> [<<"none">>]
        end,

    DpopOpts =
        case Opts of
            #{dpop_nonce := DpopNonce} ->
                #{nonce => DpopNonce};
            _ ->
                #{}
        end,
    maybe
        {ok, {Body, Header1}} ?=
            oidcc_auth_util:add_client_authentication(
                QsBody, Header0, SupportedAuthMethods, SigningAlgs, Opts, ClientContext
            ),
        Header = oidcc_auth_util:add_dpop_proof_header(
            Header1, post, Endpoint, DpopOpts, ClientContext
        ),
        Request =
            {Endpoint, Header, "application/x-www-form-urlencoded", uri_string:compose_query(Body)},
        RequestOpts = maps:get(request_opts, Opts, #{}),
        {ok, {{json, TokenResponse}, _Headers}} ?=
            oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
        {ok, TokenResponse}
    else
        {error, {use_dpop_nonce, NewDpopNonce, _}} when DpopOpts =:= #{} ->
            %% only retry automatically if we didn't use a nonce the first time
            %% (to avoid infinite loops)
            retrieve_a_token(
                QsBodyIn,
                PkceVerifier,
                ClientContext,
                Opts#{dpop_nonce => NewDpopNonce},
                TelemetryOpts,
                AuthenticateClient
            );
        {error, Reason} ->
            {error, Reason}
    end.

-spec add_pkce_verifier(QueryList, PkceVerifier) -> oidcc_http_util:query_params() when
    QueryList :: oidcc_http_util:query_params(),
    PkceVerifier :: binary() | none.
add_pkce_verifier(BodyQs, none) ->
    BodyQs;
add_pkce_verifier(BodyQs, PkceVerifier) ->
    [{<<"code_verifier">>, PkceVerifier} | BodyQs].
