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
-export([validate_id_token/3]).

-export_type([access/0]).
-export_type([client_credentials_opts/0]).
-export_type([error/0]).
-export_type([id/0]).
-export_type([jwt_profile_opts/0]).
-export_type([refresh/0]).
-export_type([refresh_opts/0]).
-export_type([refresh_opts_no_sub/0]).
-export_type([retrieve_opts/0]).
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
    #oidcc_token_access{token :: binary(), expires :: pos_integer() | undefined}.
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
        nonce => binary() | any,
        scope => oidcc_scope:scopes(),
        preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        redirect_uri := uri_string:uri_string(),
        request_opts => oidcc_http_util:request_opts()
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
%%   <li>`nonce' - Nonce to check</li>
%%   <li>`scope' - Scope to store with the token</li>
%%   <li>`refresh_jwks' - How to handle tokens with an unknown `kid'.
%%     See {@link oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun()}</li>
%%   <li>`redirect_uri' - Redirect uri given to {@link oidcc_authorization:create_redirect_url/2}</li>
%% </ul>

-type refresh_opts_no_sub() ::
    #{
        scope => oidcc_scope:scopes(),
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        request_opts => oidcc_http_util:request_opts()
    }.
%% See {@link refresh_opts_no_sub()}

-type refresh_opts() ::
    #{
        scope => oidcc_scope:scopes(),
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        expected_subject := binary(),
        request_opts => oidcc_http_util:request_opts()
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
    kid => binary()
}.

-type client_credentials_opts() :: #{
    scope => oidcc_scope:scopes(),
    refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    request_opts => oidcc_http_util:request_opts()
}.

-type error() ::
    {missing_claim, MissingClaim :: binary(), Claims :: oidcc_jwt_util:claims()}
    | no_supported_auth_method
    | bad_access_token_hash
    | sub_invalid
    | token_expired
    | token_not_yet_valid
    | {none_alg_used, Token :: t()}
    | {missing_claim, ExpClaim :: {binary(), term()}, Claims :: oidcc_jwt_util:claims()}
    | {grant_type_not_supported,
        authorization_code | refresh_token | jwt_bearer | client_credentials}
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
    Nonce = maps:get(nonce, Opts, any),
    Scopes = maps:get(scope, Opts, []),
    IdToken = maps:get(<<"id_token">>, TokenMap, none),
    AccessToken = maps:get(<<"access_token">>, TokenMap, none),
    AccessExpire = maps:get(<<"expires_in">>, TokenMap, undefined),
    RefreshToken = maps:get(<<"refresh_token">>, TokenMap, none),
    Scope = maps:get(<<"scope">>, TokenMap, oidcc_scope:scopes_to_bin(Scopes)),
    AccessTokenRecord =
        case AccessToken of
            none -> none;
            _ -> #oidcc_token_access{token = AccessToken, expires = AccessExpire}
        end,
    RefreshTokenRecord =
        case RefreshToken of
            none ->
                none;
            _ ->
                #oidcc_token_refresh{token = RefreshToken}
        end,
    case IdToken of
        none ->
            {ok, #oidcc_token{
                id = none,
                access = AccessTokenRecord,
                refresh = RefreshTokenRecord,
                scope = oidcc_scope:parse(Scope)
            }};
        _ ->
            RescueNone =
                case validate_id_token(IdToken, ClientContext, Nonce) of
                    {ok, OkClaims} ->
                        {ok, {OkClaims, false}};
                    {error, {none_alg_used, NoneClaims}} ->
                        {ok, {NoneClaims, true}};
                    {error, Reason} ->
                        {error, Reason}
                end,

            maybe
                {ok, {Claims, NoneUsed}} ?= RescueNone,
                IdTokenRecord = #oidcc_token_id{token = IdToken, claims = Claims},
                TokenRecord = #oidcc_token{
                    id = IdTokenRecord,
                    access = AccessTokenRecord,
                    refresh = RefreshTokenRecord,
                    scope = oidcc_scope:parse(Scope)
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
            end
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
%% If you gget the token passed from somewhere else, this function can validate it.
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
-spec validate_id_token(IdToken, ClientContext, Nonce) ->
    {ok, Claims} | {error, error()}
when
    IdToken :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Nonce :: binary() | any,
    Claims :: oidcc_jwt_util:claims().
validate_id_token(IdToken, ClientContext, Nonce) ->
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
        ok ?= verify_aud_claim(Claims, ClientId),
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

-spec verify_aud_claim(Claims, ClientId) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), ClientId :: binary().
verify_aud_claim(#{<<"aud">> := Audience} = Claims, ClientId) when is_list(Audience) ->
    case lists:member(ClientId, Audience) of
        true -> ok;
        false -> {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}
    end;
verify_aud_claim(#{<<"aud">> := ClientId}, ClientId) ->
    ok;
verify_aud_claim(Claims, ClientId) ->
    {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}.

-spec verify_azp_claim(Claims, ClientId) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), ClientId :: binary().
verify_azp_claim(#{<<"azp">> := ClientId}, ClientId) ->
    ok;
verify_azp_claim(#{<<"azp">> := _Azp} = Claims, ClientId) ->
    {missing_claim, {<<"azp">>, ClientId}, Claims};
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
    end.

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
retrieve_a_token(QsBodyIn, PkceVerifier, ClientContext, Opts, TelemetryOpts, AuthenticateClient) ->
    #oidcc_client_context{provider_configuration = Configuration} =
        ClientContext,
    #oidcc_provider_configuration{
        token_endpoint = TokenEndpoint,
        token_endpoint_auth_methods_supported = SupportedAuthMethods0,
        token_endpoint_auth_signing_alg_values_supported = SigningAlgs
    } =
        Configuration,

    Header0 = [{"accept", "application/jwt, application/json"}],

    Body0 = add_pkce_verifier(QsBodyIn, PkceVerifier),

    SupportedAuthMethods =
        case AuthenticateClient of
            true -> SupportedAuthMethods0;
            false -> [<<"none">>]
        end,

    maybe
        {ok, {Body, Header}} ?=
            oidcc_auth_util:add_client_authentication(
                Body0, Header0, SupportedAuthMethods, SigningAlgs, Opts, ClientContext
            ),
        Request =
            {TokenEndpoint, Header, "application/x-www-form-urlencoded",
                uri_string:compose_query(Body)},
        RequestOpts = maps:get(request_opts, Opts, #{}),
        {ok, {{json, TokenResponse}, _Headers}} ?=
            oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
        {ok, TokenResponse}
    end.

-spec add_pkce_verifier(QueryList, PkceVerifier) -> oidcc_http_util:query_params() when
    QueryList :: oidcc_http_util:query_params(),
    PkceVerifier :: binary() | none.
add_pkce_verifier(BodyQs, none) ->
    BodyQs;
add_pkce_verifier(BodyQs, PkceVerifier) ->
    [{<<"code_verifier">>, PkceVerifier} | BodyQs].
