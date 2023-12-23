%%%-------------------------------------------------------------------
%% @doc OpenID Connect Userinfo
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#UserInfo]
%%
%% <h2>Telemetry</h2>
%%
%% See {@link 'Elixir.Oidcc.Userinfo'}
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_userinfo).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-export([retrieve/3]).

-export_type([error/0]).
-export_type([retrieve_opts/0]).
-export_type([retrieve_opts_no_sub/0]).

-type retrieve_opts_no_sub() ::
    #{
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        dpop_nonce => binary()
    }.
%% See {@link retrieve_opts()}

-type retrieve_opts() ::
    #{
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        expected_subject => binary() | any,
        dpop_nonce => binary()
    }.
%% Configure userinfo request
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest]
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`refresh_jwks' - How to handle tokens with an unknown `kid'.
%%     See {@link oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun()}</li>
%%   <li>`expected_subject' - expected subject for the userinfo
%%     (`sub' from id token)</li>
%%   <li>`dpop_nonce' - if using DPoP, the `nonce' value to use in the
%%     proof claim</li>
%% </ul>

-type error() ::
    {distributed_claim_not_found, {ClaimSource :: binary(), ClaimName :: binary()}}
    | no_access_token
    | invalid_content_type
    | bad_subject
    | oidcc_jwt_util:error()
    | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, userinfo, start],
    description => <<"Emitted at the start of loading userinfo">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, userinfo, stop],
    description => <<"Emitted at the end of loading userinfo">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, userinfo, exception],
    description => <<"Emitted at the end of loading userinfo">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

%% @doc
%% Load userinfo for the given token
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:retrieve_userinfo/5}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get Token
%%
%% {ok, #{<<"sub">> => Sub}} =
%%   oidcc_userinfo:retrieve(Token, ClientContext, #{}).
%% '''
%% @end
%% @since 3.0.0
-spec retrieve
    (Token, ClientContext, Opts) -> {ok, oidcc_jwt_util:claims()} | {error, error()} when
        Token :: oidcc_token:t(),
        ClientContext :: oidcc_client_context:t(),
        Opts :: retrieve_opts_no_sub();
    (Token, ClientContext, Opts) -> {ok, oidcc_jwt_util:claims()} | {error, error()} when
        Token :: oidcc_token:access() | binary(),
        ClientContext :: oidcc_client_context:t(),
        Opts :: retrieve_opts().
retrieve(
    #oidcc_token{access = #oidcc_token_access{} = AccessTokenRecord, id = IdTokenRecord},
    ClientContext,
    Opts
) ->
    #oidcc_token_id{claims = #{<<"sub">> := ExpectedSubject}} = IdTokenRecord,
    retrieve(
        AccessTokenRecord,
        ClientContext,
        maps:put(expected_subject, ExpectedSubject, Opts)
    );
retrieve(#oidcc_token{access = none}, #oidcc_client_context{}, _Opts) ->
    {error, no_access_token};
retrieve(#oidcc_token_access{} = AccessTokenRecord, #oidcc_client_context{} = ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{
        userinfo_endpoint = Endpoint,
        issuer = Issuer
    } = Configuration,
    #oidcc_token_access{token = AccessToken, type = AccessTokenType} = AccessTokenRecord,

    %% Dialyzer gets confused about the type of Opts here (thinking that it
    %% loses the expected_subject key), so we perform a no-op map operation to
    %% separate the two.
    %%
    AuthorizationOpts = Opts#{},
    Header = oidcc_auth_util:add_authorization_header(
        AccessToken, AccessTokenType, get, Endpoint, AuthorizationOpts, ClientContext
    ),

    Request = {Endpoint, Header},
    RequestOpts = maps:get(request_opts, Opts, #{}),
    TelemetryOpts = #{
        topic => [oidcc, userinfo],
        extra_meta => #{issuer => Issuer, client_id => ClientId}
    },

    HasDpopNonce = maps:is_key(dpop_nonce, AuthorizationOpts),

    maybe
        {ok, {UserinfoResponse, _Headers}} ?=
            oidcc_http_util:request(get, Request, TelemetryOpts, RequestOpts),
        {ok, Claims} ?= validate_userinfo_body(UserinfoResponse, ClientContext, Opts),
        lookup_distributed_claims(Claims, ClientContext, Opts)
    else
        {error, {use_dpop_nonce, DpopNonce, _}} when
            HasDpopNonce =:= false
        ->
            %% retry once if we didn't provide a nonce the first time
            retrieve(AccessTokenRecord, ClientContext, Opts#{dpop_nonce => DpopNonce});
        {error, Reason} ->
            {error, Reason}
    end;
retrieve(AccessToken, #oidcc_client_context{} = ClientContext, Opts) when is_binary(AccessToken) ->
    AccessTokenRecord = #oidcc_token_access{token = AccessToken},
    retrieve(AccessTokenRecord, ClientContext, Opts).

-spec validate_userinfo_body(Body, ClientContext, Opts) ->
    {ok, Claims} | {error, error()}
when
    Body :: {json, map()} | {jwt, binary()},
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts(),
    Claims :: oidcc_jwt_util:claims().
validate_userinfo_body({json, Userinfo}, _ClientContext, Opts) ->
    ExpectedSubject = maps:get(expected_subject, Opts),

    case {ExpectedSubject, Userinfo} of
        {any, Map} -> {ok, Map};
        {ExpectedSubject, #{<<"sub">> := ExpectedSubject} = Map} -> {ok, Map};
        {_, #{}} -> {error, bad_subject}
    end;
validate_userinfo_body({jwt, UserinfoBody}, ClientContext, Opts) ->
    #oidcc_client_context{provider_configuration = Configuration, client_id = ClientId} =
        ClientContext,
    #oidcc_provider_configuration{issuer = Issuer} = Configuration,
    ExpectedSubject = maps:get(expected_subject, Opts),
    ExpectedClaims0 = [
        {<<"aud">>, ClientId},
        {<<"iss">>, Issuer}
    ],
    ExpectedClaims =
        case maps:get(expected_subject, Opts) of
            any -> ExpectedClaims0;
            ExpectedSubject -> [{<<"sub">>, ExpectedSubject} | ExpectedClaims0]
        end,
    validate_userinfo_token(
        UserinfoBody,
        ClientContext,
        maps:put(expected_claims, ExpectedClaims, Opts)
    ).

-spec validate_userinfo_token(Token, ClientContext, Opts) ->
    {ok, Claims} | {error, error()}
when
    Token :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts ::
        #{
            refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
            expected_subject => binary(),
            expected_claims => [{binary(), term()}]
        },
    Claims :: oidcc_jwt_util:claims().
validate_userinfo_token(UserinfoToken, ClientContext, Opts) ->
    RefreshJwksFun = maps:get(refresh_jwks, Opts, undefined),
    ExpClaims = maps:get(expected_claims, Opts, []),
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = #jose_jwk{} = Jwks,
        client_id = ClientId,
        client_secret = ClientSecret
    } =
        ClientContext,
    #oidcc_provider_configuration{
        userinfo_signing_alg_values_supported = AllowAlgorithms,
        issuer = Issuer
    } =
        Configuration,
    maybe
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
        {ok, {#jose_jwt{fields = Claims}, _Jws}} ?=
            oidcc_jwt_util:verify_signature(UserinfoToken, AllowAlgorithms, JwksInclOct),
        ok ?= oidcc_jwt_util:verify_claims(Claims, ExpClaims),
        {ok, maps:remove(nonce, Claims)}
    else
        {error, {no_matching_key_with_kid, Kid}} when RefreshJwksFun =/= undefined ->
            maybe
                {ok, RefreshedJwks} ?= RefreshJwksFun(Jwks, Kid),
                RefreshedClientContext = ClientContext#oidcc_client_context{jwks = RefreshedJwks},
                validate_userinfo_token(UserinfoToken, RefreshedClientContext, Opts)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec lookup_distributed_claims(Claims, ClientContext, Opts) ->
    {ok, Claims} | {error, error()}
when
    Claims :: oidcc_jwt_util:claims(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
lookup_distributed_claims(
    #{
        <<"_claim_names">> := ClaimNames,
        <<"_claim_sources">> := ClaimSources
    } =
        Claims,
    ClientContext,
    Opts
) ->
    maybe
        {ok, DistributedClaims} ?=
            lookup_distributed_claim(maps:to_list(ClaimSources), Opts, []),
        {ok, ValidatedClaims} ?=
            validate_distributed_claim(DistributedClaims, ClientContext, Opts, #{}),
        combine_claim(maps:to_list(ClaimNames), ValidatedClaims, Claims)
    end;
lookup_distributed_claims(Claims, _ClientContext, _Opts) ->
    {ok, Claims}.

-spec lookup_distributed_claim(Claims, Opts, Acc) -> {ok, Acc} | {error, error()} when
    Claims :: [{binary(), #{binary() := binary()}}],
    Opts :: retrieve_opts(),
    Acc :: [{binary(), binary()}].
lookup_distributed_claim([], _Opts, Acc) ->
    {ok, Acc};
lookup_distributed_claim([{ClaimName, #{<<"JWT">> := Jwt}} | Rest], Opts, Acc) ->
    lookup_distributed_claim(Rest, Opts, [{ClaimName, Jwt} | Acc]);
lookup_distributed_claim(
    [
        {ClaimName, #{<<"endpoint">> := Endpoint, <<"access_token">> := AccessToken}}
        | Rest
    ],
    Opts,
    Acc
) ->
    Request =
        {Endpoint, [oidcc_http_util:bearer_auth_header(AccessToken), {"accept", "application/jwt"}]},

    TelemetryOpts = #{
        topic => [oidcc, userinfo_distributed_claim], extra_meta => #{endpoint => Endpoint}
    },
    RequestOpts = maps:get(request_opts, Opts, #{}),

    maybe
        {ok, {{jwt, Jwt}, _}} ?= oidcc_http_util:request(get, Request, TelemetryOpts, RequestOpts),
        lookup_distributed_claim(Rest, Opts, [{ClaimName, Jwt} | Acc])
    else
        {error, Reason} ->
            {error, Reason};
        {ok, {{_Format, _Body}, _Headers}} ->
            {error, invalid_content_type}
    end.

-spec validate_distributed_claim(Claims, ClientContext, Opts, Acc) ->
    {ok, Acc} | {error, error()}
when
    Claims :: [{binary(), #{binary() := binary()}}],
    Opts :: retrieve_opts(),
    ClientContext :: oidcc_client_context:t(),
    Acc :: #{binary() => #{binary() => term()}}.
validate_distributed_claim([], _ClientContext, _Opts, Acc) ->
    {ok, Acc};
validate_distributed_claim([{ClaimName, Token} | Rest], ClientContext, Opts, Acc) ->
    maybe
        {ok, Claims} ?= validate_userinfo_token(Token, ClientContext, Opts),
        validate_distributed_claim(Rest, ClientContext, Opts, maps:put(ClaimName, Claims, Acc))
    end.

combine_claim([], _DistributedClaims, Acc) ->
    {ok, Acc};
combine_claim([{ClaimName, ClaimSource} | Rest], DistributedClaims, Acc) ->
    case DistributedClaims of
        #{ClaimSource := #{ClaimName := ClaimValue}} ->
            combine_claim(Rest, DistributedClaims, maps:put(ClaimName, ClaimValue, Acc));
        #{} ->
            {error, {distributed_claim_not_found, {ClaimSource, ClaimName}}}
    end.
