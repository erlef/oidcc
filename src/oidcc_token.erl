%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token).

-feature(maybe_expr, enable).

-moduledoc """
Facilitate OpenID Code/Token Exchanges.

## Records

To use the records, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_token.hrl"]).
```

## Telemetry

See [`Oidcc.Token`](`m:'Elixir.Oidcc.Token'`).
""".
-moduledoc #{since => <<"3.0.0">>}.

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").

-include_lib("jose/include/jose_jwe.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-export([client_credentials/2]).
-export([jwt_profile/4]).
-export([refresh/3]).
-export([retrieve/3]).
-export([retrieve_with_refresh/3]).
-export([validate_jarm/3]).
-export([validate_id_token/3]).
-export([validate_jwt/3]).
-export([authorization_headers/4]).
-export([authorization_headers/5]).

-export_type([access/0]).
-export_type([authorization_headers_opts/0]).
-export_type([client_credentials_opts/0]).
-export_type([error/0]).
-export_type([id/0]).
-export_type([jwt_profile_opts/0]).
-export_type([refresh/0]).
-export_type([refresh_opts/0]).
-export_type([refresh_opts_no_sub/0]).
-export_type([refresh_info/0]).
-export_type([retrieve_opts/0]).
-export_type([validate_jarm_opts/0]).
-export_type([validate_jwt_opts/0]).
-export_type([t/0]).

-doc """
ID Token Wrapper.

## Fields

* `token` - The retrieved token.
* `claims` - Unpacked claims of the verified token.
""".
-doc #{since => <<"3.0.0">>}.
-type id() :: #oidcc_token_id{token :: binary(), claims :: oidcc_jwt_util:claims()}.

-doc """
Access Token Wrapper.

## Fields

* `token` - The retrieved token.
* `expires` - Number of seconds the token is valid.
""".
-doc #{since => <<"3.0.0">>}.
-type access() ::
    #oidcc_token_access{token :: binary(), expires :: pos_integer() | undefined, type :: binary()}.

-doc """
Refresh Token Wrapper.

## Fields

* `token` - The retrieved token.
""".
-doc #{since => <<"3.0.0">>}.
-type refresh() :: #oidcc_token_refresh{token :: binary()}.

-doc """
Token Response Wrapper.

## Fields

* `id` - `t:id/0`.
* `access` - `t:access/0`.
* `refresh` - `t:refresh/0`.
* `scope` - `t:oidcc_scope:scopes/0`.
""".
-doc #{since => <<"3.0.0">>}.
-type t() ::
    #oidcc_token{
        id :: oidcc_token:id() | none,
        access :: oidcc_token:access() | none,
        refresh :: oidcc_token:refresh() | none,
        scope :: oidcc_scope:scopes()
    }.

-doc """
Options for retrieving a token.

See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3.

## Fields

* `pkce_verifier` - PKCE verifier (random string previously given to
  `m:oidcc_authorization`), see
  https://datatracker.ietf.org/doc/html/rfc7636#section-4.1.
* `require_pkce` - whether to require PKCE when getting the token.
* `nonce` - Nonce to check.
* `scope` - Scope to store with the token.
* `refresh_jwks` - How to handle tokens with an unknown `kid`.
  See `t:oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun/0`.
* `redirect_uri` - Redirect URI given to `oidcc_authorization:create_redirect_url/2`.
* `dpop_nonce` - if using DPoP, the `nonce` value to use in the proof claim.
* `trusted_audiences` - if present, a list of additional audience values to
  accept. Defaults to `any` which allows any additional values.
* `validate_azp` - if `client_id`, validate that the `azp` claim matches the
  client id. If `any`, skip the validation. Defaults to `client_id`. If a
  binary or a list of binaries is given, validate that the `azp` claim matches
  one of those.
* `token_request_claims` - Additional claims to use with the token request.
""".
-doc #{since => <<"3.0.0">>}.
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
        trusted_audiences => [binary()] | any,
        validate_azp => binary() | [binary()] | client_id | any,
        token_request_claims => #{binary() => binary() | integer()}
    }.

-doc "See `t:refresh_opts_no_sub/0`.".
-doc #{since => <<"3.0.0">>}.
-type refresh_opts_no_sub() ::
    #{
        scope => oidcc_scope:scopes(),
        preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        request_opts => oidcc_http_util:request_opts(),
        url_extension => oidcc_http_util:query_params(),
        body_extension => oidcc_http_util:query_params(),
        dpop_nonce => binary(),
        trusted_audiences => [binary()] | any,
        validate_azp => binary() | [binary()] | client_id | any,
        token_request_claims => #{binary() => binary() | integer()}
    }.

-doc #{since => <<"3.0.0">>}.
-type refresh_opts() ::
    #{
        scope => oidcc_scope:scopes(),
        preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
        expected_subject := binary(),
        request_opts => oidcc_http_util:request_opts(),
        url_extension => oidcc_http_util:query_params(),
        body_extension => oidcc_http_util:query_params(),
        dpop_nonce => binary(),
        trusted_audiences => [binary()] | any,
        validate_azp => binary() | [binary()] | client_id | any,
        token_request_claims => #{binary() => binary() | integer()}
    }.

-doc """
Options for refreshing a token.

See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3.

## Fields

* `scope` - Scope to store with the token.
* `refresh_jwks` - How to handle tokens with an unknown `kid`.
  See `t:oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun/0`.
* `expected_subject` - `sub` of the original token.
""".
-doc #{since => <<"3.2.0">>}.
-type validate_jarm_opts() ::
    #{
        trusted_audiences => [binary()] | any
    }.

-doc #{since => <<"3.0.0">>}.
-type jwt_profile_opts() :: #{
    scope => oidcc_scope:scopes(),
    refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    request_opts => oidcc_http_util:request_opts(),
    kid => binary(),
    url_extension => oidcc_http_util:query_params(),
    body_extension => oidcc_http_util:query_params()
}.

-doc #{since => <<"3.0.0">>}.
-type client_credentials_opts() :: #{
    scope => oidcc_scope:scopes(),
    refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    request_opts => oidcc_http_util:request_opts(),
    url_extension => oidcc_http_util:query_params(),
    body_extension => oidcc_http_util:query_params()
}.

-doc #{since => <<"3.0.0">>}.
-type authorization_headers_opts() :: #{
    dpop_nonce => binary()
}.

-doc #{since => <<"3.2.0">>}.
-type validate_jwt_opts() ::
    #{
        signing_algs => [binary()] | undefined,
        encryption_algs => [binary()] | undefined,
        encryption_encs => [binary()] | undefined,
        trusted_audiences => [binary()] | any,
        refresh_jwks => oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun()
    }.

-doc """
Whatever a `refresh_jwks` function reported alongside the refreshed keys.

`undefined` when no refresh happened, or when the function used the two element
return that carries only the keys. `oidcc` does not interpret it.
""".
-doc #{since => <<"3.9.0">>}.
-type refresh_info() :: term() | undefined.

-doc #{since => <<"3.0.0">>}.
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
    | no_supported_code_challenge
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

-doc """
Retrieve the token using the authcode received before and directly validate
the result.

The authcode was sent to the local endpoint by the OpenId Connect provider,
using redirects.

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:retrieve_token/5`.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get AuthCode from Redirect

{ok, #oidcc_token{}} =
  oidcc:retrieve(AuthCode, ClientContext, #{
    redirect_uri => <<"https://example.com/callback">>}).
```
""".
-doc #{since => <<"3.0.0">>}.
-spec retrieve(AuthCode, ClientContext, Opts) ->
    {ok, t()} | {error, error()}
when
    AuthCode :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
retrieve(AuthCode, ClientContext, Opts) ->
    case retrieve_with_refresh(AuthCode, ClientContext, Opts) of
        {ok, Token, _Info} -> {ok, Token};
        {error, Reason} -> {error, Reason}
    end.

-doc """
Retrieve the token, reporting what a JWKS refresh fetched.

Same as `retrieve/3`, but the third element carries whatever the `refresh_jwks`
function returned alongside the refreshed keys, or `undefined` when no refresh
happened. A function using the two element `{ok, Jwks}` return reports nothing.

`oidcc` refreshes the keys and retries validation without re-sending the
authorization code, which is single use, so this is the only way to learn what
that refresh fetched. Persisting the refreshed key set is the usual reason to
want it.

## Examples

```erlang
RefreshJwks = fun(_OldJwks, _Kid) ->
    {ok, {Jwks, Expiry, Document}} = oidcc_provider_configuration:load_jwks_raw(JwksUri, #{}),
    {ok, Jwks, {Document, Expiry}}
end,

{ok, #oidcc_token{}, {Document, Expiry}} =
    oidcc_token:retrieve_with_refresh(AuthCode, ClientContext, Opts#{refresh_jwks => RefreshJwks}).
```
""".
-doc #{since => <<"3.9.0">>}.
-spec retrieve_with_refresh(AuthCode, ClientContext, Opts) ->
    {ok, t(), refresh_info()} | {error, error()}
when
    AuthCode :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
retrieve_with_refresh(AuthCode, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{issuer = Issuer, grant_types_supported = GrantTypesSupported} =
        Configuration,

    case lists:member(<<"authorization_code">>, GrantTypesSupported) of
        true ->
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
                        QsBody, ClientContext, Opts, TelemetryOpts, true
                    ),
                extract_response(Token, ClientContext, Opts)
            end;
        false ->
            {error, {grant_type_not_supported, authorization_code}}
    end.

-doc """
Validate the JARM response, returning the valid claims as a map.

The response was sent to the local endpoint by the OpenId Connect provider,
using redirects.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get Response from Redirect

{ok, #{<<"code">> := AuthCode}} =
  oidcc:validate_jarm(Response, ClientContext, #{}),

{ok, #oidcc_token{}} = oidcc:retrieve(AuthCode, ClientContext,
  #{redirect_uri => <<"https://redirect.example/">>}).
```
""".
-doc #{since => <<"3.2.0">>}.
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
        jwks = Jwks0
    } = ClientContext,
    #oidcc_provider_configuration{
        issuer = Issuer,
        authorization_signing_alg_values_supported = SigningAlgSupported,
        authorization_encryption_alg_values_supported = EncryptionAlgSupported,
        authorization_encryption_enc_values_supported = EncryptionEncSupported
    } =
        Configuration,

    Jwks1 =
        case ClientJwks of
            none -> Jwks0;
            #jose_jwk{} -> oidcc_jwt_util:merge_jwks(Jwks0, ClientJwks)
        end,

    Jwks2 = oidcc_jwt_util:merge_client_secret_oct_keys(Jwks1, SigningAlgSupported, ClientSecret),
    Jwks = oidcc_jwt_util:merge_client_secret_oct_keys(
        Jwks2, EncryptionAlgSupported, ClientSecret
    ),
    ExpClaims = [{<<"iss">>, Issuer}],
    TrustedAudiences = maps:get(trusted_audiences, Opts, any),
    %% https://openid.net/specs/oauth-v2-jarm-final.html#name-processing-rules
    %% 1. decrypt if necessary
    %% 2. validate <<"iss">> claim
    %% 3. validate <<"aud">> claim
    %% 4. validate <<"exp">> claim
    %% 5. validate signature (valid, not <<"none">> alg)
    %% 6. continue processing
    maybe
        {ok, {#jose_jwt{fields = Claims}, Jws, _Jwk}} ?=
            oidcc_jwt_util:decrypt_and_verify(
                Response, Jwks, SigningAlgSupported, EncryptionAlgSupported, EncryptionEncSupported
            ),
        ok ?= oidcc_jwt_util:verify_claims(Claims, ExpClaims),
        ok ?= verify_aud_claim(Claims, ClientId, TrustedAudiences),
        ok ?= verify_exp_claim(Claims),
        ok ?= verify_nbf_claim(Claims),
        ok ?= oidcc_jwt_util:verify_not_none_alg(Jws),
        {ok, Claims}
    end.

-doc """
Refresh Token

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:refresh_token/5`.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get AuthCode from Redirect

{ok, Token} =
  oidcc_token:retrieve(AuthCode, ClientContext, #{
    redirect_uri => <<"https://example.com/callback">>}).

%% Later

{ok, #oidcc_token{}} =
  oidcc_token:refresh(Token,
                      ClientContext,
                      #{expected_subject => <<"sub_from_initial_id_token">>}).
```
""".
-doc #{since => <<"3.0.0">>}.
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
                    retrieve_a_token(QueryString1, ClientContext, Opts, TelemetryOpts, true),
                {ok, TokenRecord, _Info} ?=
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

-doc """
Retrieve JSON Web Token (JWT) Profile Token

See [https://datatracker.ietf.org/doc/html/rfc7523#section-4]

For a high level interface using {@link oidcc_provider_configuration_worker}
see {@link oidcc:jwt_profile_token/6}.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

{ok, KeyJson} = file:read_file("jwt-profile.json"),
KeyMap = json:decode(KeyJson),
Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),

{ok, #oidcc_token{}} =
  oidcc_token:jwt_profile(<<"subject">>,
                          ClientContext,
                          Key,
                          #{scope => [<<"scope">>],
                            kid => maps:get(<<"keyId">>, KeyMap)}).
```
""".
-doc #{since => <<"3.0.0">>}.
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
                    retrieve_a_token(QueryString1, ClientContext, Opts, TelemetryOpts, false),
                {ok, TokenRecord, _Info} ?=
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

-doc """
Retrieve Client Credential Token

See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:client_credentials_token/4`.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

{ok, #oidcc_token{}} =
  oidcc_token:client_credentials(ClientContext,
                                 #{scope => [<<"scope">>]}).
```
""".
-doc #{since => <<"3.0.0">>}.
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
                    retrieve_a_token(QueryString1, ClientContext, Opts, TelemetryOpts, true),
                {ok, TokenRecord, _Info} ?=
                    extract_response(Token, ClientContext, maps:put(nonce, any, Opts)),
                {ok, TokenRecord}
            end;
        false ->
            {error, {grant_type_not_supported, client_credentials}}
    end.

-spec extract_response(TokenResponseBody, ClientContext, Opts) ->
    {ok, t(), refresh_info()} | {error, error()}
when
    TokenResponseBody :: map(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts().
extract_response(TokenResponseBody, ClientContext, Opts) ->
    maybe
        {ok, Scopes} ?= extract_scope(TokenResponseBody, Opts),
        {ok, AccessExpire} ?= extract_expiry(TokenResponseBody),
        {ok, AccessTokenRecord} ?= extract_access_token(TokenResponseBody, AccessExpire),
        {ok, RefreshTokenRecord} ?= extract_refresh_token(TokenResponseBody),
        {ok, {IdTokenRecord, IdTokenJwk, NoneUsed}, Info} ?=
            extract_id_token(TokenResponseBody, ClientContext, Opts),
        TokenRecord = #oidcc_token{
            id = IdTokenRecord,
            access = AccessTokenRecord,
            refresh = RefreshTokenRecord,
            scope = Scopes
        },
        ok ?= verify_access_token_map_hash(TokenRecord, IdTokenJwk),
        %% If none alg was used, continue with checks to allow the user to decide
        %% if he wants to use the result
        case NoneUsed of
            true ->
                {error, {none_alg_used, TokenRecord}};
            false ->
                {ok, TokenRecord, Info}
        end
    end.

-spec extract_scope(TokenMap, Opts) -> {ok, oidcc_scope:scopes()} | {error, error()} when
    TokenMap :: map(), Opts :: retrieve_opts().
extract_scope(TokenMap, Opts) ->
    Scopes = maps:get(scope, Opts, []),
    case maps:get(<<"scope">>, TokenMap, oidcc_scope:scopes_to_bin(Scopes)) of
        ScopeBinary when is_binary(ScopeBinary) ->
            {ok, oidcc_scope:parse(ScopeBinary)};
        %% Some providers (e.g. Apple and Twitch) are setting the scope value
        %% as list of string. This extends compatibility for those.
        ScopeList when is_list(ScopeList) ->
            {ok, ScopeList};
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
    {ok, {TokenRecord, Jwk, NoneUsed}, refresh_info()} | {error, error()}
when
    TokenMap :: map(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts(),
    TokenRecord :: id() | none,
    Jwk :: jose_jwk:key() | none,
    NoneUsed :: boolean().
extract_id_token(TokenMap, ClientContext, Opts) ->
    case maps:get(<<"id_token">>, TokenMap, none) of
        none ->
            {ok, {none, none, false}, undefined};
        Token when is_binary(Token) ->
            case validate_id_token_with_refresh(Token, ClientContext, Opts) of
                {ok, {OkClaims, Jwk}, Info} ->
                    {ok, {#oidcc_token_id{token = Token, claims = OkClaims}, Jwk, false}, Info};
                {error, {none_alg_used, NoneClaims}} ->
                    {ok, {#oidcc_token_id{token = Token, claims = NoneClaims}, none, true},
                        undefined};
                {error, Reason} ->
                    {error, Reason}
            end;
        Other ->
            {error, {invalid_property, {id_token, Other}}}
    end.

-spec verify_access_token_map_hash(TokenRecord, Jwk) ->
    ok | {error, error()}
when
    TokenRecord :: t(),
    Jwk :: jose_jwk:key() | none.
verify_access_token_map_hash(
    #oidcc_token{
        id =
            #oidcc_token_id{
                token = IdToken,
                claims =
                    #{<<"at_hash">> := ExpectedHash}
            },
        access = #oidcc_token_access{token = AccessToken}
    },
    Jwk
) ->
    maybe
        {ok, Digest} ?= id_token_hash_digest(IdToken, Jwk),
        %% The hash is truncated to its left-most half, the length of which
        %% depends on the digest used. For SHA-256 this is the left-most 128
        %% bits.
        %% See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        Hash = crypto:hash(Digest, AccessToken),
        BinHash = binary:part(Hash, 0, byte_size(Hash) div 2),
        case base64:encode(BinHash, #{mode => urlsafe, padding => false}) of
            ExpectedHash ->
                ok;
            _Other ->
                {error, bad_access_token_hash}
        end
    end;
verify_access_token_map_hash(#oidcc_token{}, _Jwk) ->
    ok.

%% Digest to use for the `at_hash' claim of the given ID token.
%%
%% The digest is derived from the `alg' header of the ID token, which has
%% already been checked against the allowed signing algorithms when the
%% signature was verified.
%%
%% `EdDSA' does not name a digest, so it is derived from the curve of the key
%% the token was signed with.
-spec id_token_hash_digest(IdToken, Jwk) ->
    {ok, crypto:sha2()} | {error, oidcc_jwt_util:error()}
when
    IdToken :: binary(),
    Jwk :: jose_jwk:key() | none.
id_token_hash_digest(_IdToken, none) ->
    %% Encrypted without a nested signature, or the `none' algorithm was used:
    %% there is no signing algorithm to derive a digest from, so an `at_hash'
    %% cannot be verified.
    {error, {unsupported_signing_alg, undefined}};
id_token_hash_digest(IdToken, Jwk) ->
    #jose_jws{alg = {_Module, Alg}} = jose_jwt:peek_protected(IdToken),
    oidcc_jwt_util:signing_alg_to_digest(Alg, Jwk).

-doc """
Validate ID Token

Usually the id token is validated using `retrieve/3`.

If you get the token passed from somewhere else, this function can validate it.

## Validations

* `iss` claim must match the issuer of the provider, or match the regex pattern if `issuer_regex` is configured in quirks.
* `nonce` claim must match the `nonce` option.
* `aud` claim must match the `trusted_audiences` option.
* `exp` claim must be in the future.
* `nbf` claim must be in the past.
* `azp` claim must match the client id by default. This can be disabled by setting the `validate_azp` option to `any`.
  If the `validate_azp` option is set to a `binary()` or a list of binaries, the `azp` claim must match one of those values.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get IdToken from somewhere

{ok, Claims} =
  oidcc:validate_id_token(IdToken, ClientContext, ExpectedNonce).
```

## Regex Issuer Validation

You can use a regex pattern to validate the issuer claim by adding an `issuer_regex`
to the quirks map when creating the provider configuration. See the documentation for `validate_jwt/3`
for more details.
""".
-doc #{since => <<"3.0.0">>}.
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
    case validate_id_token_with_refresh(IdToken, ClientContext, Opts) of
        {ok, {Claims, _Jwk}, _Info} -> {ok, Claims};
        {error, Reason} -> {error, Reason}
    end.

-spec validate_id_token_with_refresh(IdToken, ClientContext, Opts) ->
    {ok, {Claims, jose_jwk:key() | none}, refresh_info()} | {error, error()}
when
    IdToken :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts(),
    Claims :: oidcc_jwt_util:claims().
validate_id_token_with_refresh(IdToken, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } =
        ClientContext,
    #oidcc_provider_configuration{
        id_token_signing_alg_values_supported = AllowAlgorithms,
        id_token_encryption_alg_values_supported = EncryptionAlgs,
        id_token_encryption_enc_values_supported = EncryptionEncs
    } =
        Configuration,

    ValidateOpts = maps:merge(Opts, #{
        signing_algs => AllowAlgorithms,
        encryption_algs => EncryptionAlgs,
        encryption_encs => EncryptionEncs
    }),

    Nonce = maps:get(nonce, Opts, any),

    ExpClaims =
        case Nonce of
            any -> [];
            Bin when is_binary(Bin) -> [{<<"nonce">>, Nonce}]
        end,

    ValidateAzp =
        case maps:get(validate_azp, Opts, client_id) of
            client_id -> [ClientId];
            any -> any;
            Binary when is_binary(Binary) -> [Binary];
            List when is_list(List) -> List
        end,

    validate_jwt_with_refresh(IdToken, ClientContext, ValidateOpts, fun(Claims) ->
        maybe
            ok ?= oidcc_jwt_util:verify_claims(Claims, ExpClaims),
            ok ?= verify_missing_required_claims(Claims),
            ok ?= verify_azp_claim(Claims, ValidateAzp),
            ok
        end
    end).

-doc """
Validate JWT

Validates a generic JWT (such as an access token) from the given provider.
Useful if the issuer is shared between multiple applications, and the access token
generated for a user at one client is used to validate their access at another client.

Validating an arbitrary JWT token (not an ID token) is not covered by the OpenID
Connect specification. Therefore the signing / encryption algorithms are not
derieved from the provider configuration, but must be provided by the caller.

## Validations

* `iss` claim must match the issuer of the provider, or match the regex pattern if `issuer_regex` is configured in quirks.
* `aud` claim must match the `trusted_audiences` option.
* `exp` claim must be in the future.
* `nbf` claim must be in the past.

## Examples

```erlang
{ok, ClientContext} =
    oidcc_client_context:from_configuration_worker(provider_name,
                                                <<"client_id">>,
                                                <<"client_secret">>),
%% Get Jwt from Authorization header
Jwt = <<"jwt">>,

Opts = #{
  signing_algs => [<<"RS256">>]
},

{ok, Claims} =
    oidcc:validate_jwt(Jwt, ClientContext, Opts).
```

## Regex Issuer Validation

You can use a regex pattern to validate the issuer claim by adding an `issuer_regex`
to the quirks map when creating the provider configuration:

```erlang
{ok, {ProviderConfig, _}} =
    oidcc_provider_configuration:load_configuration(Issuer, #{
        quirks => #{
            issuer_regex => <<"^https://accounts\\.example\\.com/[a-z0-9]+">>
        }
    }),
```

This will allow tokens with issuer claims that match the regex pattern to validate successfully.
""".
-doc #{since => <<"3.2.0">>}.
-spec validate_jwt(Token, ClientContext, Opts) ->
    {ok, Claims} | {error, error()}
when
    Token :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: validate_jwt_opts(),
    Claims :: oidcc_jwt_util:claims().
validate_jwt(Token, ClientContext, Opts) when is_map(Opts) ->
    validate_jwt(Token, ClientContext, Opts, fun(_Claims) -> ok end).

-spec validate_jwt(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    {ok, Claims} | {error, error()}
when
    Token :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: validate_jwt_opts(),
    Claims :: oidcc_jwt_util:claims(),
    AdditionalClaimValidation :: fun((Claims) -> ok | {error, error()}).
validate_jwt(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    case validate_jwt_with_refresh(Token, ClientContext, Opts, AdditionalClaimValidation) of
        {ok, {Claims, _Jwk}, _Info} -> {ok, Claims};
        {error, Reason} -> {error, Reason}
    end.

-spec validate_jwt_with_refresh(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    {ok, {Claims, jose_jwk:key() | none}, refresh_info()} | {error, error()}
when
    Token :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: validate_jwt_opts(),
    Claims :: oidcc_jwt_util:claims(),
    AdditionalClaimValidation :: fun((Claims) -> ok | {error, error()}).
validate_jwt_with_refresh(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    RefreshJwksFun = maps:get(refresh_jwks, Opts, undefined),
    unknown_kid_retry(
        fun(RefreshedClientContext) ->
            int_validate_jwt(
                Token, RefreshedClientContext, Opts, AdditionalClaimValidation
            )
        end,
        ClientContext,
        RefreshJwksFun
    ).

-spec int_validate_jwt(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    {ok, {Claims, jose_jwk:key() | none}} | {error, error()}
when
    Token :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: validate_jwt_opts(),
    Claims :: oidcc_jwt_util:claims(),
    AdditionalClaimValidation :: fun((Claims) -> ok | {error, error()}).
int_validate_jwt(Token, ClientContext, Opts, AdditionalClaimValidation) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = #jose_jwk{} = Jwks0,
        client_id = ClientId,
        client_secret = ClientSecret,
        client_jwks = ClientJwks
    } =
        ClientContext,
    #oidcc_provider_configuration{
        issuer = Issuer,
        issuer_regex = IssuerRegex
    } =
        Configuration,

    SigningAlgs = maps:get(signing_algs, Opts, []),
    EncryptionAlgs = maps:get(encryption_algs, Opts, []),
    EncryptionEncs = maps:get(encryption_encs, Opts, []),

    case {SigningAlgs, EncryptionAlgs} of
        {[], []} ->
            error(badarg, [Token, ClientContext, Opts], []);
        _ ->
            ok
    end,

    Jwks1 =
        case ClientJwks of
            none -> Jwks0;
            #jose_jwk{} -> oidcc_jwt_util:merge_jwks(Jwks0, ClientJwks)
        end,
    Jwks2 = oidcc_jwt_util:merge_client_secret_oct_keys(Jwks1, SigningAlgs, ClientSecret),
    Jwks = oidcc_jwt_util:merge_client_secret_oct_keys(Jwks2, EncryptionAlgs, ClientSecret),
    TrustedAudiences = maps:get(trusted_audiences, Opts, any),

    maybe
        {ok, {#jose_jwt{fields = Claims}, Jws, Jwk}} ?=
            rescue_none_validated_jwt(
                oidcc_jwt_util:decrypt_and_verify(
                    Token, Jwks, SigningAlgs, EncryptionAlgs, EncryptionEncs
                )
            ),
        ExpectedClaims =
            case IssuerRegex of
                undefined ->
                    [{<<"iss">>, Issuer}];
                Pattern ->
                    [{<<"iss">>, {regex, Pattern}}]
            end,
        ok ?= oidcc_jwt_util:verify_claims(Claims, ExpectedClaims),
        ok ?= verify_missing_required_claims(Claims),
        ok ?= verify_aud_claim(Claims, ClientId, TrustedAudiences),
        ok ?= verify_exp_claim(Claims),
        ok ?= verify_nbf_claim(Claims),
        ok ?= AdditionalClaimValidation(Claims),
        case Jws of
            #jose_jws{alg = {jose_jws_alg_none, none}} ->
                {error, {none_alg_used, Claims}};
            #jose_jws{} ->
                {ok, {Claims, Jwk}};
            #jose_jwe{} ->
                {ok, {Claims, none}}
        end
    end.

-doc """
Authorization headers

Generate a map of authorization headers to use when using the given
access token to access an API endpoint.

## Examples

```erlang
{ok, ClientContext} =
    oidcc_client_context:from_configuration_worker(provider_name,
                                                    <<"client_id">>,
                                                    <<"client_secret">>),
%% Get Access Token record from somewhere
Headers =
    oidcc:authorization_headers(AccessTokenRecord, :get, Url, ClientContext).
```
""".
-doc #{since => "3.2.0"}.
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
    Opts :: authorization_headers_opts(),
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

-spec verify_aud_claim(Claims, ClientId, TrustedAudiences) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), ClientId :: binary(), TrustedAudiences :: [binary()] | any.
verify_aud_claim(#{<<"aud">> := ClientId}, ClientId, _TrustedAudiences) ->
    ok;
verify_aud_claim(#{<<"aud">> := Audience} = Claims, ClientId, any) when is_list(Audience) ->
    case lists:member(ClientId, Audience) of
        true -> ok;
        false -> {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}
    end;
verify_aud_claim(#{<<"aud">> := Audience} = Claims, ClientId, TrustedAudiences0) when
    is_list(Audience)
->
    TrustedAudiences = [ClientId | TrustedAudiences0],
    maybe
        true ?= lists:member(ClientId, Audience),
        [] ?= [A || A <- Audience, not lists:member(A, TrustedAudiences)],
        ok
    else
        _ -> {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}
    end;
verify_aud_claim(Claims, ClientId, _TrustedAudiences) ->
    {error, {missing_claim, {<<"aud">>, ClientId}, Claims}}.

-spec verify_azp_claim(Claims, Mode) -> ok | {error, error()} when
    Claims :: oidcc_jwt_util:claims(), Mode :: [binary()] | any.
verify_azp_claim(_Claims, any) ->
    ok;
verify_azp_claim(#{<<"azp">> := Azp}, AllowedAzp) when is_list(AllowedAzp) ->
    case lists:member(Azp, AllowedAzp) of
        true -> ok;
        false -> {error, {missing_claim, {<<"azp">>, AllowedAzp}, #{<<"azp">> => Azp}}}
    end;
verify_azp_claim(_, _Mode) ->
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
    QsBodyIn, ClientContext, Opts, TelemetryOpts, AuthenticateClient
) ->
    {ok, map()} | {error, error()}
when
    QsBodyIn :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: retrieve_opts() | refresh_opts(),
    TelemetryOpts :: oidcc_http_util:telemetry_opts(),
    AuthenticateClient :: boolean().
retrieve_a_token(QsBodyIn, ClientContext, Opts, TelemetryOpts, AuthenticateClient) ->
    #oidcc_client_context{provider_configuration = Configuration} =
        ClientContext,
    #oidcc_provider_configuration{
        token_endpoint = TokenEndpoint0,
        token_endpoint_auth_methods_supported = SupportedAuthMethods0,
        token_endpoint_auth_signing_alg_values_supported = SigningAlgs
    } =
        Configuration,

    QueryParams = maps:get(url_extension, Opts, []),

    Header0 = [{"accept", "application/jwt, application/json"}],

    QsBody0 = QsBodyIn ++ maps:get(body_extension, Opts, []),

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
        {ok, QsBody} ?= add_pkce_verifier(QsBody0, Opts, ClientContext),
        {ok, {Body, Header1}, AuthMethod} ?=
            oidcc_auth_util:add_client_authentication(
                QsBody, Header0, SupportedAuthMethods, SigningAlgs, Opts, ClientContext
            ),
        TokenEndpoint = oidcc_auth_util:maybe_mtls_endpoint(
            TokenEndpoint0, AuthMethod, <<"token_endpoint">>, ClientContext
        ),
        Endpoint =
            case QueryParams of
                [] -> TokenEndpoint;
                _ -> [TokenEndpoint, <<"?">>, uri_string:compose_query(QueryParams)]
            end,
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
                ClientContext,
                Opts#{dpop_nonce => NewDpopNonce},
                TelemetryOpts,
                AuthenticateClient
            );
        {error, Reason} ->
            {error, Reason}
    end.

-spec add_pkce_verifier(QueryList, Opts, ClientContext) ->
    {ok, oidcc_http_util:query_params()} | {error, error()}
when
    QueryList :: oidcc_http_util:query_params(),
    Opts :: retrieve_opts() | refresh_opts(),
    ClientContext :: oidcc_client_context:t().
add_pkce_verifier(BodyQs, #{pkce_verifier := PkceVerifier} = Opts, ClientContext) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration} = ClientContext,
    #oidcc_provider_configuration{code_challenge_methods_supported = CodeChallengeMethodsSupported} =
        ProviderConfiguration,
    RequirePkce = maps:get(require_pkce, Opts, false),

    case CodeChallengeMethodsSupported of
        undefined when RequirePkce ->
            {error, no_supported_code_challenge};
        undefined ->
            {ok, BodyQs};
        Methods when is_list(Methods) ->
            case
                lists:member(<<"S256">>, CodeChallengeMethodsSupported) or
                    lists:member(<<"plain">>, CodeChallengeMethodsSupported)
            of
                true ->
                    {ok, [{<<"code_verifier">>, PkceVerifier} | BodyQs]};
                false when RequirePkce ->
                    {error, no_supported_code_challenge};
                false ->
                    {ok, BodyQs}
            end
    end;
add_pkce_verifier(_BodyQs, #{require_pkce := true}, _ClientContext) ->
    {error, pkce_verifier_required};
add_pkce_verifier(BodyQs, _Opts, _ClientContext) ->
    {ok, BodyQs}.

-spec rescue_none_validated_jwt(Result) -> Response when
    Response ::
        {ok, {#jose_jwt{}, #jose_jwe{} | #jose_jws{}, jose_jwk:key() | none}}
        | {error, oidcc_jwt_util:error()},
    Result ::
        {ok, {#jose_jwt{}, #jose_jwe{} | #jose_jws{}, jose_jwk:key() | none}}
        | {error, oidcc_jwt_util:error()}.
rescue_none_validated_jwt({ok, Valid}) ->
    {ok, Valid};
rescue_none_validated_jwt({error, {none_alg_used, Jwt0, Jws0}}) ->
    {ok, {Jwt0, Jws0, none}};
rescue_none_validated_jwt(Other) ->
    Other.

-spec unknown_kid_retry(Function, ClientContext, RefreshJwksFun) ->
    {ok, Result, refresh_info()} | {error, Error}
when
    Function :: fun((ClientContext) -> {ok, Result} | {error, Error}),
    ClientContext :: oidcc_client_context:t(),
    RefreshJwksFun :: undefined | oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    Result :: term(),
    Error :: term().
unknown_kid_retry(Function, ClientContext, RefreshJwksFun) ->
    maybe
        {ok, Result} ?= Function(ClientContext),
        {ok, Result, undefined}
    else
        {error, no_matching_key} when RefreshJwksFun =/= undefined ->
            do_refresh_jwks_and_retry(Function, ClientContext, RefreshJwksFun, undefined);
        {error, {no_matching_key_with_kid, Kid}} when RefreshJwksFun =/= undefined ->
            do_refresh_jwks_and_retry(Function, ClientContext, RefreshJwksFun, Kid);
        {error, Reason} ->
            {error, Reason}
    end.

%% The three element return is what lets a caller learn what the refresh
%% actually fetched. A function that only hands back a key forces anything else,
%% the document and its expiry for instance, out through a side channel.
-spec refresh_jwks(RefreshJwksFun, Jwks, Kid) ->
    {ok, jose_jwk:key(), refresh_info()} | {error, term()}
when
    RefreshJwksFun :: oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    Jwks :: jose_jwk:key(),
    Kid :: binary().
refresh_jwks(RefreshJwksFun, Jwks, Kid) ->
    case RefreshJwksFun(Jwks, Kid) of
        {ok, RefreshedJwks} -> {ok, RefreshedJwks, undefined};
        {ok, RefreshedJwks, Info} -> {ok, RefreshedJwks, Info};
        {error, Reason} -> {error, Reason}
    end.

-spec do_refresh_jwks_and_retry(Function, ClientContext, RefreshJwksFun, Kid) ->
    {ok, Result, refresh_info()} | {error, Error}
when
    Function :: fun((ClientContext) -> {ok, Result} | {error, Error}),
    ClientContext :: oidcc_client_context:t(),
    RefreshJwksFun :: oidcc_jwt_util:refresh_jwks_for_unknown_kid_fun(),
    Kid :: binary(),
    Result :: term(),
    Error :: term().
do_refresh_jwks_and_retry(Function, ClientContext, RefreshJwksFun, Kid) ->
    #oidcc_client_context{jwks = OldJwks} = ClientContext,
    maybe
        {ok, RefreshedJwks, Info} ?= refresh_jwks(RefreshJwksFun, OldJwks, Kid),
        RefreshedClientContext = ClientContext#oidcc_client_context{jwks = RefreshedJwks},
        {ok, Retried} ?= Function(RefreshedClientContext),
        {ok, Retried, Info}
    end.
