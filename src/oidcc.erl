%%%-------------------------------------------------------------------
%% @doc OpenID Connect High Level Interface
%%
%% <h2>Setup</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>,
%%     name => {local, google_config_provider}
%%   }).
%% '''
%%
%% (or via a `supervisor')
%%
%% See {@link oidcc_provider_configuration_worker} for details
%%
%% <h2>Global Configuration</h2>
%%
%% <ul>
%%   <li>`max_clock_skew' (default `0') - Maximum allowed clock skew for JWT
%%     `exp' / `nbf' validation</li>
%% </ul>
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc).

-feature(maybe_expr, enable).

-export([client_credentials_token/4]).
-export([create_redirect_url/4]).
-export([introspect_token/5]).
-export([jwt_profile_token/6]).
-export([refresh_token/5]).
-export([retrieve_token/5]).
-export([retrieve_userinfo/5]).

%% @doc
%% Create Auth Redirect URL
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, RedirectUri} =
%%   oidcc:create_redirect_url(
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>
%%     #{redirect_uri: <<"https://my.server/return"}
%%   ),
%%
%% %% RedirectUri = https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn
%% '''
%% @end
%% @since 3.0.0
-spec create_redirect_url(
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ok, Uri} | {error, oidcc_client_context:error() | oidcc_authorization:error()}
when
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_authorization:opts() | oidcc_client_context:opts(),
    Uri :: uri_string:uri_string().
create_redirect_url(ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),
    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_authorization:create_redirect_url(ClientContext, OtherOpts)
    end.

%% @doc
%% retrieve the token using the authcode received before and directly validate
%% the result.
%%
%% the authcode was sent to the local endpoint by the OpenId Connect provider,
%% using redirects
%%
%% <h2>Examples</h2>
%%
%% ```
%% %% Get AuthCode from Redirect
%%
%% {ok, #oidcc_token{}} =
%%   oidcc:retrieve_token(
%%     AuthCode,
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{redirect_uri => <<"https://example.com/callback">>}
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec retrieve_token(
    AuthCode,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
when
    AuthCode :: binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token:retrieve_opts() | oidcc_client_context:opts().
retrieve_token(
    AuthCode,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_token:retrieve(AuthCode, ClientContext, OptsWithRefresh)
    end.

%% @doc
%% Load userinfo for the given token
%%
%% <h2>Examples</h2>
%%
%% ```
%% %% Get Token
%%
%% {ok, #{<<"sub">> => Sub}} =
%%   oidcc:retrieve_userinfo(
%%     Token,
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{}
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec retrieve_userinfo
    (
        Token,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret,
        Opts
    ) ->
        {ok, map()} | {error, oidcc_client_context:error() | oidcc_userinfo:error()}
    when
        Token :: oidcc_token:t(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_userinfo:retrieve_opts_no_sub() | oidcc_client_context:opts();
    (Token, ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
        {ok, map()} | {error, any()}
    when
        Token :: binary(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_userinfo:retrieve_opts().
retrieve_userinfo(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_userinfo:retrieve(Token, ClientContext, OtherOpts)
    end.

%% @doc Refresh Token
%%
%% <h2>Examples</h2>
%%
%% ```
%% %% Get Token and wait for its expiry
%%
%% {ok, #oidcc_token{}} =
%%   oidcc:refresh_token(
%%     Token,
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{expected_subject => <<"sub_from_initial_id_token>>}
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_token
    (
        RefreshToken,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret,
        Opts
    ) ->
        {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
    when
        RefreshToken :: binary(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_token:refresh_opts() | oidcc_client_context:opts();
    (
        Token,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret,
        Opts
    ) ->
        {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
    when
        Token :: oidcc_token:t(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_token:refresh_opts_no_sub().
refresh_token(
    RefreshToken,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_token:refresh(RefreshToken, ClientContext, OptsWithRefresh)
    end.

%% @doc
%% Introspect the given access token
%%
%% <h2>Examples</h2>
%%
%% ```
%% %% Get AccessToken
%%
%% {ok, #oidcc_token_introspection{active = True}} =
%%   oidcc:introspect_token(
%%     AccessToken,
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{}
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec introspect_token(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ok, oidcc_token_introspection:t()}
    | {error, oidcc_client_context:error() | oidcc_token_introspection:error()}
when
    Token :: oidcc_token:t() | binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token_introspection:opts() | oidcc_client_context:opts().
introspect_token(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_token_introspection:introspect(Token, ClientContext, OtherOpts)
    end.

%% @doc Retrieve JSON Web Token (JWT) Profile Token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7523#section-4]
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, KeyJson} = file:read_file("jwt-profile.json"),
%% KeyMap = jose:decode(KeyJson),
%% Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),
%%
%% {ok, #oidcc_token{}} =
%%   oidcc_token:jwt_profile(
%%     <<"subject">>,
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     Key,
%%     #{
%%      scope => [<<"scope">>],
%%      kid => maps:get(<<"keyId">>, KeyMap)
%%     }
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec jwt_profile_token(
    Subject,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Jwk,
    Opts
) -> {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()} when
    Subject :: binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Jwk :: jose_jwk:key(),
    Opts :: oidcc_token:jwt_profile_opts() | oidcc_client_context:opts().
jwt_profile_token(Subject, ProviderConfigurationWorkerName, ClientId, ClientSecret, Jwk, Opts) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_token:jwt_profile(Subject, ClientContext, Jwk, OptsWithRefresh)
    end.

%% @doc Retrieve Client Credential Token
%%
%% See [https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4]
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, #oidcc_token{}} =
%%   oidcc:client_credentials_token(
%%     provider_name,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{scope => [<<"scope">>]}
%%   ).
%% '''
%% @end
%% @since 3.0.0
-spec client_credentials_token(
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) -> {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()} when
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token:client_credentials_opts() | oidcc_client_context:opts().
client_credentials_token(ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        oidcc_token:client_credentials(ClientContext, OptsWithRefresh)
    end.

-spec maps_put_new(Key, Value, Map1) -> Map2 when
    Key :: term(), Value :: term(), Map1 :: map(), Map2 :: map().
maps_put_new(Key, Value, Map) ->
    case maps:is_key(Key, Map) of
        true -> Map;
        false -> maps:put(Key, Value, Map)
    end.

-spec extract_client_context_opts(Opts) -> {ClientContextOpts, RestOpts} when
    Opts :: RestOpts | ClientContextOpts,
    RestOpts :: map(),
    ClientContextOpts :: oidcc_client_context:opts().
extract_client_context_opts(Opts) ->
    {
        maps:with([client_jwks], Opts),
        maps:without([client_jwks], Opts)
    }.
