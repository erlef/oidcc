%%%-------------------------------------------------------------------
%% @doc Functions to start an OpenID Connect Authorization
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_authorization).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-export([create_redirect_url/2]).

-export_type([error/0]).
-export_type([pkce/0]).
-export_type([opts/0]).

-type pkce() :: #{challenge := binary(), method := binary()}.
%% Configure PKCE for authorization
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7636#section-4.3]

-type opts() ::
    #{
        scopes => oidcc_scope:scopes(),
        state => binary(),
        nonce => binary(),
        pkce => pkce() | undefined,
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
%%   <li>`pkce' - pkce arguments to pass to the provider</li>
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
            QueryParams = redirect_params(ClientContext, Opts),
            QueryString = uri_string:compose_query(QueryParams),

            {ok, [AuthEndpoint, <<"?">>, QueryString]};
        false ->
            {error, {grant_type_not_supported, authorization_code}}
    end.

-spec redirect_params(ClientContext, Opts) -> oidcc_http_util:query_params() when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
redirect_params(#oidcc_client_context{client_id = ClientId}, Opts) ->
    QueryParams =
        [
            {<<"response_type">>, maps:get(response_type, Opts, <<"code">>)},
            {<<"client_id">>, ClientId},
            {<<"redirect_uri">>, maps:get(redirect_uri, Opts)}
            | maps:get(url_extension, Opts, [])
        ],
    QueryParams1 = maybe_append(<<"state">>, maps:get(state, Opts, undefined), QueryParams),
    QueryParams2 =
        maybe_append(<<"nonce">>, maps:get(nonce, Opts, undefined), QueryParams1),
    QueryParams3 = append_code_challenge(maps:get(pkce, Opts, undefined), QueryParams2),
    oidcc_scope:query_append_scope(
        maps:get(scopes, Opts, [openid]), QueryParams3
    ).

-spec append_code_challenge(
    Pkce :: pkce() | undefined, QueryParams :: oidcc_http_util:query_params()
) ->
    oidcc_http_util:query_params().
append_code_challenge(#{challenge := Challenge, method := Method}, QueryParams) ->
    [{<<"code_challenge">>, Challenge}, {<<"code_challenge_method">>, Method} | QueryParams];
append_code_challenge(undefined, QueryParams) ->
    QueryParams.

-spec maybe_append(Key, Value, QueryParams) -> QueryParams when
    Key :: unicode:chardata(),
    Value :: unicode:chardata() | true | undefined,
    QueryParams :: oidcc_http_util:query_params().
maybe_append(_Key, undefined, QueryParams) ->
    QueryParams;
maybe_append(Key, Value, QueryParams) ->
    [{Key, Value} | QueryParams].
