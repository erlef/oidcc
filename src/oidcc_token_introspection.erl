%%%-------------------------------------------------------------------
%% @doc OAuth Token Introspection
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7662]
%%
%% <h2>Records</h2>
%%
%% To use the records, import the definition:
%%
%% ```
%% -include_lib(["oidcc/include/oidcc_token_introspection.hrl"]).
%% '''
%%
%% <h2>Telemetry</h2>
%%
%% See {@link 'Elixir.Oidcc.TokenIntrospection'}
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_token_introspection).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").
-include("oidcc_token_introspection.hrl").

-export([introspect/3]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).

-type t() :: #oidcc_token_introspection{
    active :: boolean(),
    client_id :: binary(),
    exp :: pos_integer(),
    scope :: oidcc_scope:scopes(),
    username :: binary()
}.
%% Introspection Result
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7662#section-2.2]

-type opts() :: #{
    preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
    request_opts => oidcc_http_util:request_opts()
}.

-type error() :: client_id_mismatch | introspection_not_supported | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, load_configuration, start],
    description => <<"Emitted at the start of introspecting the token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, stop],
    description => <<"Emitted at the end of introspecting the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, exception],
    description => <<"Emitted at the end of introspecting the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

%% @doc
%% Introspect the given access token
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:introspect_token/5}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%   oidcc_client_context:from_configuration_worker(provider_name,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>),
%%
%% %% Get AccessToken
%%
%% {ok, #oidcc_token_introspection{active = True}} =
%%   oidcc_token_introspection:introspect(AccessToken, ClientContext, #{}).
%% '''
%% @end
%% @since 3.0.0
-spec introspect(Token, ClientContext, Opts) ->
    {ok, t()}
    | {error, error()}
when
    Token :: oidcc_token:t() | binary(),
    ClientContext :: oidcc_client_context:authenticated_t(),
    Opts :: opts().
introspect(
    #oidcc_token{access = #oidcc_token_access{token = AccessToken}},
    ClientContext,
    Opts
) ->
    introspect(AccessToken, ClientContext, Opts);
introspect(AccessToken, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId,
        client_secret = ClientSecret
    } =
        ClientContext,
    #oidcc_provider_configuration{
        introspection_endpoint = Endpoint,
        issuer = Issuer,
        introspection_endpoint_auth_methods_supported = SupportedAuthMethods,
        introspection_endpoint_auth_signing_alg_values_supported = AllowAlgorithms
    } = Configuration,

    case Endpoint of
        undefined ->
            {error, introspection_not_supported};
        _ ->
            Header0 = [{"accept", "application/json"}],
            Body0 = [{<<"token">>, AccessToken}],

            RequestOpts = maps:get(request_opts, Opts, #{}),
            TelemetryOpts = #{
                topic => [oidcc, introspect_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },

            maybe
                {ok, {Body, Header}} ?=
                    oidcc_auth_util:add_client_authentication(
                        Body0, Header0, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
                    ),
                Request =
                    {Endpoint, Header, "application/x-www-form-urlencoded",
                        uri_string:compose_query(Body)},
                {ok, {{json, Token}, _Headers}} ?=
                    oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
                extract_response(Token, ClientContext)
            end
    end.

-spec extract_response(TokenMap, ClientContext) ->
    {ok, t()} | {error, error()}
when
    TokenMap :: map(),
    ClientContext :: oidcc_client_context:t().
extract_response(TokenMap, #oidcc_client_context{client_id = ClientId}) ->
    Active =
        case maps:get(<<"active">>, TokenMap, undefined) of
            true ->
                true;
            _ ->
                false
        end,
    Scope = maps:get(<<"scope">>, TokenMap, <<"">>),
    Username = maps:get(<<"username">>, TokenMap, undefined),
    TokenType = maps:get(<<"token_type">>, TokenMap, undefined),
    Exp = maps:get(<<"exp">>, TokenMap, undefined),
    Iat = maps:get(<<"iat">>, TokenMap, undefined),
    Nbf = maps:get(<<"nbf">>, TokenMap, undefined),
    Sub = maps:get(<<"sub">>, TokenMap, undefined),
    Aud = maps:get(<<"aud">>, TokenMap, undefined),
    Iss = maps:get(<<"iss">>, TokenMap, undefined),
    Jti = maps:get(<<"jti">>, TokenMap, undefined),
    case maps:get(<<"client_id">>, TokenMap, undefined) of
        IntrospectionClientId when
            IntrospectionClientId == ClientId; IntrospectionClientId == undefined
        ->
            {ok, #oidcc_token_introspection{
                active = Active,
                scope = oidcc_scope:parse(Scope),
                client_id = ClientId,
                username = Username,
                exp = Exp,
                token_type = TokenType,
                iat = Iat,
                nbf = Nbf,
                sub = Sub,
                aud = Aud,
                iss = Iss,
                jti = Jti,
                extra = maps:without(
                    [
                        <<"scope">>,
                        <<"active">>,
                        <<"username">>,
                        <<"exp">>,
                        <<"client_id">>,
                        <<"token_type">>,
                        <<"iat">>,
                        <<"nbf">>,
                        <<"sub">>,
                        <<"aud">>,
                        <<"iss">>,
                        <<"jti">>
                    ],
                    TokenMap
                )
            }};
        _ ->
            {error, client_id_mismatch}
    end.
