%%%-------------------------------------------------------------------
%% @doc OAuth Token Introspection
%%
%% See [https://datatracker.ietf.org/doc/html/rfc7662]
%%
%% To use the records, import the definition:
%%
%% ```
%% -include_lib(["oidcc/include/oidcc_token_introspection.hrl"]).
%% '''
%% @end
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

-type opts() :: #{request_opts => oidcc_http_util:request_opts()}.

-type error() :: client_id_mismatch | introspection_not_supported | oidcc_http_util:error().

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
-spec introspect(Token, ClientContext, Opts) ->
    {ok, t()}
    | {error, error()}
when
    Token :: oidcc_token:t() | binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
introspect(#oidcc_token{access = #oidcc_token_access{token = AccessToken}},
                 ClientContext,
                 Opts) ->
    introspect(AccessToken, ClientContext, Opts);
introspect(AccessToken, ClientContext, Opts) ->
    #oidcc_client_context{provider_configuration = Configuration,
                          client_id = ClientId,
                          client_secret = ClientSecret} =
        ClientContext,
    #oidcc_provider_configuration{introspection_endpoint = Endpoint,
                                  issuer = Issuer} = Configuration,

    case Endpoint of
        undefined ->
            {error, introspection_not_supported};
        _ ->
            Header =
                [{"accept", "application/json"},
                oidcc_http_util:basic_auth_header(ClientId, ClientSecret)],
            Body = [{<<"token">>, AccessToken}],
            Request =
                {Endpoint, Header, "application/x-www-form-urlencoded", uri_string:compose_query(Body)},
            RequestOpts = maps:get(request_opts, Opts, #{}),
            TelemetryOpts = #{topic => [oidcc, introspect_token],
                                extra_meta => #{issuer => Issuer, client_id => ClientId}},

            maybe
                {ok, {{json, Token}, _Headers}} ?= oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
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
    Exp = maps:get(<<"exp">>, TokenMap, undefined),
    case maps:get(<<"client_id">>, TokenMap, undefined) of
        IntrospectionClientId when
            IntrospectionClientId == ClientId; IntrospectionClientId == undefined
        ->
            {ok, #oidcc_token_introspection{
                active = Active,
                scope = oidcc_scope:parse(Scope),
                client_id = ClientId,
                username = Username,
                exp = Exp
            }};
        _ ->
            {error, client_id_mismatch}
    end.
