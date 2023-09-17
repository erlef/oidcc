%%%-------------------------------------------------------------------
%% @doc OIDC Config Provider Worker
%%
%% Loads and continuously refreshes the OIDC configuration and JWKs
%% @end
%% @todo Store configuration in ETS instead of GenServer state to allow
%% concurrent reads
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_provider_configuration_worker).

-feature(maybe_expr, enable).

-behaviour(gen_server).

-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export([get_jwks/1]).
-export([get_provider_configuration/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_continue/2]).
-export([handle_info/2]).
-export([init/1]).
-export([refresh_configuration/1]).
-export([refresh_jwks/1]).
-export([refresh_jwks_for_unknown_kid/2]).
-export([start_link/1]).

-export_type([opts/0]).

%% Configuration Options
%%
%% <ul>
%%   <li>`name' - The gen_server name of the provider.</li>
%%   <li>`issuer' - The issuer URI.</li>
%%   <li>`provider_configuration_opts' - Options for the provider configuration fetching.</li>
%% </ul>
-type opts() :: #{
    name => gen_server:server_name(),
    issuer := uri_string:uri_string(),
    provider_configuration_opts => oidcc_provider_configuration:opts()
}.

-record(state, {
    provider_configuration = undefined :: #oidcc_provider_configuration{} | undefined,
    jwks = undefined :: jose_jwk:key() | undefined,
    issuer :: uri_string:uri_string(),
    provider_configuration_opts :: oidcc_provider_configuration:opts(),
    configuration_refresh_timer :: timer:tref() | undefined,
    jwks_refresh_timer :: timer:tref() | undefined
}).

%% @doc Start Configuration Provider
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>,
%%     name => {local, google_config_provider}
%%   }).
%% '''
%%
%% ```
%% %% ...
%%
%% -behaviour(supervisor).
%%
%% %% ...
%%
%% init(_opts) ->
%%   SupFlags = #{strategy => one_for_one, intensity => 1, period => 5},
%%   ChildSpecs = [#{id => google_config_provider,
%%     start => {oidcc_provider_configuration_worker,
%%               start_link,
%%               [
%%                 #{issuer => <<"https://accounts.google.com">>}
%%               ]},
%%     restart => permanent,
%%     type => worker,
%%     modules => [oidcc_provider_configuration_worker]}],
%%   {ok, {SupFlags, ChildSpecs}}.
%% '''
%% @end
%% @since 3.0.0
-spec start_link(Opts :: opts()) -> gen_server:start_ret().
start_link(Opts) ->
    case maps:get(name, Opts, undefined) of
        undefined ->
            gen_server:start_link(?MODULE, Opts, []);
        Name ->
            gen_server:start_link(Name, ?MODULE, Opts, [])
    end.

%% @private
init(Opts) ->
    maybe
        {ok, Issuer} ?= get_issuer(Opts),
        ProviderConfigurationOpts = maps:get(provider_configuration_opts, Opts, #{}),
        {ok,
         #state{issuer = Issuer, provider_configuration_opts = ProviderConfigurationOpts},
         {continue, load_configuration}}
    end.

%% @private
handle_call(
    get_provider_configuration, _From, #state{provider_configuration = Configuration} = State
) ->
    {reply, Configuration, State};
handle_call(get_jwks, _From, #state{jwks = Jwks} = State) ->
    {reply, Jwks, State}.

%% @private
handle_cast(refresh_configuration, State) ->
    {noreply, State, {continue, load_configuration}};
handle_cast(refresh_jwks, State) ->
    {noreply, State, {continue, load_jwks}};
handle_cast({refresh_jwks_for_unknown_kid, Kid}, #state{jwks = Jwks} = State) ->
    case has_kid(Jwks, Kid) of
        false ->
            {noreply, State, {continue, load_jwks}};
        true ->
            {noreply, State};
        unknown ->
            {noreply, State}
    end.

%% @private
handle_continue(
    load_configuration,
    #state{
        issuer = Issuer,
        provider_configuration_opts = ProviderConfigurationOpts,
        configuration_refresh_timer = OldTimer
    } =
        State
) ->
    maybe_cancel_timer(OldTimer),

    maybe
        {ok, {Configuration, Expiry}} ?=  oidcc_provider_configuration:load_configuration(
            Issuer,
            ProviderConfigurationOpts
        ),
        {ok, NewTimer} = timer:send_after(Expiry, configuration_expired),
        {noreply, State#state{provider_configuration = Configuration, configuration_refresh_timer = NewTimer},
            {continue, load_jwks}}
    else
        {error, Reason} ->
            {stop, {configuration_load_failed, Reason}, State}
    end;
handle_continue(
    load_jwks,
    #state{
        provider_configuration = Configuration,
        provider_configuration_opts = ProviderConfigurationOpts,
        jwks_refresh_timer = OldTimer
    } =
        State
) ->
    #oidcc_provider_configuration{jwks_uri = JwksUri} = Configuration,

    maybe_cancel_timer(OldTimer),

    maybe
        {ok, {Jwks, Expiry}} ?= oidcc_provider_configuration:load_jwks(JwksUri, ProviderConfigurationOpts),
        {ok, NewTimer} = timer:send_after(Expiry, jwks_expired),
        {noreply, State#state{jwks = Jwks, jwks_refresh_timer = NewTimer}}
    else
        {error, Reason} ->
            {stop, {jwks_load_failed, Reason}, State}
    end.

%% @private
handle_info(configuration_expired, State) ->
    {noreply, State#state{configuration_refresh_timer = undefined, jwks_refresh_timer = undefined},
        {continue, load_configuration}};
handle_info(jwks_expired, State) ->
    {noreply, State#state{jwks_refresh_timer = undefined}, {continue, load_jwks}}.

%% @doc Get Configuration
-spec get_provider_configuration(Name :: gen_server:server_ref()) ->
    oidcc_provider_configuration:t().
get_provider_configuration(Name) ->
    gen_server:call(Name, get_provider_configuration).

%% @doc Get Parsed Jwks
-spec get_jwks(Name :: gen_server:server_ref()) -> jose_jwk:key().
get_jwks(Name) ->
    gen_server:call(Name, get_jwks).

%% @doc Refresh Configuration
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% %% Later
%%
%% oidcc_provider_configuration_worker:refresh_configuration(Pid).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_configuration(Name :: gen_server:server_ref()) -> ok.
refresh_configuration(Name) ->
    gen_server:cast(Name, refresh_configuration).

%% @doc Refresh JWKs
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% %% Later
%%
%% oidcc_provider_configuration_worker:refresh_jwks(Pid).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_jwks(Name :: gen_server:server_ref()) -> ok.
refresh_jwks(Name) ->
    gen_server:cast(Name, refresh_jwks).

%% @doc Refresh JWKs if the provided `Kid' is not matching any currently loaded keys
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(Pid, <<"kid">>).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_jwks_for_unknown_kid(Name :: gen_server:server_ref(), Kid :: binary()) ->
    ok.
refresh_jwks_for_unknown_kid(Name, Kid) ->
    gen_server:cast(Name, {refresh_jwks_for_unknown_kid, Kid}).

-spec get_issuer(Opts :: opts()) -> {ok, binary()} | {error, issuer_required}.
get_issuer(Opts) ->
    case maps:get(issuer, Opts, undefined) of
        undefined ->
            {error, issuer_required};
        Issuer when erlang:is_binary(Issuer) ->
            {ok, Issuer}
    end.

%% Checking of existing kid values is a bit wonky because of partial support
%% in jose. see: https://github.com/potatosalad/erlang-jose/issues/28
-spec has_kid(Jwk :: jose_jwk:key(), Kid :: binary()) -> boolean() | unknown.
has_kid(#jose_jwk{fields = #{<<"kid">> := Kid}}, Kid) ->
    true;
has_kid(#jose_jwk{fields = #{<<"kid">> := _}}, _Kid) ->
    false;
has_kid(#jose_jwk{keys = {jose_jwk_set, Keys}}, Kid) ->
    lists:foldl(
        fun
            (_Key, Acc) when is_boolean(Acc) ->
                Acc;
            (Key, unknown) ->
                has_kid(Key, Kid)
        end,
        unknown,
        Keys
    ).

-spec maybe_cancel_timer(Timer :: undefined | timer:tref()) -> ok.
maybe_cancel_timer(undefined) ->
    ok;
maybe_cancel_timer(TRef) ->
    {ok, cancel} = timer:cancel(TRef).
