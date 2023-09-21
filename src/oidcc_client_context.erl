%%%-------------------------------------------------------------------
%% @doc Client Configuration for authorization, token exchange and
%% userinfo
%%
%% For most projects, it makes sense to use
%% {@link oidcc_provider_configuration_worker} and the high-level
%% interface of {@link oidcc}. In that case direct usage of this
%% module is not needed.
%%
%% To use the record, import the definition:
%%
%% ```
%% -include_lib(["oidcc/include/oidcc_client_context.hrl"]).
%% '''
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_client_context).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).

-export([from_configuration_worker/3]).
-export([from_configuration_worker/4]).
-export([from_manual/4]).
-export([from_manual/5]).

-type t() ::
    #oidcc_client_context{
        provider_configuration :: oidcc_provider_configuration:t(),
        jwks :: jose_jwk:key(),
        client_id :: binary(),
        client_secret :: binary(),
        client_jwks :: jose_jwk:key() | none
    }.

-type opts() :: #{
    client_jwks => jose_jwk:key()
}.

-type error() :: provider_not_ready.

%% @doc Create Client Context from a {@link oidcc_provider_configuration_worker}
%%
%% See {@link from_configuration_worker/4}
%% @end
%% @since 3.0.0
-spec from_configuration_worker(ProviderName, ClientId, ClientSecret) ->
    {ok, t()} | {error, error()}
when
    ProviderName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary().
from_configuration_worker(ProviderName, ClientId, ClientSecret) ->
    from_configuration_worker(ProviderName, ClientId, ClientSecret, #{}).

%% @doc Create Client Context from a {@link oidcc_provider_configuration_worker}
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://login.salesforce.com">>
%%   }),
%%
%% {ok, #oidcc_client_context{}} =
%%   oidcc_client_context:from_configuration_worker(Pid,
%%                                                  <<"client_id">>,
%%                                                  <<"client_secret">>).
%% '''
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://login.salesforce.com">>,
%%     name => {local, salesforce_provider}
%%   }),
%%
%% {ok, #oidcc_client_context{}} =
%%   oidcc_client_context:from_configuration_worker($
%%     salesforce_provider,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{client_jwks => jose_jwk:generate_key(16)}
%% ).
%% '''
%% @end
%% @since 3.0.0
-spec from_configuration_worker(ProviderName, ClientId, ClientSecret, Opts) ->
    {ok, t()} | {error, error()}
when
    ProviderName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: opts().
from_configuration_worker(ProviderName, ClientId, ClientSecret, Opts) when is_pid(ProviderName) ->
    {ok, #oidcc_client_context{
        provider_configuration =
            oidcc_provider_configuration_worker:get_provider_configuration(ProviderName),
        jwks = oidcc_provider_configuration_worker:get_jwks(ProviderName),
        client_id = ClientId,
        client_secret = ClientSecret,
        client_jwks = maps:get(client_jwks, Opts, none)
    }};
from_configuration_worker(ProviderName, ClientId, ClientSecret, Opts) ->
    case erlang:whereis(ProviderName) of
        undefined ->
            {error, provider_not_ready};
        Pid ->
            from_configuration_worker(Pid, ClientId, ClientSecret, Opts)
    end.

%% @doc Create Client Context manually
%%
%% See {@link from_manual/5}
%% @end
%% @since 3.0.0
-spec from_manual(Configuration, Jwks, ClientId, ClientSecret) -> t() when
    Configuration :: oidcc_provider_configuration:t(),
    Jwks :: jose_jwk:key(),
    ClientId :: binary(),
    ClientSecret :: binary().
from_manual(Configuration, Jwks, ClientId, ClientSecret) ->
    from_manual(Configuration, Jwks, ClientId, ClientSecret, #{}).

%% @doc Create Client Context manually
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Configuration} =
%%   oidcc_provider_configuration:load_configuration(<<"https://login.salesforce.com">>,
%%                                              []),
%%
%% #oidcc_provider_configuration{jwks_uri = JwksUri} = Configuration,
%%
%% {ok, Jwks} = oidcc_provider_configuration:load_jwks(JwksUri, []).
%%
%% #oidcc_client_context{} =
%%   oidcc_client_context:from_manual(
%%     Metdata,
%%     Jwks,
%%     <<"client_id">>,
%%     <<"client_secret">>,
%%     #{client_jwks => jose_jwk:generate_key(16)}
%% ).
%% '''
%% @end
%% @since 3.0.0
-spec from_manual(Configuration, Jwks, ClientId, ClientSecret, Opts) -> t() when
    Configuration :: oidcc_provider_configuration:t(),
    Jwks :: jose_jwk:key(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: opts().
from_manual(
    #oidcc_provider_configuration{} = Configuration,
    #jose_jwk{} = Jwks,
    ClientId,
    ClientSecret,
    Opts
) when
    is_binary(ClientId) and is_binary(ClientSecret)
->
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = Jwks,
        client_id = ClientId,
        client_secret = ClientSecret,
        client_jwks = maps:get(client_jwks, Opts, none)
    }.
