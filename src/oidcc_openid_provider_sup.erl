-module(oidcc_openid_provider_sup).
-behaviour(supervisor).

-export([add_openid_provider/2]).

-export([start_link/0]).
-export([init/1]).

add_openid_provider(Id, Config) ->
    supervisor:start_child(?MODULE, openid_provider_spec(Id, Config)).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [],
    {ok, {{one_for_one, 1, 5}, Procs}}.

openid_provider_spec(Id, Config) ->
    #{ id => Id,
       start => {oidcc_openid_provider, start_link, [Id, Config]}
     }.

