-module(oidcc_openid_provider_sup).
-behaviour(supervisor).

-export([add_openid_provider/1]).

-export([start_link/0]).
-export([init/1]).

add_openid_provider(Id) ->
    supervisor:start_child(?MODULE, openid_provider_spec(Id)).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [],
    {ok, {{one_for_one, 1, 5}, Procs}}.

openid_provider_spec(Id) ->
    #{ id => Id,
       start => {oidcc_openid_provider, start_link, [Id]}
     }.

