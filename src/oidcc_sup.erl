-module(oidcc_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
	Procs = [
             openid_provider_supervisor()
            ],
	{ok, {{one_for_one, 1, 5}, Procs}}.


openid_provider_supervisor() ->
    #{ id => op_sup,
       start => {oidcc_openid_provider_sup,start_link,[]},
       type => supervisor
     }.
