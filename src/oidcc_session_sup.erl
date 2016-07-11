-module(oidcc_session_sup).
-behaviour(supervisor).

-export([new_session/3]).

-export([start_link/0]).
-export([init/1]).

new_session(Id, Nonce, State) ->
    supervisor:start_child(?MODULE, [Id, Nonce, State]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [
             session()
            ],
    {ok, {{simple_one_for_one, 1, 5}, Procs}}.

session() ->
    #{ id => session,
       start => {oidcc_session, start_link, []},
       type => worker,
       restart => transient
     }.
