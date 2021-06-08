-module(oidcc_session_sup).

-behaviour(supervisor).

-export([new_session/3]).
-export([new_session/4]).
-export([start_link/0]).
-export([init/1]).

new_session(Id, Nonce, ProviderId) ->
    supervisor:start_child(?MODULE, [Id, Nonce, ProviderId]).

new_session(Id, Nonce, ProviderId, Scopes) ->
    supervisor:start_child(?MODULE, [Id, Nonce, ProviderId, Scopes]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [session()],
    {ok, {{simple_one_for_one, 1, 5}, Procs}}.

session() ->
    #{id => session,
      start => {oidcc_session, start_link, []},
      type => worker,
      restart => transient}.
