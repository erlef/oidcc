-module(oidcc_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [
             openid_provider_manager(),
             openid_session_manager(),
             openid_client(),
             openid_provider_supervisor(),
             session_supervisor()
            ],
    {ok, {{one_for_one, 1, 5}, Procs}}.


openid_provider_supervisor() ->
    #{ id => op_sup,
       start => {oidcc_openid_provider_sup, start_link, []},
       type => supervisor
     }.

session_supervisor() ->
    #{ id => session_sup,
       start => {oidcc_session_sup, start_link, []},
       type => supervisor
     }.

openid_provider_manager() ->
    #{ id => op_mgr,
       start => {oidcc_openid_provider_mgr, start_link, []},
       type => worker
     }.

openid_session_manager() ->
    #{ id => session_mgr,
       start => {oidcc_session_mgr, start_link, []},
       type => worker
     }.

openid_client() ->
    #{ id => client,
       start => {oidcc_client, start_link, []},
       type => worker
     }.
