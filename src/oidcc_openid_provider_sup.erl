-module(oidcc_openid_provider_sup).
-behaviour(supervisor).

-export([add_openid_provider/1]).
-export([get_openid_provider/1]).
-export([get_openid_provider_list/0]).

-export([start_link/0]).
-export([init/1]).


-spec add_openid_provider(Id :: binary()) -> 
    {ok, pid()} | {error, term()}.
add_openid_provider(Id) ->
    supervisor:start_child(?MODULE, openid_provider_spec(Id)).



get_openid_provider(Id) ->
    {ok, Children} = get_openid_provider_list(),
    Filter = fun({ChildId,Pid}, Acc) ->
                     case ChildId of
                         Id -> Pid;
                         _ -> Acc
                     end
             end,
    case lists:foldl(Filter, not_found, Children) of
        not_found -> {error, not_found};
        undefined -> {error, undefined};
        Pid when is_pid(Pid) -> {ok, Pid}
    end.
    
get_openid_provider_list() ->
    Children = supervisor:which_children(?MODULE),
    MakeTuple = fun({ChildId,Pid,_,_}, Acc) ->
                        [{ChildId,Pid} | Acc]
             end,
    {ok, lists:foldl(MakeTuple, [], Children)}.

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
	Procs = [],
	{ok, {{one_for_one, 1, 5}, Procs}}.


openid_provider_spec(Id) ->
    #{ id => Id,
       start => {oidcc_openid_provider,start_link,[Id]}
     }.
