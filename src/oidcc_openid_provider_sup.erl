-module(oidcc_openid_provider_sup).
-behaviour(supervisor).

-export([add_openid_provider/1]).
-export([add_openid_provider/0]).
-export([get_openid_provider/1]).
-export([get_openid_provider_list/0]).

-export([start_link/0]).
-export([init/1]).


-spec add_openid_provider() -> {ok, pid()}.
add_openid_provider() ->
    Id = get_unique_id(), 
    supervisor:start_child(?MODULE, openid_provider_spec(Id)).

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

get_unique_id() ->
    List = gen_supervisor:which_children(?MODULE),
    Id = random_id(),
    case lists:keyfind(Id,1,List) of
        true -> Id;
        false -> get_unique_id()
    end.


random_id() ->
    random_id(5).

random_id(Length) ->
    Random = try crypto:strong_rand_bytes(Length) of
                 Data -> Data
             catch
                 low_entropy ->
                     crypto:rand_bytes(Length)
             end,
    base64url:encode(Random).
