-module(oidcc_openid_provider_mgr).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).
-export([add_openid_provider/1]).
-export([get_openid_provider/1]).
-export([find_openid_provider/1]).
-export([get_openid_provider_list/0]).



%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).


-record(state, {
          ets_prov = undefined,
          ets_iss = undefined,
          ets_mon = undefined
         }).


%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:cast(?MODULE, stop).

-spec add_openid_provider(Config::map()) ->
    {ok, Id::binary(), pid()} | {error, Reason::atom()}.
add_openid_provider(Config) ->
    Id = maps:get(id, Config, undefined),
    gen_server:call(?MODULE, {add_provider, Id, Config}).


get_openid_provider(Id) ->
    get_provider(Id).

get_openid_provider_list() ->
    get_provider_list().

-spec find_openid_provider(Issuer::binary()) -> {ok, pid()}
                                                | {error, not_found}.
find_openid_provider(Issuer) ->
    find_provider(Issuer).

%% gen_server.

init([]) ->
    ProvEts = ets:new(oidcc_ets_provider, [set, protected, named_table]),
    IssEts = ets:new(oidcc_ets_issuer, [set, protected, named_table]),
    MonEts = ets:new(oidcc_ets_monitor, [set, protected]),
    {ok, #state{ets_prov=ProvEts, ets_iss=IssEts, ets_mon = MonEts}}.

handle_call({add_provider, undefined, Config}, _From, State) ->
    add_provider(Config, State);
handle_call({add_provider, Id, Config}, _From, State) ->
    try_adding_provider(Id, Config, State);
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.


handle_info({'DOWN', MRef, process, _Object, _Info},
            #state{ets_mon=MonEts, ets_prov=ProvEts, ets_iss=IssEts} = State) ->
    case ets:lookup(MonEts, MRef) of
        [{MRef, Id, Issuer}] ->
            true = ets:delete(MRef, MonEts),
            true = ets:delete(Id, ProvEts),
            true = ets:delete(Issuer, IssEts),
            ok;
        _ -> ok
    end,
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

try_adding_provider(Id, Config, State) ->
    case is_unique_id(Id, State) of
        true -> add_provider(Id, Config, State);
        false -> {reply, {error, id_already_used}, State}
    end.

add_provider(Config, State) ->
    Id = get_unique_id(State),
    add_provider(Id, Config, State).

add_provider(Id, Config, State) ->
    {ok, Pid} = start_provider(Id, Config),
    ok = insert_provider(Id, Pid, State),
    {reply, {ok, Id, Pid}, State}.

get_provider_list() ->
    Ets = oidcc_ets_provider,
    true = ets:safe_fixtable(Ets, true),
    Last = ets:first(Ets),
    List = create_provider_list(Last, [], Ets),
    true = ets:safe_fixtable(Ets, false),
    {ok, List}.


get_provider(Id) ->
    case ets:lookup(oidcc_ets_provider, Id) of
        [{Id, _Issuer, Pid, _MRef}] -> {ok, Pid};
        _ -> {error, not_found}
    end.

find_provider(Issuer) ->
    Ets = oidcc_ets_issuer,
    case ets:lookup(Ets, Issuer) of
        [{Issuer, Pid}] ->
            {ok, Pid};
        _ ->
            {error, not_found}
    end.

start_provider(Id, Config) ->
    oidcc_openid_provider_sup:add_openid_provider(Id, Config).

insert_provider(Id, Pid, #state{ets_prov=ProvEts, ets_iss=IssEts,
                                ets_mon=MonEts}) ->
    MRef = monitor(process, Pid),
    {ok, Issuer} = oidcc_openid_provider:get_issuer(Pid),
    true = ets:insert(ProvEts, {Id, Issuer, Pid, MRef}),
    true = ets:insert(IssEts, {Issuer, Pid}),
    true = ets:insert(MonEts, {MRef, Id, Issuer}),
    ok.

create_provider_list('$end_of_table', List, _) ->
    lists:reverse(List);
create_provider_list(Current , List, Ets) ->
    [{Id, _Iss, Pid, _MRef}] = ets:lookup(Ets, Current),
    Next = ets:next(Ets, Current),
    create_provider_list(Next, [{Id, Pid} | List], Ets).



get_unique_id(State) ->
    Id = random_id(),
    case is_unique_id(Id, State) of
        true -> Id;
        false -> get_unique_id(State)
    end.

is_unique_id(Id, #state{ets_prov=Ets}) ->
    case ets:lookup(Ets, Id) of
        [] -> true;
        _ -> false
    end.


random_id() ->
    random_id(5).

random_id(Length) ->
    Random = try crypto:strong_rand_bytes(Length) of
                 Data -> Data
             catch
                 low_entropy ->
                     timer:sleep(100),
                     random_id(Length)
             end,
    base64url:encode(Random).
