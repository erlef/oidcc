-module(oidcc_openid_provider_mgr).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).
-export([add_openid_provider/1]).
-export([add_openid_provider/0]).
-export([get_openid_provider/1]).
-export([get_openid_provider_list/0]).



%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).


-record(state, {
          provider = []
         }).


%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:cast(?MODULE, stop).

-spec add_openid_provider() -> {ok, Id::binary(), pid()}.
add_openid_provider() ->
    gen_server:call(?MODULE, add_provider).

-spec add_openid_provider(Id::binary() | undefined) ->
    {ok, Id::binary(), pid()} | {error, Reason::atom()}.
add_openid_provider(undefined) ->
    gen_server:call(?MODULE, add_provider);
add_openid_provider(Id) ->
    gen_server:call(?MODULE, {add_provider, Id}).


get_openid_provider(Id) ->
    gen_server:call(?MODULE, {get_provider, Id}).

get_openid_provider_list() ->
    gen_server:call(?MODULE, get_provider_list).

%% gen_server.

init([]) ->
    {ok, #state{}}.

handle_call(add_provider, _From, State) ->
    add_provider(State);
handle_call({add_provider, Id}, _From, State) ->
    try_adding_provider(Id, State);
handle_call({get_provider, Id}, _From, State) ->
    get_provider(Id, State);
handle_call(get_provider_list, _From, State) ->
    get_provider_list(State);
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

try_adding_provider(Id, State) ->
    case is_unique_id(Id, State) of
        true -> add_provider(Id, State);
        false -> {reply, {error, id_already_used}, State}
    end.

add_provider(State) ->
    Id = get_unique_id(State),
    add_provider(Id, State).

add_provider(Id, State) ->
    {ok, Pid} = start_provider(Id),
    NewState = insert_provider(Id, Pid, State),
    {reply, {ok, Id, Pid}, NewState}.

get_provider_list(#state{provider=Provider}=State) ->
    Filter = fun({Id, Pid, _Mref}, Acc) ->
                     [{Id, Pid} | Acc]
             end,
    List = lists:foldl(Filter, [], Provider),
    {reply, {ok, List}, State}.

get_provider(Id, #state{provider=Provider}=State) ->
    case lists:keyfind(Id, 1, Provider) of
        false -> {reply, {error, not_found}, State};
        {Id, Pid, _MRef} -> {reply, {ok, Pid}, State}
    end.



start_provider(Id) ->
    oidcc_openid_provider_sup:add_openid_provider(Id).

insert_provider(Id, Pid, #state{provider=Provider} = State) ->
    MRef = monitor(process, Pid),
    NewProvider = [{Id, Pid, MRef} | lists:keydelete(Id, 1, Provider)],
    State#state{provider=NewProvider}.


get_unique_id(State) ->
    Id = random_id(),
    case is_unique_id(Id, State) of
        true -> Id;
        false -> get_unique_id(State)
    end.

is_unique_id(Id, #state{provider=Provider}) ->
    case lists:keyfind(Id, 1, Provider) of
        false -> true;
        _ -> false
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
