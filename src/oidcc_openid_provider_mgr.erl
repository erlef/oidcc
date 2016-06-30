-module(oidcc_openid_provider_mgr).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).
-export([add_openid_provider/2]).
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
          provider = []
         }).


%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:cast(?MODULE, stop).

-spec add_openid_provider(Config::map()) -> {ok, Id::binary(), pid()}.
add_openid_provider(Config) ->
    add_openid_provider(undefined, Config).

-spec add_openid_provider(Id::binary() | undefined, Config::map()) ->
    {ok, Id::binary(), pid()} | {error, Reason::atom()}.
add_openid_provider(Id, Config) ->
    gen_server:call(?MODULE, {add_provider, Id, Config}).


get_openid_provider(Id) ->
    gen_server:call(?MODULE, {get_provider, Id}).

get_openid_provider_list() ->
    gen_server:call(?MODULE, get_provider_list).

-spec find_openid_provider(Issuer::binary()) -> {ok, pid()}
                                                | {error, not_found}.
find_openid_provider(Issuer) ->
    gen_server:call(?MODULE, {find_provider, Issuer}).

%% gen_server.

init([]) ->
    {ok, #state{}}.

handle_call({add_provider, undefined, Config}, _From, State) ->
    add_provider(Config, State);
handle_call({add_provider, Id, Config}, _From, State) ->
    try_adding_provider(Id, Config, State);
handle_call({get_provider, Id}, _From, State) ->
    get_provider(Id, State);
handle_call(get_provider_list, _From, State) ->
    get_provider_list(State);
handle_call({find_provider, Issuer}, _From, State) ->
    find_provider(Issuer, State);
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.


handle_info({'DOWN', MRef, process, _Object, _Info},
            #state{provider=Provider} = State) ->
    NewProvider = lists:keydelete(MRef, 3, Provider),
    {noreply, State#state{provider = NewProvider}};
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

find_provider(Issuer, #state{provider=Provider}=State) ->
    Filter = fun({_Id, Pid, _Mref}, List) ->
                     case oidcc_openid_provider:is_issuer(Issuer, Pid) of
                         true -> [ Pid | List];
                         _ -> List
                     end
             end,
    case lists:foldl(Filter, [], Provider) of
        [Pid | _ ] -> {reply, {ok, Pid}, State};
        [] -> {reply, {error, not_found}, State}
    end.

start_provider(Id, Config) ->
    oidcc_openid_provider_sup:add_openid_provider(Id, Config).

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
                     timer:sleep(100),
                     random_id(Length)
             end,
    base64url:encode(Random).
