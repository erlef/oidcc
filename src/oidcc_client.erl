-module(oidcc_client).
-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([succeeded/2]).
-export([failed/3]).
-export([register/1]).

-callback login_succeeded( Token::map()) -> {ok, [term()]}.
-callback login_failed( Reason::atom(), Description::binary() ) ->
    {ok, [term()]}.

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).


-record(state, {
          default = undefined,
          clients = []
         }).

%% API.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

register(Module) when is_atom(Module) ->
    List = Module:module_info(exports),
    true = lists:member({login_succeeded, 1}, List),
    true = lists:member({login_failed, 2}, List),
    gen_server:call(?MODULE, {add_module, Module}).


succeeded(Token, ModuleId) ->
    {ok, Mod} = get_module(ModuleId),
    {ok, Updates} = Mod:login_succeeded(Token),
    reorder_updates(Updates).

failed(Error, Description, ModuleId) ->
    {ok, Mod} = get_module(ModuleId),
    {ok, Updates} = Mod:login_failed(Error, Description),
    reorder_updates(Updates).


get_module(Id) ->
    gen_server:call(?MODULE, {get_module, Id}).

init(_) ->
    {ok, #state{}}.

handle_call({get_module, ModuleId}, _From, State) ->
    {ok, Module} = get_module(ModuleId, State),
    {reply, {ok, Module}, State};
handle_call({add_module, Module}, _From, State) ->
    {ok, Id, NewState} = add_module(Module, State),
    {reply, {ok, Id}, NewState};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

get_module(Id, #state{clients=Clients, default=DefMod}) ->
    case lists:keyfind(Id, 1, Clients) of
        {Id, Mod} ->
            {ok, Mod};
        _ ->
            {ok, DefMod}
    end.

add_module(Module, State) ->
    Id = gen_unique_id(State),
    {ok, NewState} = add_module(Id, Module, State),
    {ok, Id, NewState}.
add_module(Id, Module, #state{default=undefined} = State) ->
    add_module(Id, Module, State#state{default=Module});
add_module(Id, Module, #state{clients = Clients} = State) ->
    NewClients = [{Id, Module} | Clients],
    {ok, State#state{clients = NewClients}}.

gen_unique_id(#state{clients=Clients} = State) ->
    Id = random_string(9),
    case lists:keyfind(Id, 1, Clients) of
        false ->
            Id;
        _ -> gen_unique_id(State)
    end.



reorder_updates(Updates) ->
    case lists:keyfind(redirect, 1, Updates) of
        false -> {ok, Updates};
        Tuple -> NewUpdates = lists:keydelete(redirect, 1, Updates),
                 OrderedUpdates = NewUpdates ++ [Tuple],
                 {ok, OrderedUpdates}
    end.


random_string(Length) ->
    base64url:encode(crypto:strong_rand_bytes(Length)).
