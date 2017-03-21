-module(oidcc_client).
-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([stop/0]).
-export([succeeded/2]).
-export([failed/3]).
-export([register/1]).

-export([get_module/1]).

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
          ets_mod = undefined,
          ets_id = undefined
         }).

%% API.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:cast(?MODULE, stop).

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
    Ets = oidcc_ets_client_id,
    case ets:lookup(Ets, Id) of
        [{Id, Mod}] ->
            {ok, Mod};
        _ ->
            [{default, DefMod}] =  ets:lookup(Ets, default),
            {ok, DefMod}
    end.


init(_) ->
    EtsId = ets:new(oidcc_ets_client_id, [set, protected, named_table]),
    EtsMod = ets:new(oidcc_ets_client_mod, [set, protected]),
    {ok, #state{ets_id = EtsId, ets_mod = EtsMod}}.

handle_call({add_module, Module}, _From, State) ->
    {ok, Id} = add_module(Module, State),
    {reply, {ok, Id}, State};
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


add_module(Module, #state{ets_mod = EtsMod, ets_id = EtsId}) ->
    case ets:lookup(EtsMod, Module) of
        [{Module, Id}] ->
            {ok, Id};
        [] ->
            insert_new_module(Module, EtsId, EtsMod)
    end.

insert_new_module(Module, EtsId, EtsMod) ->
    Id = random_string(9),
    case ets:insert_new(EtsId, {Id, Module}) of
        true ->
            true = ets:insert_new(EtsMod, {Module, Id}),
            Default = ets:lookup(EtsId, default),
            set_default_if_needed(Default, Module, EtsId),
            {ok, Id};
        _ ->
            insert_new_module(Module, EtsId, EtsMod)
    end.

set_default_if_needed([], Module, Ets) ->
    true = ets:insert_new(Ets, {default, Module}),
    ok;
set_default_if_needed(_, _Module, _Ets) ->
    ok.


reorder_updates(Updates) ->
    case lists:keyfind(redirect, 1, Updates) of
        false -> {ok, Updates};
        Tuple -> NewUpdates = lists:keydelete(redirect, 1, Updates),
                 OrderedUpdates = NewUpdates ++ [Tuple],
                 {ok, OrderedUpdates}
    end.


random_string(Length) ->
    base64url:encode(crypto:strong_rand_bytes(Length)).
