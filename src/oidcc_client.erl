-module(oidcc_client).
-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([stop/0]).
-export([succeeded/2]).
-export([succeeded/3]).
-export([failed/3]).
-export([failed/4]).
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
    SucceededOne = lists:member({login_succeeded, 1}, List),
    SucceededTwo = lists:member({login_succeeded, 2}, List),
    FailedTwo = lists:member({login_failed, 2}, List),
    FailedThree = lists:member({login_failed, 3}, List),
    true = SucceededOne or SucceededTwo,
    true = FailedTwo or FailedThree,
    gen_server:call(?MODULE, {add_module, Module}).


succeeded(Token, ModuleId) ->
    succeeded(Token, ModuleId, #{}).

succeeded(Token, ModuleId, Environment) when is_map(Environment) ->
    {ok, Mod} = get_module(ModuleId),
    {ok, Updates} = call_succeeded(Mod, Token, Environment),
    reorder_updates(Updates).

failed(Error, Description, ModuleId) ->
    failed(Error, Description, ModuleId, #{}).

failed(Error, Description, ModuleId, Environment) when is_map(Environment) ->
    {ok, Mod} = get_module(ModuleId),
    {ok, Updates} = call_failed(Mod, Error, Description, Environment),
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
    InsertResult = ets:insert_new(EtsId, {Id, Module}),
    handle_insert_result(InsertResult, EtsMod, Module, EtsId, Id).

handle_insert_result(true, EtsMod, Module, EtsId, Id) ->
            true = ets:insert_new(EtsMod, {Module, Id}),
            Default = ets:lookup(EtsId, default),
            set_default_if_needed(Default, Module, EtsId),
            {ok, Id};
handle_insert_result(_, EtsMod, Module, EtsId, _Id) ->
            insert_new_module(Module, EtsId, EtsMod).


set_default_if_needed([], Module, Ets) ->
    true = ets:insert_new(Ets, {default, Module}),
    ok;
set_default_if_needed(_, _Module, _Ets) ->
    ok.


reorder_updates(Updates) ->
    append_redirect(lists:keyfind(redirect, 1, Updates), Updates).

append_redirect(false, Updates) ->
    {ok, Updates};
append_redirect(Tuple, Updates) ->
    NewUpdates = lists:keydelete(redirect, 1, Updates),
    OrderedUpdates = NewUpdates ++ [Tuple],
    {ok, OrderedUpdates}.


random_string(Length) ->
    base64url:encode(crypto:strong_rand_bytes(Length)).


call_succeeded(Mod, Token, Environment) ->
    Exports = Mod:module_info(exports),
    SucceededTwo = lists:member({login_succeeded, 2}, Exports),
    call_matching_succeeded(SucceededTwo, Mod, Token, Environment).

call_matching_succeeded(true, Mod, Token, Environment) ->
    Mod:login_succeeded(Token, Environment);
call_matching_succeeded(_, Mod, Token, _) ->
    Mod:login_succeeded(Token).


call_failed(Mod, Error, Description, Environment) ->
    Exports = Mod:module_info(exports),
    FailedThree = lists:member({login_failed, 3}, Exports),
    call_matching_failed(FailedThree, Mod, Error, Description,  Environment).

call_matching_failed(true, Mod, Error, Description, Environment) ->
    Mod:login_failed(Error, Description, Environment);
call_matching_failed(_, Mod, Error, Description, _) ->
    Mod:login_failed(Error, Description).
