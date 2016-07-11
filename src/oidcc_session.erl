-module(oidcc_session).
-behaviour(gen_server).

%% API.
-export([start_link/3]).
-export([start_link/4]).
-export([is_state/2]).
-export([get_id/1]).
-export([get_provider/1]).
-export([get_state/1]).
-export([get_scopes/1]).
-export([get_nonce/1]).
-export([set_provider/2]).
-export([close/1]).


%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          id = undefined,
          provider = undefined,
          nonce = undefined,
          state = undefined,
          scopes = undefined,
          timeout = undefined
         }).

%% API.

start_link(Id, Nonce, State) ->
    Scopes = application:get_env(oidcc, scopes, [openid]),
    start_link(Id, Nonce, State, Scopes).

start_link(Id, Nonce, State, Scopes) ->
    gen_server:start_link(?MODULE, {Id, Nonce, State, Scopes}, []).

-spec close(Pid ::pid()) -> ok.
close(Pid) ->
    gen_server:call(Pid, close).

get_id(Pid) ->
    gen_server:call(Pid, get_id).

get_provider(Pid) ->
    gen_server:call(Pid, get_provider).

get_state(Pid) ->
    gen_server:call(Pid, get_state).

get_scopes(Pid) ->
    gen_server:call(Pid, get_scopes).

get_nonce(Pid) ->
    gen_server:call(Pid, get_nonce).

set_provider(Provider, Pid) ->
    gen_server:call(Pid, {set_provider, Provider}).

is_state(State, Pid) ->
    gen_server:call(Pid, {is_state, State}).
%% gen_server.

init({Id, Nonce, State, Scopes}) ->
    Timeout = application:get_env(oidcc, session_timeout, 300000),
    {ok, #state{id = Id, nonce = Nonce, state = State, scopes = Scopes,
                timeout=Timeout}, Timeout}.

handle_call(get_id, _From, #state{id=Id, timeout=To} = State) ->
    {reply, {ok, Id}, State, To};
handle_call(get_provider, _From, #state{provider=Provider,
                                        timeout=To} = State) ->
    {reply, {ok, Provider}, State, To};
handle_call(get_state, _From, #state{state=OidcState, timeout=To} = State) ->
    {reply, {ok, OidcState}, State, To};
handle_call({is_state, OidcState}, _From, #state{state=OidcState,
                                                 timeout=To} = State) ->
    {reply, true, State, To};
handle_call({is_state, _}, _From, #state{timeout=To} = State) ->
    {reply, false, State, To};
handle_call(get_scopes, _From, #state{scopes=Scopes, timeout=To} = State) ->
    {reply, {ok, Scopes}, State, To};
handle_call(get_nonce, _From, #state{nonce=Nonce, timeout=To} = State) ->
    {reply, {ok, Nonce}, State, To};
handle_call({set_provider, Provider}, _From, #state{timeout=To} = State) ->
    {reply, ok, State#state{provider=Provider}, To};
handle_call(close, _From, #state{id = Id} = State) ->
    ok = oidcc_session_mgr:session_terminating(Id),
    {stop, normal, ok, State};
handle_call(_Request, _From, #state{timeout=To} = State) ->
    {reply, ignored, State, To}.

handle_cast(_Request, #state{timeout = To} = State) ->
    {noreply, State, To}.

handle_info(timeout, #state{id = Id} = State) ->
    ok = oidcc_session_mgr:session_terminating(Id),
    {stop, normal, State};
handle_info(_Info, #state{timeout=To} = State) ->
    {noreply, State, To}.



terminate(normal, _State) ->
    ok;
terminate(_Reason, #state{id = Id}) ->
    oidcc_session_mgr:session_terminating(Id),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

