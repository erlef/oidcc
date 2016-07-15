-module(oidcc_session).
-behaviour(gen_server).

%% API.
-export([start_link/2]).
-export([start_link/3]).
-export([is_user_agent/2]).
-export([is_cookie_data/2]).
-export([is_peer_ip/2]).
-export([get_id/1]).
-export([get_provider/1]).
-export([get_scopes/1]).
-export([get_nonce/1]).
-export([get_client_mod/1]).
-export([set_provider/2]).
-export([set_user_agent/2]).
-export([set_cookie_data/2]).
-export([set_peer_ip/2]).
-export([set_client_mod/2]).
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
          timeout = undefined,
          data = #{}
         }).

%% API.

start_link(Id, Nonce) ->
    Scopes = application:get_env(oidcc, scopes, [openid]),
    start_link(Id, Nonce, Scopes).

start_link(Id, Nonce, Scopes) ->
    gen_server:start_link(?MODULE, {Id, Nonce, Scopes}, []).

-spec close(Pid ::pid()) -> ok.
close(Pid) ->
    gen_server:cast(Pid, close).

is_user_agent(UserAgent, Pid) ->
    gen_server:call(Pid, {is, user_agent, UserAgent}).

is_cookie_data(CookieData, Pid) ->
    gen_server:call(Pid, {is, cookie_data, CookieData}).

is_peer_ip(PeerIp, Pid) ->
    gen_server:call(Pid, {is, peer_ip, PeerIp}).

get_id(Pid) ->
    gen_server:call(Pid, get_id).

get_provider(Pid) ->
    gen_server:call(Pid, {get, provider}).

get_scopes(Pid) ->
    gen_server:call(Pid, {get, scopes}).

get_nonce(Pid) ->
    gen_server:call(Pid, {get, nonce}).

get_client_mod(Pid) ->
    gen_server:call(Pid, {get, client_mod}).

set_provider(Provider, Pid) ->
    gen_server:call(Pid, {set, provider, Provider}).

set_user_agent(UserAgent, Pid) ->
    gen_server:call(Pid, {set, user_agent, UserAgent}).

set_peer_ip(PeerIp, Pid) ->
    gen_server:call(Pid, {set, peer_ip, PeerIp }).

set_cookie_data(CookieData, Pid) ->
    gen_server:call(Pid, {set, cookie_data, CookieData }).

set_client_mod(ClientMod, Pid) ->
    gen_server:call(Pid, {set, client_mod, ClientMod }).
%% gen_server.

init({Id, Nonce, Scopes}) ->
    Timeout = application:get_env(oidcc, session_timeout, 300000),
    Map = #{nonce => Nonce, scopes => Scopes},
    {ok, #state{id = Id, data = Map, timeout=Timeout}, Timeout}.

handle_call({get, Field}, _From, #state{data=Map, timeout=To} = State) ->
    Value = maps:get(Field, Map, undefined),
    {reply, {ok, Value}, State, To};
handle_call({set, Field, Value}, _From, #state{data=Map, timeout=To} = State) ->
    NewMap = maps:put(Field, Value, Map),
    {reply, ok, State#state{data=NewMap}, To};
handle_call({is, Field, InVal}, _From, #state{data=Map, timeout=To} = State) ->
    Value = maps:get(Field, Map, undefined),
    {reply, InVal == Value, State, To};

handle_call(get_id, _From, #state{id=Id, timeout=To} = State) ->
    {reply, {ok, Id}, State, To};
handle_call(_Request, _From, #state{timeout=To} = State) ->
    {reply, ignored, State, To}.

handle_cast(close, #state{id = Id} = State) ->
    ok = oidcc_session_mgr:session_terminating(Id),
    {stop, normal, State};
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

