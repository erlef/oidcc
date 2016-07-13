-module(oidcc_session).
-behaviour(gen_server).

%% API.
-export([start_link/2]).
-export([start_link/3]).
-export([is_user_agent/2]).
-export([is_peer_ip/2]).
-export([get_id/1]).
-export([get_provider/1]).
-export([get_scopes/1]).
-export([get_nonce/1]).
-export([get_client_mod/1]).
-export([set_provider/2]).
-export([set_user_agent/2]).
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
          provider = undefined,
          user_agent = undefined,
          peer_ip = undefined,
          nonce = undefined,
          scopes = undefined,
          timeout = undefined,
          client_mod = undefined
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
    gen_server:call(Pid, {is_user_agent, UserAgent}).

is_peer_ip(PeerIp, Pid) ->
    gen_server:call(Pid, {is_peer_ip, PeerIp}).

get_id(Pid) ->
    gen_server:call(Pid, get_id).

get_provider(Pid) ->
    gen_server:call(Pid, get_provider).

get_scopes(Pid) ->
    gen_server:call(Pid, get_scopes).

get_nonce(Pid) ->
    gen_server:call(Pid, get_nonce).

get_client_mod(Pid) ->
    gen_server:call(Pid, get_client_mod).

set_provider(Provider, Pid) ->
    gen_server:call(Pid, {set_provider, Provider}).

set_user_agent(UserAgent, Pid) ->
    gen_server:call(Pid, {set_user_agent, UserAgent}).

set_peer_ip(PeerIp, Pid) ->
    gen_server:call(Pid, {set_peer_ip, PeerIp }).

set_client_mod(ClientMod, Pid) ->
    gen_server:call(Pid, {set_client_mod, ClientMod }).
%% gen_server.

init({Id, Nonce, Scopes}) ->
    Timeout = application:get_env(oidcc, session_timeout, 300000),
    {ok, #state{id = Id, nonce = Nonce, scopes = Scopes,
                timeout=Timeout}, Timeout}.

handle_call(get_id, _From, #state{id=Id, timeout=To} = State) ->
    {reply, {ok, Id}, State, To};
handle_call(get_provider, _From, #state{provider=Provider,
                                        timeout=To} = State) ->
    {reply, {ok, Provider}, State, To};
handle_call(get_scopes, _From, #state{scopes=Scopes, timeout=To} = State) ->
    {reply, {ok, Scopes}, State, To};
handle_call(get_nonce, _From, #state{nonce=Nonce, timeout=To} = State) ->
    {reply, {ok, Nonce}, State, To};
handle_call(get_client_mod, _From, #state{client_mod=ClientMod,
                                          timeout=To} = State) ->
    {reply, {ok, ClientMod}, State, To};
handle_call({is_user_agent, UserAgentIn}, _From, #state{user_agent = UserAgent,
                                                      timeout=To} = State) ->
    {reply, UserAgentIn == UserAgent, State, To};
handle_call({is_peer_ip, PeerIpIn}, _From, #state{peer_ip = PeerIp,
                                                      timeout=To} = State) ->
    {reply, PeerIpIn == PeerIp, State, To};
handle_call({set_provider, Provider}, _From, #state{timeout=To} = State) ->
    {reply, ok, State#state{provider=Provider}, To};
handle_call({set_user_agent, UserAgent}, _From, #state{timeout=To} = State) ->
    {reply, ok, State#state{user_agent=UserAgent}, To};
handle_call({set_peer_ip, PeerIp}, _From, #state{timeout=To} = State) ->
    {reply, ok, State#state{peer_ip=PeerIp}, To};
handle_call({set_client_mod, ClientMod}, _From, #state{timeout=To} = State) ->
    {reply, ok, State#state{client_mod=ClientMod}, To};
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

