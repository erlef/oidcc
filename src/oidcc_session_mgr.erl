-module(oidcc_session_mgr).
%%
%% Copyright 2016 SCC/KIT
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0 (see also the LICENSE file)
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
-author("Bas Wegh, Bas.Wegh<at>kit.edu").

-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).

-export([new_session/0]).
-export([get_session/1]).
-export([close_all_sessions/0]).
-export([get_session_list/0]).
-export([session_terminating/1]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          sessions = []
         }).

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

-spec new_session() -> {ok, pid()}.
new_session() ->
    gen_server:call(?MODULE, new_session).

-spec get_session(ID :: uuid:uuid() | undefined) -> {ok, pid()}.
get_session(undefined) ->
    new_session();
get_session(ID) ->
    gen_server:call(?MODULE, {get_or_create_session, ID}).

-spec session_terminating(ID :: binary()) -> ok.
session_terminating(ID) ->
    gen_server:call(?MODULE, {delete_session, ID}).

-spec close_all_sessions() -> ok.
close_all_sessions() ->
    gen_server:call(?MODULE, close_all_sessions).

-spec get_session_list() -> {ok, Sessions::list()}.
get_session_list() ->
    gen_server:call(?MODULE, get_session_list).


%% gen_server.

init([]) ->
    {ok, #state{}}.

handle_call(new_session, _From, State) ->
    {ok, Pid, NewState} = create_new_session(State),
    {reply, {ok, Pid}, NewState};
handle_call({get_or_create_session, Id}, _From, State) ->
    {ok, Pid, NewState} = lookup_or_create_session(Id, State),
    {reply, {ok, Pid}, NewState};
handle_call({delete_session, ID}, _From, State) ->
    {ok, NewState} = delete_session(ID, State),
    {reply, ok, NewState};
handle_call(close_all_sessions, _From, State) ->
    {ok, NewState} = delete_sessions(State),
    {reply, ok, NewState};
handle_call(get_session_list, _From, State) ->
    SessionList = session_list(State),
    {reply, {ok, SessionList}, State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(stop, State) ->
    {ok, NewState} = delete_sessions(State),
    {stop, normal, NewState};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


delete_sessions(#state{sessions = Sessions} = State) ->
    {ok, NewState} = delete_sessions(Sessions, State),
    {ok, NewState}.

delete_sessions([], State) ->
    {ok, State#state{sessions = []}};
delete_sessions([{_Id, Pid}|T], State) ->
    oidcc_session:close(Pid),
    delete_sessions(T, State).

set_session_for_id(ID, Pid, #state{sessions = Sessions} = State) ->
    {ok, State#state{sessions = [ {ID, Pid} | Sessions]}}.

delete_session(Id, #state{sessions = Sessions} = State) ->
    NewSessions = lists:keydelete(Id, 1, Sessions),
    {ok, State#state{sessions = NewSessions}}.

get_unique_id(#state{sessions = List}) ->
    get_unique_id(List);
get_unique_id(List) ->
    ID = random_string(64),
    repeat_id_gen_if_needed(ID, lists:keyfind(ID, 1, List), List).

start_session(Id) ->
    Nonce = random_string(128),
    State = random_string(64),
    {ok, Pid} = oidcc_session_sup:new_session(Id, Nonce, State),
    Pid.

repeat_id_gen_if_needed(ID, false, _) ->
    ID;
repeat_id_gen_if_needed(_, _, List) ->
    get_unique_id(List).

lookup_session(Id, #state{sessions=Sessions}) ->
    case lists:keyfind(Id, 1, Sessions) of
        {Id, Pid} ->
            {ok, Pid};
        _ ->
            {error, not_found}
    end.

session_list(#state{sessions=Sessions}) ->
    Sessions.

create_new_session(State) ->
    ID = get_unique_id(State),
    Pid = start_session(ID),
    {ok, NewState} = set_session_for_id(ID, Pid, State),
    {ok, Pid, NewState}.

lookup_or_create_session({ok, Pid}, State) ->
    {ok, Pid, State};
lookup_or_create_session({error, _}, State) ->
    create_new_session(State);
lookup_or_create_session(ID, State) ->
    lookup_or_create_session(lookup_session(ID, State), State).

random_string(Length) ->
    base64url:encode(crypto:strong_rand_bytes(Length)).
