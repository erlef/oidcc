-module(oidcc_app).

-export([start/2]).
-export([stop/1]).
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([httpc_profile/0]).

-behaviour(application).
-behaviour(gen_server).

%% @private
httpc_profile() ->
    oidcc.

%% Application Callbacks

%% @private
start(_StartType, StartArgs) ->
    gen_server:start_link(oidcc_app, StartArgs, []).

%% @private
stop(_State) ->
    ok.

%% GenServer Callbacks
%% @private
init(_Args) ->
    try
        inets:start(httpc, [{profile, httpc_profile()}])
    catch
        error:{already_started, _} -> ok
    end,

    % disable keep-alive
    httpc:set_options(
        [
            {pipeline_timeout, 0},
            {keep_alive_timeout, 0},
            {max_sessions, 1}
        ],
        httpc_profile()
    ),

    {ok, [], hibernate}.

handle_call(_Call, _From, State) ->
    {stop, unexpected_call, State}.

handle_cast(_Call, State) ->
    {stop, unexpected_cast, State}.

handle_info(_Call, State) ->
    {stop, unexpected_info, State}.

terminate(_Reason, _State) ->
    inets:stop(httpc, httpc_profile()),
    ok.
