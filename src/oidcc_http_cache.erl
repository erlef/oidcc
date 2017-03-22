-module(oidcc_http_cache).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).
-export([cache_http_result/3]).
-export([lookup_http_call/2]).
-export([trigger_cleaning/0]).


%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          ets_cache = undefined,
          ets_time = undefined,
          cache_duration = undefined,
          clean_timeout = undefined,
          last_clean = undefined
         }).

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

cache_http_result(Method, Request, Result) ->
    Key = {Method, Request},
    gen_server:call(?MODULE, {cache_http, Key, Result}).

lookup_http_call(Method, Request) ->
    Key = {Method, Request},
    read_cache(Key).

trigger_cleaning() ->
    gen_server:cast(?MODULE, clean_cache).

%% gen_server.
init(_) ->
    EtsCache = ets:new(oidcc_ets_http_cache, [set, protected, named_table]),
    EtsTime = ets:new(oidcc_ets_http_cache_time, [ordered_set, private]),
    CacheDuration = application:get_env(oidcc, http_cache_duration, none),
    CleanTimeout = application:get_env(oidcc, http_cache_clean, 60),
    Now = erlang:system_time(seconds),
    {ok, #state{ets_cache=EtsCache,
                ets_time = EtsTime,
                cache_duration = CacheDuration,
                clean_timeout = CleanTimeout,
                last_clean = Now
               }}.

handle_call({cache_http, Key, Result}, _From,
            #state{ets_cache = EtsCache, ets_time = EtsTime,
                   cache_duration=CacheDuration} = State) ->
    ok = trigger_cleaning_if_needed(State),
    ok = insert_into_cache(Key, Result, EtsCache, EtsTime, CacheDuration),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.


insert_into_cache(Key, Result, EtsCache, EtsTime, Duration)
  when is_integer(Duration), Duration > 0 ->
    Now = erlang:system_time(seconds),
    Timeout = Now + Duration,
    true = ets:insert(EtsCache, {Key, Timeout, Result}),
    true = ets:insert(EtsTime, {Timeout, Key}),
    ok;
insert_into_cache(_Key, _Result, _EtsCache, _EtsTime, _Duration)  ->
    ok.


handle_cast(clean_cache, #state{ets_cache=EtsCache,
                                ets_time=EtsTime
                               } = State) ->
    Now = erlang:system_time(seconds),
    case ets:first(EtsTime) of
        '$end_of_table' ->
            ok;
        Timeout ->
            delete_entry_if_outdated(Timeout, EtsCache, EtsTime, Now >= Timeout)
    end,
    {noreply, State#state{last_clean=Now}};
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


read_cache(Key) ->
    Now = erlang:system_time(seconds),
    case ets:lookup(oidcc_ets_http_cache, Key) of
        [{Key, Timeout, Result}] ->
            return_if_not_outdated(Result, Timeout > Now);
        [] ->
            {error, not_found}
    end.

trigger_cleaning_if_needed(#state{last_clean=LastClean,
                                  clean_timeout=CleanTimeout}) ->
    Now = erlang:system_time(seconds),
    case (Now - LastClean) >= CleanTimeout of
        true ->
            trigger_cleaning(),
            ok;
        _ ->
            ok
    end.


return_if_not_outdated(Result, true) ->
    {ok, Result};
return_if_not_outdated(_, _) ->
    trigger_cleaning(),
    {error, outdated}.

delete_entry_if_outdated(Timeout, EtsCache, EtsTime, true) ->
    [{Timeout, Key}] = ets:lookup(EtsTime, Timeout),
    true = ets:delete(EtsTime, Timeout),
    true = ets:delete(EtsCache, Key),
    trigger_cleaning(),
    ok;
delete_entry_if_outdated(_Timeout, _EtsCache, _EtsTime, _) ->
    ok.
