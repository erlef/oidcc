-module(oidcc_http_cache_test).

-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    {ok, Pid} = oidcc_http_cache:start_link(),
    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

insert_lookup_unconf_test() ->
    {ok, Pid} = oidcc_http_cache:start_link(),
    %% default behaviour of unconfigured
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

insert_lookup_conf_test() ->
    application:set_env(oidcc, http_cache_duration, 30),
    {ok, Pid} = oidcc_http_cache:start_link(),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    ok = oidcc_http_cache:stop(),
    application:unset_env(oidcc, http_cache_duration),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

enqueue_test() ->
    application:set_env(oidcc, http_cache_duration, 30),
    {ok, Pid} = oidcc_http_cache:start_link(),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual(true, oidcc_http_cache:enqueue_http_call(a, b)),
    ?assertEqual(false, oidcc_http_cache:enqueue_http_call(a, b)),
    ?assertEqual({ok, pending}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual(false, oidcc_http_cache:enqueue_http_call(a, b)),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    ok = oidcc_http_cache:stop(),
    application:unset_env(oidcc, http_cache_duration),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

clean_test() ->
    application:unset_env(oidcc, http_cache_clean),
    application:set_env(oidcc, http_cache_duration, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    io:format("ets: ~p~n", [ets:match(oidcc_ets_http_cache, {'$1', '$2', '$3'})]),
    oidcc_http_cache:trigger_cleaning(),
    timer:sleep(200),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    io:format("ets: ~p~n", [ets:match(oidcc_ets_http_cache, {'$1', '$2', '$3'})]),
    timer:sleep(2000),
    io:format("ets: ~p~n", [ets:match(oidcc_ets_http_cache, {'$1', '$2', '$3'})]),
    ?assertEqual({error, outdated}, oidcc_http_cache:lookup_http_call(a, b)),
    wait_for_cache(0),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ok = oidcc_http_cache:stop(),
    application:unset_env(oidcc, http_cache_duration),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

auto_clean_test() ->
    application:set_env(oidcc, http_cache_duration, 1),
    application:set_env(oidcc, http_cache_clean, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    timer:sleep(1000),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    timer:sleep(1000),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(b, c, d)),
    ?assertEqual({ok, d}, oidcc_http_cache:lookup_http_call(b, c)),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ok = oidcc_http_cache:stop(),
    application:unset_env(oidcc, http_cache_duration),
    application:unset_env(oidcc, http_cache_clean),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

multiple_entries_test() ->
    application:unset_env(oidcc, http_cache_clean),
    application:set_env(oidcc, http_cache_duration, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    io:format("ets: ~p~n", [ets:match(oidcc_ets_http_cache, {'$1', '$2', '$3'})]),
    oidcc_http_cache:trigger_cleaning(),
    timer:sleep(100),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    application:set_env(oidcc, http_cache_duration, 5),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(b, c, d)),
    ?assertEqual({ok, d}, oidcc_http_cache:lookup_http_call(b, c)),
    io:format("ets: ~p~n", [ets:match(oidcc_ets_http_cache, {'$1', '$2', '$3'})]),
    WaitForOutdated =
        fun() ->
           Result = oidcc_http_cache:lookup_http_call(a, b),
           Result == {error, outdated}
        end,
    ok = test_util:wait_for_true(WaitForOutdated, 200),
    ?assertEqual({ok, d}, oidcc_http_cache:lookup_http_call(b, c)),
    wait_for_cache(1),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual({ok, d}, oidcc_http_cache:lookup_http_call(b, c)),
    application:unset_env(oidcc, http_cache_duration),
    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

garbage_test() ->
    {ok, Pid} = oidcc_http_cache:start_link(),
    ignored = gen_server:call(Pid, unsupported_glibberish),
    ok = gen_server:cast(Pid, unsupported_glibberish),
    Pid ! some_unsupported_message,
    ok = oidcc_http_cache:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

wait_for_cache(Size) ->
    case ets:info(oidcc_ets_http_cache, size) of
        Size ->
            ok;
        _ ->
            timer:sleep(10),
            wait_for_cache(Size)
    end.
