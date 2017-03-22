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
    application:unset_env(oidcc, http_cache_duration),

    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),

    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

clean_test() ->
    application:set_env(oidcc, http_cache_duration, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:unset_env(oidcc, http_cache_duration),

    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    oidcc_http_cache:trigger_cleaning(),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),

    timer:sleep(1000),
    ?assertEqual({error, outdated}, oidcc_http_cache:lookup_http_call(a, b)),
    oidcc_http_cache:trigger_cleaning(),
    wait_for_cache(),
    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),

    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

auto_clean_test() ->
    application:set_env(oidcc, http_cache_duration, 1),
    application:set_env(oidcc, http_cache_clean, 1),
    {ok, Pid} = oidcc_http_cache:start_link(),
    application:unset_env(oidcc, http_cache_duration),
    application:unset_env(oidcc, http_cache_clean),


    ?assertEqual(ok, oidcc_http_cache:cache_http_result(a, b, c)),
    ?assertEqual({ok, c}, oidcc_http_cache:lookup_http_call(a, b)),
    timer:sleep(1000),
    ?assertEqual(ok, oidcc_http_cache:cache_http_result(b, c, d)),
    ?assertEqual({ok, d}, oidcc_http_cache:lookup_http_call(b, c)),

    ?assertEqual({error, not_found}, oidcc_http_cache:lookup_http_call(a, b)),

    ok = oidcc_http_cache:stop(),
    test_util:wait_for_process_to_die(Pid, 100),
    ok.

garbage_test() ->
    {ok, Pid} = oidcc_http_cache:start_link(),
    ignored = gen_server:call(Pid,unsupported_glibberish),
    ok = gen_server:cast(Pid,unsupported_glibberish),
    Pid ! some_unsupported_message,
    ok = oidcc_http_cache:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

wait_for_cache() ->
    case ets:info(oidcc_ets_http_cache, size) of
        0 ->
            ok;
        _ ->
            timer:sleep(10),
            wait_for_cache()
    end.
