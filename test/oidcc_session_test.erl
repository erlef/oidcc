-module(oidcc_session_test).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    MeckModules = [oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    Id = 123,
    Nonce = 123,
    State = 234,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, State),
    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.

timeout_test() ->
    MeckModules = [oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    application:set_env(oidcc, session_timeout, 50),
    Id = 123,
    Nonce = 123,
    State = 234,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, State),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.

garbage_test() ->
    MeckModules = [oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    Id = 123,
    Nonce = 123,
    State = 234,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, State),

    ignored = gen_server:call(Pid, garbage),
    ok = gen_server:cast(Pid, garbage),
    Pid ! garbage,

    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
    

get_set_test() ->
    MeckModules = [oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    Id = id,
    Nonce = nonce,
    State = state,
    Scopes = [openid],
    Provider = provider,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, State, Scopes),
    ok = oidcc_session:set_provider(Provider, Pid),
    ?assertEqual({ok, Nonce}, oidcc_session:get_nonce(Pid)),
    ?assertEqual({ok, Id}, oidcc_session:get_id(Pid)),
    ?assertEqual({ok, State}, oidcc_session:get_state(Pid)),
    ?assertEqual({ok, Scopes}, oidcc_session:get_scopes(Pid)),
    ?assertEqual({ok, Provider}, oidcc_session:get_provider(Pid)),
    ?assertEqual(true, oidcc_session:is_state(State, Pid)),
    ?assertEqual(false, oidcc_session:is_state(stat, Pid)),
    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
