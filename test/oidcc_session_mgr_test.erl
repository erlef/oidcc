-module(oidcc_session_mgr_test).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    {ok, Pid} = oidcc_session_mgr:start_link(),
    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

basic_session_test() ->
    MeckModules = [oidcc_session_sup],
    test_util:meck_new(MeckModules),
    SessionPid = self(),
    meck:expect(oidcc_session_sup, new_session, fun(_, _, _) -> {ok, SessionPid} end),

    {ok, Pid} = oidcc_session_mgr:start_link(),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    {ok, Pid2} = oidcc_session_mgr:new_session(),
    ?assertEqual(SessionPid, Pid2),
    
    {ok, List} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(1, length(List)),

    [{SessionId, SessionPid}] = List,
    ok = oidcc_session_mgr:session_terminating(SessionId),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
