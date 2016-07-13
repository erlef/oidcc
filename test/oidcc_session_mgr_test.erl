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
    NewSession = fun(Id, Nonce) ->
                         oidcc_session:start_link(Id, Nonce)
                 end,
    meck:expect(oidcc_session_sup, new_session, NewSession),

    {ok, Pid} = oidcc_session_mgr:start_link(),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    {ok, SessPid} = oidcc_session_mgr:new_session(),
    
    {ok, List} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(1, length(List)),

    [{SessionId, SessPid}] = List,
    ok = oidcc_session_mgr:session_terminating(SessionId),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.

advanced_session_test() ->
    MeckModules = [oidcc_session_sup],
    test_util:meck_new(MeckModules),
    NewSession = fun(Id, Nonce) ->
                         oidcc_session:start_link(Id, Nonce)
                 end,
    meck:expect(oidcc_session_sup, new_session, NewSession),

    SessionId = <<"123">>,
    {ok, Pid} = oidcc_session_mgr:start_link(),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    {ok, Sess1} = oidcc_session_mgr:get_session(SessionId),
    {ok, List1} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(1, length(List1)),
    
    
    {ok, Sess2} = oidcc_session_mgr:get_session(SessionId),
    ?assertEqual(Sess1, Sess2),
    {ok, List2} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(List1, List2),
  
    {ok, Sess3} = oidcc_session_mgr:get_session(undefined),
    {ok, List3} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(2, length(List3)),
   
    {ok, Sess4} = oidcc_session_mgr:get_session(undefined),
    {ok, List4} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(3, length(List4)),
    
    ok = oidcc_session:close(Sess3),
    ok = test_util:wait_for_process_to_die(Sess3, 100),

    {ok, List5} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(2, length(List5)),

    ok = oidcc_session_mgr:close_all_sessions(),
    {ok, []} = oidcc_session_mgr:get_session_list(),

    
    ok = test_util:wait_for_process_to_die(Sess1, 100),
    ok = test_util:wait_for_process_to_die(Sess4, 100),

    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
    

garbage_test() ->
    {ok, Pid} = oidcc_session_mgr:start_link(),
    ignored = gen_server:call(Pid, garbage), 
    ok = gen_server:cast(Pid, garbage), 
    Pid ! garbage, 
    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

    

