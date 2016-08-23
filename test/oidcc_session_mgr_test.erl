-module(oidcc_session_mgr_test).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    {ok, Pid} = oidcc_session_mgr:start_link(),
    ok = oidcc_session_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

basic_session_test() ->
    MeckModules = [oidcc_session_sup, oidcc],
    test_util:meck_new(MeckModules),
    ProviderId = <<"oidcc_provider">>,
    NewSession = fun(Id, Nonce, PId) ->
                         oidcc_session:start_link(Id, Nonce, PId)
                 end,
    meck:expect(oidcc_session_sup, new_session, NewSession),
    meck:expect(oidcc, get_openid_provider_info,
                fun(_) -> {ok, #{request_scopes => undefined}} end),

    {ok, Pid} = oidcc_session_mgr:start_link(),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    {ok, SessPid} = oidcc_session_mgr:new_session(ProviderId),
    
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
    MeckModules = [oidcc, oidcc_session_sup],
    test_util:meck_new(MeckModules),
    NewSession = fun(Id, Nonce, PId) ->
                         oidcc_session:start_link(Id, Nonce, PId)
                 end,
    meck:expect(oidcc_session_sup, new_session, NewSession),
    meck:expect(oidcc, get_openid_provider_info,
                fun(_) -> {ok, #{request_scopes => undefined}} end),

    ProviderId = <<"oidcc_provider">>,

    {ok, Pid} = oidcc_session_mgr:start_link(),
    {ok, []} = oidcc_session_mgr:get_session_list(),
    
    {ok, Sess1} = oidcc_session_mgr:new_session(ProviderId),
    {ok, SessId} = oidcc_session:get_id(Sess1),
    {ok, List1} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(1, length(List1)),
    
    
    {ok, Sess2} = oidcc_session_mgr:get_session(SessId),
    ?assertEqual(Sess1, Sess2),
    {ok, List2} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(List1, List2),
  
    {ok, Sess3} = oidcc_session_mgr:new_session(ProviderId),
    {ok, List3} = oidcc_session_mgr:get_session_list(),
    ?assertEqual(2, length(List3)),
   
    {ok, Sess4} = oidcc_session_mgr:new_session(ProviderId),
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

    

