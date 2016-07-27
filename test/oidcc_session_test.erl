-module(oidcc_session_test).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    MeckModules = [oidcc, oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    meck:expect(oidcc, get_openid_provider_info, fun(_) -> {ok, #{}} end),
    Id = 123,
    Nonce = 123,
    ProviderId = <<"oidcc_provider">>,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, ProviderId),
    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.

timeout_test() ->
    MeckModules = [oidcc, oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    meck:expect(oidcc, get_openid_provider_info, fun(_) -> {ok, #{}} end),
    application:set_env(oidcc, session_timeout, 50),
    Id = 123,
    Nonce = 123,
    ProviderId = <<"oidcc_provider">>,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, ProviderId),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.

garbage_test() ->
    MeckModules = [oidcc, oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    meck:expect(oidcc, get_openid_provider_info, fun(_) -> {ok, #{}} end),
    Id = 123,
    Nonce = 123,
    ProviderId = <<"oidcc_provider">>,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, ProviderId),

    ignored = gen_server:call(Pid, garbage),
    ok = gen_server:cast(Pid, garbage),
    Pid ! garbage,

    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
    

get_set_test() ->
    MeckModules = [oidcc, oidcc_session_mgr],
    ok = test_util:meck_new(MeckModules),
    meck:expect(oidcc_session_mgr, session_terminating, fun(_) -> ok end ),
    meck:expect(oidcc, get_openid_provider_info, fun(_) -> {ok, #{}} end),
    Id = id,
    Nonce = nonce,
    Scopes = [openid],
    UserAgent = <<"some agent">>,
    PeerIp = <<"some ip">>,
    ClientMod = <<"id234">>,
    Provider = <<"oidcc_provider">>,
    {ok, Pid} = oidcc_session:start_link(Id, Nonce, Provider),
    ok = oidcc_session:set_user_agent(UserAgent, Pid),
    ok = oidcc_session:set_peer_ip(PeerIp, Pid),
    ok = oidcc_session:set_client_mod(ClientMod, Pid),
    ?assertEqual({ok, Nonce}, oidcc_session:get_nonce(Pid)),
    ?assertEqual({ok, Id}, oidcc_session:get_id(Pid)),
    ?assertEqual({ok, Scopes}, oidcc_session:get_scopes(Pid)),
    ?assertEqual({ok, Provider}, oidcc_session:get_provider(Pid)),
    ?assertEqual({ok, ClientMod}, oidcc_session:get_client_mod(Pid)),
    ?assertEqual(true, oidcc_session:is_user_agent(UserAgent, Pid)),
    ?assertEqual(false, oidcc_session:is_user_agent(PeerIp, Pid)),
    ?assertEqual(true, oidcc_session:is_peer_ip(PeerIp, Pid)),
    ?assertEqual(false, oidcc_session:is_peer_ip(UserAgent, Pid)),
    ok = oidcc_session:close(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = test_util:meck_done(MeckModules),
    ok.
