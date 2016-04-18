-module(oidcc_openid_provider_test).
-include_lib("eunit/include/eunit.hrl").


start_stop_test() ->
    Id = <<"some id">>,
    {ok, Pid} = oidcc_openid_provider:start_link(Id),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).
