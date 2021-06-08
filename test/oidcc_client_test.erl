-module(oidcc_client_test).

-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    {ok, Pid} = oidcc_client:start_link(),
    ok = oidcc_client:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

register_test() ->
    {ok, Pid} = oidcc_client:start_link(),
    Module = oidcc_client_one,
    {ok, Id} = oidcc_client:register(Module),
    {ok, Module} = oidcc_client:get_module(Id),
    {ok, Id} = oidcc_client:register(Module),
    ok = oidcc_client:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

default_test() ->
    {ok, Pid} = oidcc_client:start_link(),
    OtherId = <<"123">>,
    {ok, Id1} = oidcc_client:register(oidcc_client_one),
    {ok, Id2} = oidcc_client:register(oidcc_client_two),
    true = OtherId /= Id1,
    true = OtherId /= Id2,
    {ok, oidcc_client_one} = oidcc_client:get_module(OtherId),
    {ok, oidcc_client_one} = oidcc_client:get_module(Id1),
    {ok, oidcc_client_two} = oidcc_client:get_module(Id2),
    ok = oidcc_client:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.

garbage_test() ->
    {ok, Pid} = oidcc_client:start_link(),
    ignored = gen_server:call(Pid, unsupported_glibberish),
    ok = gen_server:cast(Pid, unsupported_glibberish),
    Pid ! some_unsupported_message,
    ok = oidcc_client:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.
