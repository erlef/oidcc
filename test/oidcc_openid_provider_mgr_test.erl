-module(oidcc_openid_provider_mgr_test).
-include_lib("eunit/include/eunit.hrl").

start_stop_test() ->
    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.


simple_add_test() ->
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               issuer_or_endpoint => <<"well.known">>,
               local_endpoint => <<"/here">>
              },
    ok = meck(),

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    {ok, Id, MyPid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    {ok, [{Id, MyPid}]} = oidcc_openid_provider_mgr:get_openid_provider_list(),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok = stop_meck(),
    ok.


id_add_test() ->
    Id = <<"123">>,
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               issuer_or_endpoint => <<"well.known">>,
               local_endpoint => <<"/here">>,
               id => Id
              },
    ok = meck(),

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    {ok, Id, MyPid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    {ok, [{Id, MyPid}]} = oidcc_openid_provider_mgr:get_openid_provider_list(),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    ok = stop_meck(),
    ok.


double_add_test() ->
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               issuer_or_endpoint => <<"well.known">>,
               local_endpoint => <<"/here">>
              },
    MyPid = self(),

    ok = meck(),

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    {ok, Id, MyPid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    NewConfig = maps:put(id, Id, Config),
    {error, id_already_used} =
        oidcc_openid_provider_mgr:add_openid_provider(NewConfig),
    {ok, _Id, MyPid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    ok = stop_meck(),
    ok.

multiple_add_test() ->
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               issuer_or_endpoint => <<"well.known">>,
               local_endpoint => <<"/here">>
              },
    NumberToAdd = 1000,
    ok = meck(),

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    ok = add_provider(NumberToAdd, Config),
    {ok, List} = oidcc_openid_provider_mgr:get_openid_provider_list(),
    NumberToAdd = length(List),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    ok = stop_meck(),
    ok.

add_provider(0, _) ->
    ok;
add_provider(Num, Config) ->
    {ok, _Id, _Pid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    add_provider(Num-1, Config).



lookup_test() ->
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               issuer_or_endpoint => <<"well.known">>,
               local_endpoint => <<"/here">>
              },
    ok = meck(),

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    {ok, Id, MyPid} = oidcc_openid_provider_mgr:add_openid_provider(Config),
    {ok, MyPid} = oidcc_openid_provider_mgr:get_openid_provider(Id),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    ok = stop_meck(),
    ok.


bad_lookup_test() ->
    ok = meck(),
    Id = <<"some random Id">>,

    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    {error, not_found} = oidcc_openid_provider_mgr:get_openid_provider(Id),
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    ok = stop_meck(),
    ok.


garbage_test() ->
    {ok, Pid} = oidcc_openid_provider_mgr:start_link(),
    ignored = gen_server:call(Pid,unsupported_glibberish),
    ok = gen_server:cast(Pid,unsupported_glibberish),
    Pid ! some_unsupported_message,
    ok = oidcc_openid_provider_mgr:stop(),
    ok = test_util:wait_for_process_to_die(Pid, 100),
    ok.


meck() ->
    MyPid = self(),
    AddFun = fun(_Id, _Config) ->
                     {ok, MyPid}
             end,
    ok = meck:new(oidcc_openid_provider_sup),
    ok = meck:expect(oidcc_openid_provider_sup, add_openid_provider, AddFun),
    ok.

stop_meck() ->
    true = meck:validate(oidcc_openid_provider_sup),
    ok = meck:unload(oidcc_openid_provider_sup),
    ok.
