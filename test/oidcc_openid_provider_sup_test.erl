-module(oidcc_openid_provider_sup_test).
-include_lib("eunit/include/eunit.hrl").

overall_test() ->
    {ok, _} = oidcc_openid_provider_sup:start_link(),
    {ok, []} = oidcc_openid_provider_sup:get_openid_provider_list(),
    {ok, _Id, _Pid} = oidcc_openid_provider_sup:add_openid_provider(),
    Id = <<"MyCoolId">>,
    {ok, Id, Pid} = oidcc_openid_provider_sup:add_openid_provider(Id),
    {ok, Pid} = oidcc_openid_provider_sup:get_openid_provider(Id),
    {error, not_found} = oidcc_openid_provider_sup:get_openid_provider(<<"123">>),
    {error, id_already_used} = oidcc_openid_provider_sup:add_openid_provider(Id),
    {ok, UndefinedId, _} = oidcc_openid_provider_sup:add_openid_provider(undefined),
    false = (UndefinedId == undefined),
    {ok, List} = oidcc_openid_provider_sup:get_openid_provider_list(),
    3 = length(List),
    ok.
