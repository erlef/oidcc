-module(oidcc_provider_configuration_worker_test).

-include_lib("eunit/include/eunit.hrl").

does_not_start_without_issuer_test() ->
    ?assertMatch(
        {error, issuer_required},
        oidcc_provider_configuration_worker:start_link(#{})
    ).
