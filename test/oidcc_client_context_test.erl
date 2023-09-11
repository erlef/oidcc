-module(oidcc_client_context_test).

-include_lib("eunit/include/eunit.hrl").

provider_not_running_test() ->
    ?assertMatch(
        {error, provider_not_ready},
        oidcc_client_context:from_configuration_worker(
            invalid,
            <<"client_id">>,
            <<"client_secret">>
        )
    ),
    ok.
