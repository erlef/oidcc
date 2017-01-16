-module(oidc_SUITE).
-include_lib("common_test/include/ct.hrl").

-export([all/0,
         %% groups/0,
         %% group/1,
         %% suite/0,
         init_per_suite/1,
         end_per_suite/1,
         %% init_per_group/2,
         %% end_per_group/2,
         %% init_per_testcase/2,
         %% end_per_testcase/2,

         retrieve_google/1,
         retrieve_iam/1,
         retrieve_hbp/1,
         retrieve_egi/1,
         retrieve_eudat/1
        ]).

all() ->
    [
     retrieve_google,
     retrieve_eudat,
     retrieve_iam,
     retrieve_hbp,
     retrieve_egi
    ].

%% groups() ->
%%     [].
%%
%% group(_) ->
%%     [].
%%
%% suite() ->
%%     [].

init_per_suite(Conf) ->
    {ok, _} = application:ensure_all_started(oidcc),
    Conf.

end_per_suite(Conf) ->
    ok = application:stop(oidcc),
    Conf.

%% init_per_group(_Group, Conf) ->
%%     Conf.
%%
%% end_per_group(_Group, Conf) ->
%%     Conf.
%%
%% init_per_testcase(_TestCase, Conf) ->
%%      Conf.
%%
%% end_per_testcase(_TestCase, Conf) ->
%%     Conf.


retrieve_google(_Conf) ->
    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    retrieve_configuration(ConfigEndpoint).

retrieve_iam(_Conf) ->
    ConfigEndpoint = <<"https://iam-test.indigo-datacloud.eu/.well-known/openid-configuration">>,
    retrieve_configuration(ConfigEndpoint).

retrieve_hbp(_Conf) ->
    ConfigEndpoint = <<"https://services.humanbrainproject.eu/oidc/.well-known/openid-configuration">>,
    retrieve_configuration(ConfigEndpoint).

retrieve_egi(_Conf) ->
    ConfigEndpoint = <<"https://aai-dev.egi.eu/oidc/.well-known/openid-configuration">>,
    retrieve_configuration(ConfigEndpoint).

retrieve_eudat(_Conf) ->
    ConfigEndpoint = <<"https://b2access.eudat.eu:8443/oauth2/.well-known/openid-configuration">>,
    retrieve_configuration(ConfigEndpoint).

retrieve_configuration(ConfigEndpoint) ->
    Name = <<"name">>,
    Description = <<"description">>,
    ClientId = <<"some id">>,
    ClientSecret = <<"secret">>,
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    {ok, _, Pid} = oidcc:add_openid_provider(Name, Description, ClientId, ClientSecret,
					     ConfigEndpoint, LocalEndpoint),
    ok = wait_for_config(Pid),
    ok = ensure_has_signing_keys(Pid),
    ok.


ensure_has_signing_keys(Pid) ->
    {ok, Config} = oidcc:get_openid_provider_info(Pid),
    #{keys := Keys} = Config,
    Filter = fun(#{use := Use}) ->
                     Use == sign
             end,
    ct:log("all keys: ~p", [Keys]),
    case lists:filter(Filter, Keys) of
        [] -> {error, no_signing_keys};
        SigKeys ->
            ct:log("signign keys: ~p", [SigKeys]),
            ok
    end.






wait_for_config(Pid) ->
    case oidcc_openid_provider:is_ready(Pid) of
	true ->
	    ok;
	false ->
	    timer:sleep(100),
	    wait_for_config(Pid)
    end.
