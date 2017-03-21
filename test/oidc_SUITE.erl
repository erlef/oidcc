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
    application:set_env(oidcc, cert_depth, 5),
    application:set_env(oidcc, provider_max_tries, 1),
    application:set_env(oidcc, cacertfile, "/etc/ssl/certs/ca-certificates.crt"),
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
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    Config = #{client_id => <<"some_id">>},
    {ok, _, Pid} = oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint,
                                             Config),
    ok = wait_for_config(Pid),
    ok = fetch_signing_keys(Pid),
    ok.


fetch_signing_keys(Pid) ->
    {ok, Keys} = oidcc_openid_provider:update_and_get_keys(Pid),
    {ok, Config} = oidcc:get_openid_provider_info(Pid),
    #{keys := Keys,
      config_deadline := Deadline
     } = Config,
    Filter = fun(#{use := Use}) ->
                     Use == sign
             end,
    Now = erlang:system_time(seconds),
    ct:log("all keys: ~p", [Keys]),
    ct:log("config deadline in ~p seconds", [Deadline - Now]),
    case lists:filter(Filter, Keys) of
        [] -> {error, no_signing_keys};
        SigKeys ->
            ct:log("signign keys: ~p", [SigKeys]),
            ok
    end.






wait_for_config(Pid) ->
    Ready = oidcc_openid_provider:is_ready(Pid),
    {ok, Error} = oidcc_openid_provider:get_error(Pid),
    case {Ready, Error}  of
	{true, undefined} ->
	    ok;
	{false, undefined} ->
	    timer:sleep(100),
	    wait_for_config(Pid);
        _ ->
            {error, Error}
    end.
