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

         retrieve_configuration/1
        ]).

all() ->
    [
     retrieve_configuration
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


retrieve_configuration(_Conf) ->
    Name = <<"Google">>,
    Description = <<"the well known search giant">>,
    ClientId = <<"some id">>,
    ClientSecret = <<"secret">>,
    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    {ok, _, Pid} = oidcc:add_openid_provider(Name, Description, ClientId, ClientSecret, 
					     ConfigEndpoint, LocalEndpoint),
    ok = wait_for_config(Pid),
    ok.




wait_for_config(Pid) ->
    case oidcc_openid_provider:is_ready(Pid) of
	true ->
	    ok;
	false ->
	    timer:sleep(100),
	    wait_for_config(Pid)
    end.

