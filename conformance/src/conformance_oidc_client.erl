-module(conformance_oidc_client).
-behaviour(oidcc_client).

-export([init/0]).
-export([login_succeeded/1]).
-export([login_failed/2]).

init() ->
    oidcc_client:register(?MODULE).

login_succeeded(Token) ->
    lager:info("~n~n*************************************~nthe user logged in with~n ~p~n", [Token]),
    % create e.g. a session and store it't id in a session to look it up on further usage
    Path = <<"/">>,
    Updates = [
               {redirect, Path}
              ],
    {ok, Updates}.


login_failed(Error, Desc) ->
    lager:info("~n~n*************************************~nlogin failed with~n ~p:~p~n", [Error, Desc]),
    Path = <<"/">>,
    Updates = [{redirect, Path}],
    {ok, Updates}.
