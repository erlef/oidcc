-module(basic_client).
-behaviour(oidcc_client).

-export([init/0]).
-export([login_succeeded/1]).
-export([login_failed/2]).

init() ->
    oidcc_client:register(?MODULE).

login_succeeded(Token) ->
    io:format("~n~n*************************************~nthe user logged in with~n ~p~n", [Token]),
    % create e.g. a session and store it't id in a session to look it up on further usage
    SessionId = <<"123">>,
    CookieName = basic_client_http:cookie_name(),
    CookieData = SessionId,
    Path = <<"/">>,
    Updates = [
               {redirect, Path}, 
               {cookie, CookieName, CookieData, [{max_age, 30}]}
              ],
    {ok, Updates}.


login_failed(Error, Desc) ->
    io:format("~n~n*************************************~nlogin failed with~n ~p:~p~n", [Error, Desc]),
    Path = <<"/">>,
    Updates = [{redirect, Path}],
    {ok, Updates}.



    
    
