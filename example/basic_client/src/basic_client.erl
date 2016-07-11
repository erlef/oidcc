-module(basic_client).
-behaviour(oidcc_client).

-export([init/0]).
-export([login_succeeded/1]).
-export([login_failed/2]).

init() ->
    application:set_env(oidcc, client_mod, ?MODULE).

login_succeeded(Token) ->
    io:format("~n~n*************************************~nthe user logged in with~n ~p~n", [Token]),
    % create e.g. a session and store it't id in a session to look it up on further usage
    SessionId = <<"123">>,
    CookieName = basic_client_http:cookie_name(),
    CookieData = SessionId,
    Path = <<"/">>,
    {ok, CookieName, CookieData, Path}.


login_failed(_Error, _Description) ->
    Path = <<"/">>,
    {ok, Path}.



    
    
