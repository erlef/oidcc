-module(conformance_oidc_client).
-behaviour(oidcc_client).

-export([init/0]).
-export([login_succeeded/1]).
-export([login_failed/2]).

init() ->
    oidcc_client:register(?MODULE).

login_succeeded(Token) ->
    {ok, Path} = conformance:check_result(true, Token),
    Updates = [
               {redirect, Path}
              ],
    {ok, Updates}.


login_failed(Error, Desc) ->
    conformance:check_result(false, {Error, Desc}),
    Path = <<"/">>,
    Updates = [{redirect, Path}],
    {ok, Updates}.
