-module(oidcc_client).
-export([succeeded/1]).
-export([failed/2]).


-callback login_succeeded( Token::map()) ->
    {ok, CookieName::binary(), CookieData::binary(), Path::binary()} |
    {ok, Path::binary()}.
-callback login_failed( Reason::atom(), Description::binary() ) ->
    {ok, CookieName::binary(), CookieData::binary(), Path::binary()} |
    {ok, Path::binary()}.

succeeded(Token) ->
    case application:get_env(oidcc, client_mod) of
        {ok, Mod} -> Result = Mod:login_succeeded(Token),
                     return_unified_result(Result);
        _ -> {error, no_module_given}
    end.

failed(Error, Description) ->
    case application:get_env(oidcc, client_mod) of
        {ok, Mod} -> Result = Mod:login_failed(Error, Description),
                     return_unified_result(Result);
        _ -> {error, no_module_given}
    end.


return_unified_result({ok, Path}) ->
    {ok, undefined, undefined, Path};
return_unified_result({ok, Name, Data, Path}) ->
    {ok, Name, Data, Path}.
