-module(conformance_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    conformance_oidc_client:init(),
    PrivDir = code:priv_dir(conformance),
    Dispatch = cowboy_router:compile( [{'_',
					[
                                         {"/", conformance_http, []},
					 {"/oidc", oidcc_cowboy, []},
					 {"/oidc/return", oidcc_cowboy, []}
					]}]),
    {ok, _} = cowboy:start_https( https_handler
			       , 100
			       , [
                                   {port, 8080},
                                   {certfile, PrivDir ++ "/ssl/server.crt"},
                                   {keyfile, PrivDir ++ "/ssl/server.key"}
                                 ]
			       , [{env, [{dispatch, Dispatch}]}]
			       ),
    conformance_sup:start_link().

stop(_) ->
    ok.
