-module(conformance_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    conformance_oidc_client:init(),
    PrivDir = code:priv_dir(conformance),
    create_log_dir(),
    Dispatch = cowboy_router:compile( [{'_',
					[
                                         {"/", cowboy_static,
                                          {priv_file, conformance,
                                           "static/index.html"}
                                         },
                                         {"/test/", conformance_http, []},
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

create_log_dir() ->
    LDir = "/tmp/oidcc_rp_conformance/",
    os:cmd("rm -rf " ++ LDir),
    LogDir = list_to_binary(LDir),

    ok = file:make_dir(LogDir),
    conformance:set_conf(log_dir, LogDir),
    lager:info("using log dir ~p",[LogDir]),
    ok.
