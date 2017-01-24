-module(conformance_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    conformance_oidc_client:init(),
    PrivDir = code:priv_dir(conformance),
    init(),
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

init() ->
    LDir = "/tmp/oidcc_rp_conformance/",
    CDir = LDir ++ "code/",
    CnfDir = LDir ++ "configuration/",
    DDir = LDir ++ "dynamic/",
    os:cmd("rm -rf " ++ LDir),
    LogDir = list_to_binary(LDir),
    CodeDir = list_to_binary(CDir),
    ConfDir = list_to_binary(CnfDir),
    DynDir = list_to_binary(DDir),

    ok = file:make_dir(LogDir),
    ok = file:make_dir(CodeDir),
    ok = file:make_dir(ConfDir),
    ok = file:make_dir(DynDir),
    conformance:set_conf(log_dir, LogDir),
    conformance:set_conf(code_dir, CodeDir),
    conformance:set_conf(conf_dir, ConfDir),
    conformance:set_conf(dyn_dir, DynDir),
    conformance:set_conf(rp_id, <<"oidcc.code">>),
    lager:info("using log dir ~p",[LogDir]),

    Url = <<"https://rp.certification.openid.net:8080/">>,
    SSLResult =
        case oidcc_http_util:sync_http(get, Url ,[]) of
            {ok, #{status := 200}}  -> "successful";
            Error ->
                OidccInfo = application:get_all_env(oidcc),
                lager:info("oidcc settings: ~p",[OidccInfo]),
                Error
        end,
    lager:info("checking ssl: ~p~n", [SSLResult]),

    lager:info("cleaning logs ..."),
    ClearLog = <<"https://rp.certification.openid.net:8080/clear/oidcc.code">>,
    oidcc_http_util:sync_http(get, ClearLog, []),
    ok.
