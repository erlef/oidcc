-module(oidcc_http_util_test).
-include_lib("eunit/include/eunit.hrl").

sync_get_test() ->
    UserInfoEndpoint = <<"http://my.provider/info">>,
    HttpBody = <<"{\"name\":\"joe\"}">>,

    OpenFun = fun(Host, Port, _Config)  ->
                      Host = "my.provider",
                      Port = 80,
                      {ok, gun}
              end,

    GetFun = fun(ConPid, Path, _Header)  ->
                      Path = "/info",
                      ConPid = gun,
                      gun_stream
              end,
    AwaitFun = fun(ConPid, Stream)  ->
                      ConPid = gun,
                      Stream = gun_stream,
                      {response, nofin, 200, []}
              end,
    AwaitBodyFun = fun(ConPid, Stream)  ->
                      ConPid = gun,
                      Stream = gun_stream,
                      {ok, HttpBody}
              end,
    ok = meck:new(gun),

    ok = meck:expect(gun, open, OpenFun),
    ok = meck:expect(gun, await_up, fun(_) -> {ok, tcp} end),
    ok = meck:expect(gun, get, GetFun),
    ok = meck:expect(gun, shutdown, fun(_) -> ok end),
    ok = meck:expect(gun, await, AwaitFun),
    ok = meck:expect(gun, await_body, AwaitBodyFun),

    {ok, #{body := HttpBody, status := 200 }} =
    oidcc_http_util:sync_http(get,UserInfoEndpoint,[],undefined),

    true = meck:validate(gun),
    meck:unload(gun),
    ok.


sync_post_test() ->
    TokenEndpoint = <<"https://my.provider/token">>,
    HttpBody = <<"TokenRawData">>,

    OpenFun = fun(Host, Port, _Config)  ->
                      Host = "my.provider",
                      Port = 443,
                      {ok, gun}
              end,

    PostFun = fun(ConPid, Path, _Header, _Body)  ->
                      Path = "/token",
                      ConPid = gun,
                      gun_stream
              end,
    AwaitFun = fun(ConPid, Stream)  ->
                      ConPid = gun,
                      Stream = gun_stream,
                      {response, nofin, 200, []}
              end,
    AwaitBodyFun = fun(ConPid, Stream)  ->
                      ConPid = gun,
                      Stream = gun_stream,
                      {ok, HttpBody}
              end,
    ok = meck:new(gun),

    ok = meck:expect(gun, open, OpenFun),
    ok = meck:expect(gun, await_up, fun(_) -> {ok, tcp} end),
    ok = meck:expect(gun, post, PostFun),
    ok = meck:expect(gun, shutdown, fun(_) -> ok end),
    ok = meck:expect(gun, await, AwaitFun),
    ok = meck:expect(gun, await_body, AwaitBodyFun),

    {ok,Map} = oidcc_http_util:sync_http(post,TokenEndpoint,[],<<"somedata">>),
    #{ status := 200,
       header := [],
       body := HttpBody} = Map,

    true = meck:validate(gun),
    meck:unload(gun),
    ok.

async_test() ->
    GetEndpoint = <<"http://my.provider/get">>,
    PostEndpoint = <<"http://my.provider/post">>,

    Pid = self(),
    OpenFun = fun(Host, Port, _Config)  ->
                      Host = "my.provider",
                      Port = 80,
                      {ok, Pid}
              end,

    GetFun = fun(ConPid, Path, _Header)  ->
                      Path = "/get",
                      ConPid = Pid,
                      get_stream
              end,
    PostFun = fun(ConPid, Path, _Header, _Body)  ->
                      Path = "/post",
                      ConPid = Pid,
                      post_stream
              end,
    ok = meck:new(gun),

    ok = meck:expect(gun, open, OpenFun),
    ok = meck:expect(gun, await_up, fun(_) -> {ok, tcp} end),
    ok = meck:expect(gun, get, GetFun),
    ok = meck:expect(gun, post, PostFun),
    ok = meck:expect(gun, shutdown, fun(_) -> ok end),

    {ok, GetPid, GetMRef, get_stream} =
    oidcc_http_util:async_http(get,GetEndpoint,[],undefined),
    GetPid = Pid,
    {ok, PostPid, PostMRef, post_stream} =
    oidcc_http_util:async_http(post,PostEndpoint,[],<<"somedata">>),
    PostPid = Pid,
    ok = oidcc_http_util:async_close(GetPid,GetMRef),
    ok = oidcc_http_util:async_close(PostPid,PostMRef),


    true = meck:validate(gun),
    meck:unload(gun),
    ok.


real_sync_get_test() ->
    Url = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    application:ensure_all_started(gun),
    {ok,#{status := 200} } = oidcc_http_util:sync_http(get,Url,[],undefined),
    ok.

