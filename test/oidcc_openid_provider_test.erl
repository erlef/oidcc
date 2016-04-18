-module(oidcc_openid_provider_test).
-include_lib("eunit/include/eunit.hrl").


start_stop_test() ->
    Id = <<"some id">>,
    {ok, Pid} = oidcc_openid_provider:start_link(Id),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).

set_test() ->
    Id = <<"some id">>,
    Name = <<"my Name">>,
    Description = <<"some test oidc">>,
    ClientId = <<"234">>,
    ClientSecret = <<"secret">>,
    ConfigEndpoint = <<"https://my.provider/config">>,
    LocalEndpoint = <<"https://my.server/return">>,

    {ok, Pid} = oidcc_openid_provider:start_link(Id),
    ok = oidcc_openid_provider:set_name(Name,Pid),
    ok = oidcc_openid_provider:set_description(Description,Pid),
    ok = oidcc_openid_provider:set_client_id(ClientId,Pid),
    ok = oidcc_openid_provider:set_client_secret(ClientSecret,Pid),
    ok = oidcc_openid_provider:set_config_endpoint(ConfigEndpoint,Pid),
    ok = oidcc_openid_provider:set_local_endpoint(LocalEndpoint,Pid),
    {ok, Config} = oidcc_openid_provider:get_config(Pid),
    #{id := Id,
      name := Name,
      description := Description,
      client_id := ClientId,
      client_secret := ClientSecret,
      config_endpoint := ConfigEndpoint,
      local_endpoint := LocalEndpoint } = Config,
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).

fetch_config_test() ->
    Id = <<"some id">>,

    ConfigEndpoint = <<"https://my.provider/info">>,
    ConfigBody1 = <<"{\"issuer\":\"https://my.provider\"">>,
    ConfigBody2 = <<", \"jwks_uri\": \"https://my.provider/keys\" }">>,
    KeyBody = <<"{ \"keys\": [ { \"kty\": \"RSA\", \"alg\": \"RS256\", \"use\":
    \"sig\", \"kid\": \"6b8297523597b08d37e9c66e6dbbb32ea70e2770\", \"n\":
    \"ufxh3jipQ6N9GvVfaHIdFkCBQ7MA8XBkXswHQdwKEyXhYBPp11KKumenQ9hVodEkFEpVnblPxI-Tnmj_0lLX-d4CSEBzZO5hQGTSCKiCUESVOYrirLiN3Mxjt5qi4-7JESeATcptGbEk69T2NLlWYki_LcXTmt_-n4XV_HfgCg9DdrlTjq7xtDlc3KYUf6iizWEBKixd47Y91vzdegl-O5iu1WCHrF6owAu1Ok5q4pVoACPzXONLXnxjUNRpuYksmFZDJOeJEy4Ig59H0S-uy20StRSGCySSEjeACP_Kib7weqyRD-7zHzJpW6jR25XHvoIIbCvnnWkkCKj_noyimw\",
    \"e\": \"AQAB\" } ] }">>,

    OpenFun = fun(Host, Port, _Config)  ->
                      Host = "my.provider",
                      Port = 443,
                      {ok, gun}
              end,

    GetFun = fun(ConPid, Path, _Header)  ->
                      ConPid = gun,
                      case Path of
                          "/info" -> config_stream;
                          "/keys" -> key_stream
                      end
              end,

    AwaitFun = fun(ConPid, _Stream)  ->
                      ConPid = gun,
                      {response, nofin, 200, []}
              end,
    ok = meck:new(gun),
    ok = meck:expect(gun, open, OpenFun),
    ok = meck:expect(gun, await_up, fun(_) -> {ok, tcp} end),
    ok = meck:expect(gun, get, GetFun),
    ok = meck:expect(gun, shutdown, fun(_) -> ok end),
    ok = meck:expect(gun, await, AwaitFun),

    {ok, Pid} = oidcc_openid_provider:start_link(Id),
    ok = oidcc_openid_provider:set_config_endpoint(ConfigEndpoint,Pid),
    ok = oidcc_openid_provider:update_config(Pid),

    Pid ! {gun_response, gun, config_stream, nofin, 200, []},
    Pid ! {gun_data, gun, config_stream, nofin, ConfigBody1},
    Pid ! {gun_data, gun, config_stream, fin, ConfigBody2},

    {ok, Config1} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>
     } = Config1,

    Pid ! {gun_response, gun, key_stream, nofin, 200, []},
    Pid ! {gun_data, gun, key_stream, fin, KeyBody},

    {ok, Config2} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [_Key],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>
     } = Config2,

    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    true = meck:validate(gun),
    meck:unload(gun),
    ok.




