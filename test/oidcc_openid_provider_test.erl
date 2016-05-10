-module(oidcc_openid_provider_test).
-include_lib("eunit/include/eunit.hrl").


start_stop_test() ->
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secrect => <<"dont tell">>,
               config_endpoint => <<"https://my.provider.com/well.known">>,
               local_endpoint => <<"/here">>
              },
    Id = <<"some id">>,
    {ok, Pid} = oidcc_openid_provider:start_link(Id, Config),
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

    ConfigIn = #{name => Name,
               description => Description,
               client_id => ClientId,
               client_secrect => ClientSecret,
               config_endpoint => ConfigEndpoint,
               local_endpoint => LocalEndpoint
              },
    {ok, Pid} = oidcc_openid_provider:start_link(Id, ConfigIn),
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

manual_set_test() ->
    Id = <<"some id">>,
    Name = <<"my Name">>,
    Description = <<"some test oidc">>,
    ClientId = <<"234">>,
    ClientSecret = <<"secret">>,
    ConfigEndpoint = <<"https://my.provider/config">>,
    LocalEndpoint = <<"https://my.server/return">>,

    ConfigOne = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secrect => <<"dont tell">>,
               config_endpoint => ConfigEndpoint,
               local_endpoint => <<"/here">>
              },
    {ok, Pid} = oidcc_openid_provider:start_link(Id, ConfigOne),
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
    KeyEndpoint = <<"https://my.provider/keys">>,
    ConfigBody1 = <<"{\"issuer\":\"https://my.provider\",">>,
    ConfigBody2 = <<" \"jwks_uri\": \"https://my.provider/keys\" }">>,
    KeyBody = <<"{ \"keys\": [ { \"kty\": \"RSA\", \"alg\": \"RS256\", \"use\":
    \"sig\", \"kid\": \"6b8297523597b08d37e9c66e6dbbb32ea70e2770\", \"n\":
    \"ufxh3jipQ6N9GvVfaHIdFkCBQ7MA8XBkXswHQdwKEyXhYBPp11KKumenQ9hVodEkFEpVnblPxI-Tnmj_0lLX-d4CSEBzZO5hQGTSCKiCUESVOYrirLiN3Mxjt5qi4-7JESeATcptGbEk69T2NLlWYki_LcXTmt_-n4XV_HfgCg9DdrlTjq7xtDlc3KYUf6iizWEBKixd47Y91vzdegl-O5iu1WCHrF6owAu1Ok5q4pVoACPzXONLXnxjUNRpuYksmFZDJOeJEy4Ig59H0S-uy20StRSGCySSEjeACP_Kib7weqyRD-7zHzJpW6jR25XHvoIIbCvnnWkkCKj_noyimw\",
    \"e\": \"AQAB\" } ] }">>,

    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secrect => <<"dont tell">>,
               config_endpoint => ConfigEndpoint,
               local_endpoint => <<"/here">>
              },
    StartFun = fun(Url)  ->
                      case Url of
                          ConfigEndpoint -> {ok, gun, mref, "/info"};
                          KeyEndpoint -> {ok, gun, mref, "/keys"}
                      end
              end,
    HttpFun = fun(Method, Path, _Header, _Body, ConPid)  ->
                      ConPid = gun,
                      Method = get,
                      case Path of
                          "/info" -> {ok, config_stream};
                          "/keys" -> {ok, key_stream}
                      end
              end,

    CloseFun = fun(Pid, Mref)  ->
                      Pid = gun,
                      Mref = mref,
                      ok
              end,

    ok = meck:new(oidcc_http_util),
    ok = meck:expect(oidcc_http_util, start_http, StartFun),
    ok = meck:expect(oidcc_http_util, async_http, HttpFun),
    ok = meck:expect(oidcc_http_util, async_close, CloseFun),
    ok = meck:expect(oidcc_http_util, uncompress_body_if_needed, fun(B,_) ->
                                                                         {ok,B}
                                                                 end),

    {ok, Pid} = oidcc_openid_provider:start_link(Id, Config),

    Pid ! {gun_up, gun, http},
    Pid ! {gun_response, gun, config_stream, nofin, 200, []},
    Pid ! {gun_data, gun, config_stream, nofin, ConfigBody1},
    Pid ! {gun_data, gun, config_stream, fin, ConfigBody2},

    {ok, Config1} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>
     } = Config1,

    Pid ! {gun_up, gun, http},
    Pid ! {gun_response, gun, key_stream, nofin, 200, []},
    Pid ! {gun_data, gun, key_stream, fin, KeyBody},

    {ok, Config2} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [_Key],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>
     } = Config2,

    true = oidcc_openid_provider:is_issuer(<<"https://my.provider">>, Pid),
    false = oidcc_openid_provider:is_issuer(<<"https://other.provider">>, Pid),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),
    ok.




