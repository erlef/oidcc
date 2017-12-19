-module(oidcc_openid_provider_test).
-include_lib("eunit/include/eunit.hrl").


start_stop_test() ->
    application:set_env(oidcc, cacertfile, "somefile.pem"),
    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               request_scopes => undefined,
               issuer_or_endpoint => <<"http://my.provider.com/">>,
               local_endpoint => <<"/here">>,
               static_extend_url => #{}
              },
    Id = <<"some id">>,
    {ok, Pid} = oidcc_openid_provider:start_link(Id, Config),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).

set_test() ->
    application:set_env(oidcc, cacertfile, "somefile.pem"),
    Id = <<"some id">>,
    Name = <<"my Name">>,
    Description = <<"some test oidc">>,
    ClientId = <<"234">>,
    ClientSecret = <<"secret">>,
    ConfigEndpoint = <<"https://my.provider/.well-known/openid-configuration">>,
    LocalEndpoint = <<"https://my.server/return">>,

    ConfigIn = #{name => Name,
               description => Description,
               client_id => ClientId,
               client_secret => ClientSecret,
               request_scopes => undefined,
               issuer_or_endpoint => ConfigEndpoint,
               local_endpoint => LocalEndpoint,
               static_extend_url => #{}
              },
    {ok, Pid} = oidcc_openid_provider:start_link(Id, ConfigIn),
    {ok, Config} = oidcc_openid_provider:get_config(Pid),
    #{id := ConfId,
      name := ConfName,
      description := ConfDesc,
      client_id := ConfClientId,
      client_secret := ConfClientSecret,
      config_endpoint := ConfConfigEndpoint,
      local_endpoint := ConfLocalEndpoint } = Config,
    ?assertEqual(ConfId, Id),
    ?assertEqual(ConfName, Name),
    ?assertEqual(ConfDesc, Description),
    ?assertEqual(ConfClientSecret, ClientSecret),
    ?assertEqual(ConfClientId, ClientId),
    ?assertEqual(ConfConfigEndpoint, ConfigEndpoint),
    ?assertEqual(ConfLocalEndpoint, LocalEndpoint),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).


fetch_config_test() ->
    Id = <<"some id">>,

    ConfigEndpoint = <<"https://my.provider/.well-known/openid-configuration">>,
    KeyEndpoint = <<"https://my.provider/keys">>,
    ConfigBody = <<"{\"issuer\":\"https://my.provider\",\"jwks_uri\": \"https://my.provider/keys\", \"response_types_supported\":[\"code\"] }">>,
    KeyBody = <<"{ \"keys\": [ { \"kty\": \"RSA\", \"alg\": \"RS256\", \"use\":
    \"sig\", \"kid\": \"6b8297523597b08d37e9c66e6dbbb32ea70e2770\", \"n\":
    \"ufxh3jipQ6N9GvVfaHIdFkCBQ7MA8XBkXswHQdwKEyXhYBPp11KKumenQ9hVodEkFEpVnblPxI-Tnmj_0lLX-d4CSEBzZO5hQGTSCKiCUESVOYrirLiN3Mxjt5qi4-7JESeATcptGbEk69T2NLlWYki_LcXTmt_-n4XV_HfgCg9DdrlTjq7xtDlc3KYUf6iizWEBKixd47Y91vzdegl-O5iu1WCHrF6owAu1Ok5q4pVoACPzXONLXnxjUNRpuYksmFZDJOeJEy4Ig59H0S-uy20StRSGCySSEjeACP_Kib7weqyRD-7zHzJpW6jR25XHvoIIbCvnnWkkCKj_noyimw\",
    \"e\": \"AQAB\" } ] }">>,

    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               request_scopes => undefined,
               issuer_or_endpoint => ConfigEndpoint,
               local_endpoint => <<"/here">>,
               test => <<"extra config">>,
               static_extend_url => #{}
              },
    HttpFun = fun(Method, Url, _Header)  ->
                      Method = get,
                      case Url of
                          ConfigEndpoint -> {ok, config_id};
                          KeyEndpoint -> {ok, key_id}
                      end
              end,

    ok = meck:new(oidcc_http_util),
    ok = meck:expect(oidcc_http_util, async_http, HttpFun),
    ok = meck:expect(oidcc_http_util, uncompress_body_if_needed, fun(B,_) ->
                                                                         {ok,B}
                                                                 end),

    {ok, Pid} = oidcc_openid_provider:start_link(Id, Config),

    Pid ! {http, {config_id, {{tcp, 200, good}, [], ConfigBody }}},

    {ok, Config1} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>,
       extra_config := #{ test := <<"extra config">>}
     } = Config1,

    gen_server:cast(Pid, retrieve_keys),
    Pid ! {http, {key_id, {{tcp, 200, good}, [], KeyBody }}},
    {ok, Config2} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [_Keys],
       issuer := <<"https://my.provider">>,
       jwks_uri := <<"https://my.provider/keys">>,
       extra_config := #{ test := <<"extra config">>}
     } = Config2,

    true = oidcc_openid_provider:is_issuer(<<"https://my.provider">>, Pid),
    false = oidcc_openid_provider:is_issuer(<<"https://other.provider">>, Pid),
    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),
    ok.

real_config_fetch_test_() ->
    Setup = fun() ->
                    application:set_env(oidcc, cert_depth, 5),
                    application:set_env(oidcc, provider_max_tries, 1),
                    application:set_env(oidcc, cacertfile, ca_file()),
                    ok
            end,
    Cleanup = fun(_) ->
                      application:unset_env(oidcc, cert_depth),
                      application:unset_env(oidcc, provider_max_tries),
                      application:unset_env(oidcc, cacertfile),
                      ok
              end,
    WithoutKeys = {"real config fetch", fun() -> real_config_fetch(false) end},
    WithKeys = {"real config and keys fetch", fun() -> real_config_fetch(true) end},
    Instantiator = fun(_) ->
                           [ WithoutKeys,
                             {timeout, 70, [WithKeys ]}
                           ]
                   end,
    {setup, Setup, Cleanup, Instantiator}.


real_config_fetch(WithKeys) ->
    Id = <<"some id">>,

    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    Issuer = <<"https://accounts.google.com">>,

    Config = #{name => <<"some name">>,
               description => <<"some description">>,
               client_id => <<"123">>,
               client_secret => <<"dont tell">>,
               request_scopes => undefined,
               issuer_or_endpoint => Issuer,
               local_endpoint => <<"/here">>,
               static_extend_url => #{}
              },


    {ok, Pid} = oidcc_openid_provider:start_link(Id, Config),
    ok = oidcc_openid_provider:update_config(Pid),
    ok = wait_for_config(Pid, 50),

    {ok, Config2} = oidcc_openid_provider:get_config(Pid),
    #{ config_endpoint := ConfigEndpoint,
       keys := [],
       issuer := Issuer,
       jwks_uri := <<"https://www.googleapis.com/oauth2/v3/certs">>
     } = Config2,

    ok = case WithKeys of
             true ->
                 {ok, Keys} = oidcc_openid_provider:update_and_get_keys(Pid),
                 true = (length(Keys) >= 1),
                 ok;
             _ ->
                 ok
         end,

    ok = oidcc_openid_provider:stop(Pid),
    ok = test_util:wait_for_process_to_die(Pid, 100).


wait_for_config(_, 0) ->
    timeout;
wait_for_config(Pid, Timeout) ->
    {ok, Config} = oidcc_openid_provider:get_config(Pid),
    case maps:is_key(jwks_uri, Config) of
        true ->
            ok;
        false ->
            timer:sleep(100),
            wait_for_config(Pid, Timeout - 1)
    end.

ca_file() ->
    code:where_is_file("cacert.pem").
