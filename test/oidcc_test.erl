-module(oidcc_test).
-include_lib("eunit/include/eunit.hrl").

add_openid_provider_test() ->
    MyPid = self(),
    RandomId = <<"6">>,
    AddFun = fun(Config) ->
                     Id = maps:get(id, Config, undefined),
                     case Id of
                         undefined ->
                             {ok, RandomId, MyPid};
                         Id ->
                             {ok, Id, MyPid}
                     end
                end,
    ok = meck:new(oidcc_openid_provider),
    ok = meck:new(oidcc_openid_provider_mgr),
    ok = meck:expect(oidcc_openid_provider, update_config, fun(_) -> ok end),

    ok = meck:expect(oidcc_openid_provider_mgr, add_openid_provider, AddFun),

    ConfigEndpoint = <<"some_remote_url">>,
    LocalEndpoint = <<"some_local_url">>,
    Id = <<"123345456">>,
    Config = #{ client_id => <<"123">>,
                client_secret => <<"secret">>
              },

    {ok, RandomId, MyPid} = oidcc:add_openid_provider(ConfigEndpoint,
                                                      LocalEndpoint, Config),

    {ok, Id, MyPid} = oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint,
                                               maps:put(id, Id, Config)),
    true = meck:validate(oidcc_openid_provider),
    true = meck:validate(oidcc_openid_provider_mgr),
    meck:unload(oidcc_openid_provider),
    meck:unload(oidcc_openid_provider_mgr),
    ok.

get_openid_provider_info_test() ->
    MyPid = self(),
    ProviderId = <<"6">>,
    BadProviderId = <<"7">>,
    ConfigFun = fun(Pid)->
                     Pid = MyPid,
                     {ok, #{}}
                end,
    MapFun = fun(Id) ->
                     case Id of
                         ProviderId -> {ok, MyPid};
                         _ -> {error, not_found}
                     end
             end,
    ok = meck:new(oidcc_openid_provider),
    ok = meck:new(oidcc_openid_provider_mgr),

    ok = meck:expect(oidcc_openid_provider, get_config, ConfigFun),
    ok = meck:expect(oidcc_openid_provider_mgr, get_openid_provider, MapFun),

    {ok, #{}} = oidcc:get_openid_provider_info(MyPid),
    {ok, #{}} = oidcc:get_openid_provider_info(ProviderId),
    {error,not_found} = oidcc:get_openid_provider_info(BadProviderId),

    true = meck:validate(oidcc_openid_provider),
    true = meck:validate(oidcc_openid_provider_mgr),
    meck:unload(oidcc_openid_provider),
    meck:unload(oidcc_openid_provider_mgr),
    ok.

get_openid_provider_list_test() ->
    ListFun = fun() ->
                      {ok, []}
              end,
    ok = meck:new(oidcc_openid_provider_mgr),
    ok = meck:expect(oidcc_openid_provider_mgr, get_openid_provider_list, ListFun),

    {ok, []} = oidcc:get_openid_provider_list(),

    true = meck:validate(oidcc_openid_provider_mgr),
    meck:unload(oidcc_openid_provider_mgr),
    ok.

create_redirect_url_test() ->
    MyPid = self(),
    ProviderId = <<"6">>,
    ClientId = <<"123">>,
    State = <<"someimportantstate">>,
    Nonce = <<"noncenonce">>,

    LocalEndpoint = <<"https://my.server/return">>,
    AuthzEndpoint = <<"https://my.provider/auth">>,

    ConfigFun = fun(Pid)->
                     Pid = MyPid,
                     {ok, #{local_endpoint => LocalEndpoint,
                            client_id => ClientId,
                            authorization_endpoint => AuthzEndpoint,
                            static_extend_url => #{<<"test">> => <<"id">>}
                           }}
                end,
    MapFun = fun(Id) ->
                     case Id of
                         ProviderId -> {ok, MyPid};
                         _ -> {error, not_found}
                     end
             end,
    ok = meck:new(oidcc_openid_provider),
    ok = meck:new(oidcc_openid_provider_mgr),

    ok = meck:expect(oidcc_openid_provider, get_config, ConfigFun),
    ok = meck:expect(oidcc_openid_provider_mgr, get_openid_provider, MapFun),

    Config1 = #{scopes => ["email", <<"openid">>]},
    Config2 = #{scopes => ["email", <<"profile">>, openid],
                state => State},
    Config3 = #{scopes => [email, profile, openid],
                state => State,
                nonce => Nonce},
    Config4 = #{scopes => ["email", <<"openid">>],
                url_extension => #{<<"other">> => <<"green">>}},


    {ok, Url1} = oidcc:create_redirect_url(ProviderId),
    {ok, Url2} = oidcc:create_redirect_url(ProviderId, Config1),
    {ok, Url3} = oidcc:create_redirect_url(ProviderId, Config2),
    {ok, Url4} = oidcc:create_redirect_url(ProviderId, Config3),
    {ok, Url5} = oidcc:create_redirect_url(ProviderId, Config4),

    ExpUrl1 = <<"https://my.provider/auth?scope=openid&response_type=code&client_id=123&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl1, Url1),

    ExpUrl2 =
    <<"https://my.provider/auth?scope=openid+email&response_type=code&client_id=123&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl2, Url2),

    ExpUrl3 =
    <<"https://my.provider/auth?scope=openid+profile+email&state=someimportantstate&response_type=code&client_id=123&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl3, Url3),

    ExpUrl4 =
    <<"https://my.provider/auth?scope=openid+profile+email&nonce=noncenonce&state=someimportantstate&response_type=code&client_id=123&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl4, Url4),

    ExpUrl5 =
    <<"https://my.provider/auth?scope=openid+email&response_type=code&client_id=123&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id&other=green">>,
    ?assertEqual(ExpUrl5, Url5),
    true = meck:validate(oidcc_openid_provider),
    true = meck:validate(oidcc_openid_provider_mgr),
    meck:unload(oidcc_openid_provider),
    meck:unload(oidcc_openid_provider_mgr),
    ok.


retrieve_and_validate_token_test() ->
    MyPid = self(),
    ClientId = <<"123">>,
    ClientSecret = <<"secret">>,

    TokenEndpoint = <<"https://my.provider/token">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    TokenData = <<"TokenData">>,
    IdToken = <<"IdToken">>,
    ProviderId = <<"ID123">>,
    AuthMethods = [<<"unsupporeted_auth">>,<<"client_secret_post">>],

    ConfigFun = fun(Pid)->
                     Pid = MyPid,
                     {ok, #{local_endpoint => LocalEndpoint,
                            client_id => ClientId,
                            client_secret => ClientSecret,
                            token_endpoint => TokenEndpoint,
                            token_endpoint_auth_methods_supported => AuthMethods
                           }}
                end,
    MapFun = fun(Id) ->
                     case Id of
                         ProviderId -> {ok, MyPid};
                         _ -> {error, not_found}
                     end
             end,

    HttpFun = fun(Method, Url, _Header, _ContentType, _Body)  ->
                      Method = post,
                      Url = TokenEndpoint,
                      {ok, #{status => 200, header => [], body => TokenData}}
              end,

    PassThrough = fun(Data) ->
                          meck:passthrough([Data])
                  end,
    ExtractFun = fun(Data, _Scopes) ->
                         Data = TokenData,
                         #{id => IdToken}
                 end,
    ValidateFun = fun(TokenMap,Provider,_Nonce, _NoneAllowed) ->
                          Provider = ProviderId,
                          #{id := IdToken} = TokenMap,
                          {ok,#{ id => #{}}}
                  end,

    ok = meck:new(oidcc_token),
    ok = meck:expect(oidcc_token, extract_token_map, ExtractFun),
    ok = meck:expect(oidcc_token, validate_token_map, ValidateFun),
    ok = meck:new(oidcc_openid_provider),
    ok = meck:new(oidcc_openid_provider_mgr),
    ok = meck:new(oidcc_http_util),

    ok = meck:expect(oidcc_openid_provider, get_config, ConfigFun),
    ok = meck:expect(oidcc_openid_provider_mgr, get_openid_provider, MapFun),
    ok = meck:expect(oidcc_http_util, sync_http, HttpFun),
    ok = meck:expect(oidcc_http_util, urlencode, PassThrough ),
    ok = meck:expect(oidcc_http_util, qs, PassThrough),

    AuthCode = <<"1234567890">>,
    {ok, #{id := #{}}} = oidcc:retrieve_and_validate_token(AuthCode, ProviderId),

    true = meck:validate(oidcc_token),
    true = meck:validate(oidcc_openid_provider),
    true = meck:validate(oidcc_openid_provider_mgr),
    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_openid_provider),
    meck:unload(oidcc_openid_provider_mgr),
    meck:unload(oidcc_http_util),
    meck:unload(oidcc_token),
    ok.

retrieve_user_info_test() ->
    MyPid = self(),
    ProviderId = <<"6">>,
    UserInfoEndpoint = <<"http://my.provider/info">>,
    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    GoodSub = <<"123456">>,
    BadSub =  <<"123789">>,

    ConfigFun = fun(Pid)->
                        Pid = MyPid,
                        {ok, #{userinfo_endpoint => UserInfoEndpoint}}
                end,
    MapFun = fun(Id) ->
                     case Id of
                         ProviderId -> {ok, MyPid};
                         _ -> {error, not_found}
                     end
             end,
    HttpFun = fun(Method, Url, _Header, _UseCache)  ->
                      Method = get,
                      Url = UserInfoEndpoint,
                      {ok, #{status => 200, header => [], body => HttpBody}}
              end,

    ok = meck:new(oidcc_openid_provider),
    ok = meck:new(oidcc_openid_provider_mgr),
    ok = meck:new(oidcc_http_util),

    ok = meck:expect(oidcc_openid_provider, get_config, ConfigFun),
    ok = meck:expect(oidcc_openid_provider_mgr, get_openid_provider, MapFun),
    ok = meck:expect(oidcc_http_util, sync_http,HttpFun),
    AccessToken = <<"opensesame">>,
    GoodToken = #{access => #{token => AccessToken},
              id => #{ claims => #{ sub => <<"123456">> }},
              refresh => #{}},
    BadToken = #{access => #{token => AccessToken},
              id => #{ claims => #{ sub => <<"123457">> }},
              refresh => #{}},

    {ok, #{name := <<"joe">>} } = oidcc:retrieve_user_info(GoodToken,
                                                           ProviderId),
    {ok, #{name := <<"joe">>} } = oidcc:retrieve_user_info(AccessToken,
                                                           ProviderId, GoodSub),
    {ok, #{name := <<"joe">>} } = oidcc:retrieve_user_info(AccessToken,
                                                           ProviderId),
    {error, bad_subject } = oidcc:retrieve_user_info(BadToken, ProviderId),
    {error, bad_subject } = oidcc:retrieve_user_info(AccessToken, ProviderId,
                                                     BadSub),

    true = meck:validate(oidcc_openid_provider),
    true = meck:validate(oidcc_openid_provider_mgr),
    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_openid_provider),
    meck:unload(oidcc_openid_provider_mgr),
    meck:unload(oidcc_http_util),
    ok.
