-module(oidcc).

-export([add_openid_provider/2]).
-export([add_openid_provider/3]).
-export([find_openid_provider/1]).
-export([find_all_openid_provider/1]).
-export([get_openid_provider_info/1]).
-export([get_openid_provider_list/0]).
-export([create_redirect_url/1]).
-export([create_redirect_url/2]).
-export([create_redirect_for_session/1]).
-export([create_redirect_for_session/2]).
-export([retrieve_and_validate_token/2]).
-export([retrieve_and_validate_token/3]).
-export([retrieve_user_info/2]).
-export([retrieve_user_info/3]).
-export([retrieve_fresh_token/2]).
-export([retrieve_fresh_token/3]).
-export([introspect_token/2]).
-export([register_module/1]).



%% @doc
%% add an OpenID Connect Provider to the list of possible Providers
%%
%% this automatically triggers the fetching of the configuration endpoint
%% @end
-spec add_openid_provider(binary(), binary()) -> {ok, Id::binary(), Pid::pid()}.
add_openid_provider(IssuerOrConfigEP, LocalEndpoint) ->
    add_openid_provider(IssuerOrConfigEP, LocalEndpoint, #{}).

-spec add_openid_provider(binary(), binary(), map()) ->
                                 {ok, Id::binary(), Pid::pid()} |
                                 {error, Reason::any()}.
add_openid_provider(IssuerOrConfigEP, LocalEndpoint, AdditionalConfig) ->
    BasicConfig = #{name => <<"OpenId Connect Provider">>,
                    description => <<"a minimal configured provider">>,
                    client_id => undefined,
                    client_secret => <<"">>,
                    request_scopes => undefined,
                    static_extend_url => #{},
                    registration_params => #{}
                   },
    ForceUpdate = #{ issuer_or_endpoint => IssuerOrConfigEP,
                     local_endpoint => LocalEndpoint},

    ConfigBase = maps:merge(BasicConfig, AdditionalConfig),
    Config = maps:merge(ConfigBase, ForceUpdate),
    oidcc_openid_provider_mgr:add_openid_provider(Config).




-spec find_openid_provider(Issuer::binary()) -> {ok, pid()}
                                                    | {error, not_found}.
find_openid_provider(Issuer) ->
    oidcc_openid_provider_mgr:find_openid_provider(Issuer).

-spec find_all_openid_provider(Issuer::binary()) -> {ok, [pid()]}
                                                    | {error, not_found}.
find_all_openid_provider(Issuer) ->
    oidcc_openid_provider_mgr:find_all_openid_provider(Issuer).

%% @doc
%% get information from a given OpenId Connect Provider
%%
%% the parameter can either be the Pid or it's Id. The result is a map
%% containing all the information gathered by connecting to the configuration
%% endpoint given at the beginning.
%% the map also contains a boolean flag 'ready' which is true, once the
%% configuration has been fetched.
%% @end
-spec get_openid_provider_info(pid() | binary()) -> {ok, map()}.
get_openid_provider_info(Pid) when is_pid(Pid) ->
    oidcc_openid_provider:get_config(Pid);
get_openid_provider_info(OpenIdProviderId) when is_binary(OpenIdProviderId) ->
    case oidcc_openid_provider_mgr:get_openid_provider(OpenIdProviderId) of
        {ok, Pid} ->
            oidcc_openid_provider:get_config(Pid);
        {error, Reason} ->
            {error, Reason}
    end.


%% @doc
%% get a list of all currently configured OpenId Connect Provider
%%
%% it is a list of tuples {Id, Pid}
%% @end
-spec get_openid_provider_list() -> {ok, [{binary(), pid()}]}.
get_openid_provider_list() ->
    oidcc_openid_provider_mgr:get_openid_provider_list().

%% @doc
%% same as create_redirect_url/4 but with all parameters being fetched
%% from the given session, except the provider
%% @end
-spec create_redirect_for_session(pid()) -> {ok, binary()}.
create_redirect_for_session(Session) ->
    create_redirect_for_session(Session, #{}).

%% @doc
%% same as create_redirect_url/4 but with all parameters being fetched
%% from the given session, except the provider
%% @end
-spec create_redirect_for_session(pid(), map()) -> {ok, binary()}.
create_redirect_for_session(Session, UrlExtension) ->
    {ok, Scopes} = oidcc_session:get_scopes(Session),
    {ok, State} = oidcc_session:get_id(Session),
    {ok, Nonce} = oidcc_session:get_nonce(Session),
    {ok, Pkce} = oidcc_session:get_pkce(Session),
    {ok, OpenIdProviderId} = oidcc_session:get_provider(Session),
    Config = #{scopes => Scopes, state => State, nonce => Nonce, pkce => Pkce,
              url_extension => UrlExtension},
    create_redirect_url(OpenIdProviderId, Config).

%% @doc
%% same as create_redirect_url/4 but with State and Nonce being undefined and
%% scope being openid
%% @end
-spec create_redirect_url(binary()) ->
                                 {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId) ->
    create_redirect_url(OpenIdProviderId, #{}).

%% @doc
%% same as create_redirect_url/4 but with State and Nonce being undefined
%% @end
-spec create_redirect_url(binary(), map()) ->
                                 {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, Config) ->
    BasicConfig = #{
      scopes => [openid],
      state => undefined,
      nonce => undefined,
      pkce => undefined,
      url_extension => #{}
     },
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    create_redirect_url_if_ready(Info, maps:merge(BasicConfig, Config)).


%% @doc
%% retrieve the token using the authcode received before and directly validate
%% the result.
%%
%% the authcode was sent to the local endpoint by the OpenId Connect provider,
%% using redirects. the result is textual representation of the token and should
%% be verified using parse_and_validate_token/3
%% @end
retrieve_and_validate_token(AuthCode, ProviderId) ->
    retrieve_and_validate_token(AuthCode, ProviderId, #{}).

retrieve_and_validate_token(AuthCode, ProviderId, Config) ->
    Pkce = maps:get(pkce, Config, undefined),
    Nonce = maps:get(nonce, Config, undefined),
    Scopes = scopes_to_bin(maps:get(scope, Config, []), <<>>),
    {ok, Info} = get_openid_provider_info(ProviderId),
    #{local_endpoint := LocalEndpoint} = Info,
    QsBody = [ {<<"grant_type">>, <<"authorization_code">>},
                {<<"code">>, AuthCode},
                {<<"redirect_uri">>, LocalEndpoint}
              ],
    case retrieve_a_token(QsBody, Pkce, Info) of
        {ok, Token} ->
            TokenMap = oidcc_token:extract_token_map(Token, Scopes),
            oidcc_token:validate_token_map(TokenMap, ProviderId, Nonce, true);
        Error -> Error
    end.

%% @doc
%% retrieve the informations of a user given by its token map or an access token
%%
%% this is done by looking up the UserInfoEndpoint from the configuration and
%% then requesting info, using the access token as bearer token
%% @end
-spec retrieve_user_info(map() | binary(), binary()) ->
                                {ok, map()} | {error, any()}.
retrieve_user_info(#{access := _, id := _, refresh := _} = TokenMap,
                   ProviderIdOrPid) ->
    Subject = extract_subject(TokenMap),
    retrieve_user_info(TokenMap, ProviderIdOrPid, Subject);
retrieve_user_info(AccessToken, ProviderIdOrPid) when is_binary(AccessToken) ->
    retrieve_user_info(AccessToken, ProviderIdOrPid, undefined);
retrieve_user_info(_, _) ->
    {error, bad_token}.


-spec retrieve_user_info(Token, ProviderIdOrPid, Subject)-> {ok, map()} |
                                                             {error, any()} when
      Token :: binary() | map(),
      ProviderIdOrPid :: binary() | pid(),
      Subject :: binary() | undefined.
retrieve_user_info(Token, ProviderIdOrPid, Subject) ->
    {ok,
     #{userinfo_endpoint := Endpoint}
    } = get_openid_provider_info(ProviderIdOrPid),
    AccessToken = extract_access_token(Token),
    Header = [bearer_auth(AccessToken)],
    HttpResult = oidcc_http_util:sync_http(get, Endpoint, Header, true),
    return_validated_user_info(HttpResult, Subject).



retrieve_fresh_token(RefreshToken, OpenIdProvider) ->
    retrieve_fresh_token(RefreshToken, [], OpenIdProvider).

retrieve_fresh_token(RefreshToken, Scopes, OpenIdProvider) ->
    {ok, Config} = get_openid_provider_info(OpenIdProvider),
    BodyQs0 = [
              {<<"refresh_token">>, RefreshToken},
              {<<"grant_type">>, <<"refresh_token">>}
             ],
    BodyQs = append_scope(Scopes, BodyQs0),
    retrieve_a_token(BodyQs, Config).


%% @doc
%% introspect the given token at the given provider
%%
%% this is done by looking up the IntrospectionEndpoint from the configuration
%% and then requesting info, using the client credentials as authentication
%% @end
-spec introspect_token(Token, ProviderOrConfig) -> {ok, map()} |
                                                   {error, any()} when
      Token :: binary() | map(),
      ProviderOrConfig :: binary() | map().
introspect_token(TokenMapIn, #{introspection_endpoint := Endpoint,
                          client_id := ClientId,
                          client_secret := ClientSecret}) ->
    AccessToken = extract_access_token(TokenMapIn),
    Header = [
              {"accept", "application/json"},
              basic_auth(ClientId, ClientSecret)
             ],
    BodyQs = oidcc_http_util:qs([{<<"token">>, AccessToken}]),
    HttpResult = oidcc_http_util:sync_http(post, Endpoint, Header,
                                           "application/x-www-form-urlencoded",
                                           BodyQs, true),
    case return_token(HttpResult) of
        {ok, Token} ->
            TokenMap = oidcc_token:introspect_token_map(Token, ClientId),
            {ok, TokenMap};
        Error -> Error
    end;
introspect_token(Token, ProviderId) ->
    {ok, Config} = get_openid_provider_info(ProviderId),
    introspect_token(Token, Config).

register_module(Module) ->
    oidcc_client:register(Module).


retrieve_a_token(QsBodyIn, OpenIdProviderInfo) ->
    retrieve_a_token(QsBodyIn, undefined, OpenIdProviderInfo).

retrieve_a_token(QsBodyIn, Pkce, OpenIdProviderInfo) ->
    #{ client_id := ClientId,
       client_secret := Secret,
       token_endpoint := Endpoint
     } = OpenIdProviderInfo,
    AuthMethods = maps:get(token_endpoint_auth_methods_supported,
                           OpenIdProviderInfo, [<<"client_secret_basic">>]),
    AuthMethod = select_preferred_auth(AuthMethods),
    Header0 = [],
    {QsBody, Header} = add_authentication_code_verifier(QsBodyIn, Header0,
                                                        AuthMethod, ClientId,
                                                        Secret, Pkce),
    Body = oidcc_http_util:qs(QsBody),
    return_token(oidcc_http_util:sync_http(post, Endpoint, Header,
                                           "application/x-www-form-urlencoded",
                                           Body)).


extract_subject(#{sub := Subject}) ->
    Subject;
extract_subject(#{id := IdToken}) ->
    extract_subject(IdToken);
extract_subject(#{claims := Claims}) ->
    extract_subject(Claims);
extract_subject(_) ->
    undefined.

extract_access_token(#{access := AccessToken}) ->
    #{token := Token} = AccessToken,
    Token;
extract_access_token(#{token := Token}) ->
    Token;
extract_access_token(Token) when is_binary(Token) ->
    Token.



create_redirect_url_if_ready(#{ready := false}, _) ->
    {error, provider_not_ready};
create_redirect_url_if_ready(Info, Config) ->
    #{ local_endpoint := LocalEndpoint,
       client_id := ClientId,
       authorization_endpoint := AuthEndpoint,
       static_extend_url := StaticUrlKeyValues
     } = Info,
    #{
       scopes := Scopes,
       state := OidcState,
       nonce := OidcNonce,
       pkce := Pkce,
       url_extension := DynUrlKeyValues
     } = Config,
    UrlKeyValues = maps:merge(StaticUrlKeyValues, DynUrlKeyValues),
    UrlList = [
               {<<"response_type">>, <<"code">>},
               {<<"client_id">>, ClientId},
               {<<"redirect_uri">>, LocalEndpoint}
              ] ++ map_to_url_list(UrlKeyValues),
    UrlList1 = append_state(OidcState, UrlList),
    UrlList2 = append_nonce(OidcNonce, UrlList1),
    UrlList3 = append_code_challenge(Pkce, UrlList2),
    UrlList4 = append_scope(Scopes, UrlList3),
    Qs = oidcc_http_util:qs(UrlList4),
    Url = << AuthEndpoint/binary, <<"?">>/binary, Qs/binary>>,
    {ok, Url}.

map_to_url_list(Map) when is_map(Map) ->
    ConvertValue = fun(Value) when is_binary(Value) ->
                           Value;
                      (Atom) when is_atom(Atom) ->
                           atom_to_binary(Atom, utf8);
                      (List) when is_list(List) ->
                           list_to_binary(List);
                      (_Other) ->
                           undefined
                   end,
    Convert = fun({Key, Value}, List) ->
                      CKey = ConvertValue(Key),
                      CValue = ConvertValue(Value),
                      case (CKey /= undefined) and (CValue /= undefined) of
                          true ->
                              [{CKey, CValue} | List];
                          _ ->
                              List
                      end
              end,
    lists:foldl(Convert, [], maps:to_list(Map)).



append_scope(<<>>, QsList) ->
    QsList;
append_scope(Scope, QsList) when is_binary(Scope) ->
    [{<<"scope">>, Scope} | QsList];
append_scope(Scopes, QsList) when is_list(Scopes) ->
    append_scope(scopes_to_bin(Scopes, <<>>), QsList).



append_state(State, UrlList) when is_binary(State) ->
    [{<<"state">>, State} | UrlList];
append_state(_, UrlList)  ->
    UrlList.


append_nonce(Nonce, UrlList) when is_binary(Nonce) ->
    [{<<"nonce">>, Nonce} | UrlList];
append_nonce(_, UrlList) ->
    UrlList.

append_code_challenge(#{challenge := Challenge} = Pkce, UrlList) ->
    NewUrlList = [{<<"code_challenge">>, Challenge} | UrlList],
    append_code_challenge_method(Pkce, NewUrlList);
append_code_challenge(_, UrlList) ->
    UrlList.

append_code_challenge_method(#{method := 'S256'}, UrlList) ->
    [{<<"code_challenge_method">>, <<"S256">>} | UrlList];
append_code_challenge_method(_, UrlList) ->
    [{<<"code_challenge_method">>, <<"plain">>} | UrlList].

select_preferred_auth(AuthMethodsSupported) ->
    Selector = fun(Method, Current) ->
                       case {Method, Current} of
                           {_, basic} -> basic;
                           {<<"client_secret_basic">>, _} -> basic;
                           {<<"client_secret_post">>, _} -> post;
                           {_, Current} -> Current
                       end
               end,
    lists:foldl(Selector, undefined, AuthMethodsSupported).


add_authentication_code_verifier(QsBodyList, Header, basic, ClientId, Secret,
                                 undefined) ->
    NewHeader = [basic_auth(ClientId, Secret)| Header ],
    {QsBodyList, NewHeader};
add_authentication_code_verifier(QsBodyList, Header, post, ClientId,
                                 ClientSecret, undefined) ->
    NewBodyList = [ {<<"client_id">>, ClientId},
                    {<<"client_secret">>, ClientSecret} | QsBodyList ],
    {NewBodyList, Header};
add_authentication_code_verifier(B, H, undefined, CI, CS, undefined) ->
    add_authentication_code_verifier(B, H, basic, CI, CS, undefined);
add_authentication_code_verifier(BodyQs, Header, AuthMethod, CI, CS,
                                 #{verifier:=CV}) ->
    BodyQs1 = [{<<"code_verifier">>, CV} | BodyQs],
    add_authentication_code_verifier(BodyQs1, Header, AuthMethod, CI, CS,
                                     undefined).


return_token( {ok, #{body := Token, status := 200}} ) ->
    {ok, Token};
return_token( {ok, #{body := Body, status := Status}} ) ->
    {error, {http_error, Status, Body}}.


return_validated_user_info(HttpData, undefined) ->
    return_json_info(HttpData);
return_validated_user_info(HttpData, Subject) ->
    case return_json_info(HttpData) of
        {ok, #{ sub := Subject } = Map} -> {ok, Map};
        {ok, _} -> {error, bad_subject};
        Other -> Other
    end.

return_json_info({ok, #{status := 200, body := Data}}) ->
    try jsone:decode(Data, [{keys, attempt_atom}, {object_format, map}])
    of Map -> {ok, Map}
    catch Error -> {error, Error}
    end;
return_json_info({ok, Map}) ->
    {error, {bad_status, Map}}.


basic_auth(User, Secret) ->
    UserEnc = oidcc_http_util:urlencode(User),
    SecretEnc = oidcc_http_util:urlencode(Secret),
    RawAuth = <<UserEnc/binary, <<":">>/binary, SecretEnc/binary>>,
    AuthData = base64:encode(RawAuth),
    BasicAuth = << <<"Basic ">>/binary, AuthData/binary >>,
    {<<"authorization">>, BasicAuth}.

bearer_auth(Token) ->
    {<<"authorization">>, << <<"Bearer ">>/binary, Token/binary >>}.


scopes_to_bin([], Bin) ->
    Bin;
scopes_to_bin([H | T], <<>>) when is_binary(H) ->
    scopes_to_bin(T, H);
scopes_to_bin([H | T], Bin) when is_binary(H) ->
    NewBin = << H/binary, <<" ">>/binary, Bin/binary>>,
    scopes_to_bin(T, NewBin);
scopes_to_bin([H | T], Bin) when is_atom(H) ->
    List = [ atom_to_binary(H, utf8) | T],
    scopes_to_bin(List, Bin);
scopes_to_bin([H | T], Bin) when is_list(H) ->
    List = [ list_to_binary(H) | T],
    scopes_to_bin(List, Bin).
