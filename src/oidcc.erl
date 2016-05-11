-module(oidcc).

-export([add_openid_provider/6]).
-export([add_openid_provider/7]).
-export([find_openid_provider/1]).
-export([get_openid_provider_info/1]).
-export([get_openid_provider_list/0]).
-export([create_redirect_url/1]).
-export([create_redirect_url/2]).
-export([create_redirect_url/3]).
-export([create_redirect_url/4]).
-export([retrieve_token/2]).
-export([parse_and_validate_token/2]).
-export([parse_and_validate_token/3]).
-export([retrieve_user_info/2]).
-export([retrieve_user_info/3]).
-export([introspect_token/2]).

%% @doc
%% add an OpenID Connect Provider to the list of possible Providers
%%
%% this automatically triggers the fetching of the configuration endpoint
%% and after that fetching the keys for verifying the signature of the
%% ID Tokens.
%% @end
-spec add_openid_provider(binary(), binary(), binary(), binary(), binary(),
                          binary()) -> {ok, Id::binary(), Pid::pid()}.
add_openid_provider(Name, Description, ClientId, ClientSecret, ConfigEndpoint,
                    LocalEndpoint) ->
    add_openid_provider(undefined, Name, Description, ClientId, ClientSecret,
                        ConfigEndpoint, LocalEndpoint).

%% @doc
%% add an OpenID Connect Provider to the list of possible Providers, giving the
%% ID to use
%%
%% this automatically triggers the fetching of the configuration endpoint
%% and after that fetching the keys for verifying the signature of the
%% ID Tokens.
%% @end
-spec add_openid_provider(binary(), binary(), binary(), binary(), binary()
                          , binary(), binary()) ->
    {ok, Id::binary(), Pid::pid()} | {error, id_already_used}.
add_openid_provider(IdIn, Name, Description, ClientId, ClientSecret,
                    ConfigEndpoint, LocalEndpoint) ->
    Config = #{name => Name,
               description => Description,
               client_id => ClientId,
               client_secrect => ClientSecret,
               config_endpoint => ConfigEndpoint,
               local_endpoint => LocalEndpoint
              },
    oidcc_openid_provider_mgr:add_openid_provider(IdIn, Config).


-spec find_openid_provider(Issuer::binary()) -> {ok, pid()}
                                                | {error, not_found}.
find_openid_provider(Issuer) ->
    oidcc_openid_provider_mgr:find_openid_provider(Issuer).

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
%% same as create_redirect_url/4 but with State and Nonce being undefined and
%% scope being openid
%% @end
-spec create_redirect_url(binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId) ->
    create_redirect_url(OpenIdProviderId, [<<"openid">>], undefined, undefined).

%% @doc
%% same as create_redirect_url/4 but with State and Nonce being undefined
%% @end
-spec create_redirect_url(binary(), list()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, Scopes) ->
    create_redirect_url(OpenIdProviderId, Scopes, undefined, undefined).

%% @doc
%% same as create_redirect_url/4 but with Nonce being undefined
%% @end
-spec create_redirect_url(binary(), list(), binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, Scopes, OidcState) ->
    create_redirect_url(OpenIdProviderId, Scopes, OidcState, undefined).

%% @doc
%% create a redirection for the given OpenId Connect provider
%%
%% this can be used to redirect the useragent of the ressource owner
%% to the OpenId Connect Provider
%% @end
-spec create_redirect_url(binary(), list(), binary(), binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, Scopes, OidcState, OidcNonce ) ->
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    create_redirect_url_if_ready(Info, Scopes, OidcState, OidcNonce).

%% @doc
%% retrieve the token using the authcode received before
%%
%% the authcode was sent to the local endpoint by the OpenId Connect provider,
%% using redirects. the result is textual representation of the token and should
%% be verified using parse_and_validate_token/3
%% @end
-spec retrieve_token(binary(), binary()) -> {ok, binary()}.
retrieve_token(AuthCode, OpenIdProviderId) ->
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    #{ client_id := ClientId,
       client_secret := Secret,
       token_endpoint := Endpoint,
       token_endpoint_auth_methods_supported := AuthMethods,
       local_endpoint := LocalEndpoint
     } = Info,
    AuthMethod = select_preferred_auth(AuthMethods),
    QsBody0 = [ {<<"grant_type">>, <<"authorization_code">>},
                   {<<"code">>, AuthCode},
                   {<<"redirect_uri">>, LocalEndpoint}
                 ],
    Header0 = [ {<<"content-type">>, <<"application/x-www-form-urlencoded">>}],
    {QsBody, Header} = add_authentication(QsBody0, Header0, AuthMethod,
                                          ClientId, Secret),
    Body = cow_qs:qs(QsBody),
    return_token(oidcc_http_util:sync_http(post, Endpoint, Header, Body)).

%% @doc
%% like parse_and_validate_token/3 yet without checking the nonce
%% @end
-spec parse_and_validate_token(binary(), binary()) ->
    {ok, map()} | {error, any()}.
parse_and_validate_token(Token, OpenIdProvider) ->
    parse_and_validate_token(Token, OpenIdProvider, undefined).
%% @doc
%%
%% also validates the token according to the OpenID Connect spec, see
%% source of oidcc_token:validate_id_token/1 for more information
%% @end
-spec parse_and_validate_token(binary(), binary(), binary()) ->
    {ok, map()} | {error, any()}.
parse_and_validate_token(Token, OpenIdProvider, Nonce) ->
    TokenMap = oidcc_token:extract_token_map(Token),
    #{id := IdToken0 } = TokenMap,
    case oidcc_token:validate_id_token(IdToken0, OpenIdProvider, Nonce) of
        {ok, IdToken} ->
           {ok, maps:put(id, IdToken, TokenMap)};
        Other -> Other
    end.

%% @doc
%% retrieve the informations of a user given by its token map
%%
%% this is done by looking up the UserInfoEndpoint from the configuration and
%% then requesting info, using the access token as bearer token
%% @end
-spec retrieve_user_info(map() | binary(), binary()) ->
    {ok, map()} | {error, any()}.
retrieve_user_info(Token, OpenIdProvider) ->
    retrieve_user_info(Token, OpenIdProvider, undefined).


-spec retrieve_user_info(map() | binary(), binary(), binary()|undefined) ->
    {ok, map()} | {error, any()}.
retrieve_user_info(Token, #{userinfo_endpoint := Endpoint}, Subject) ->
    AccessToken = extract_access_token(Token),
    Header = [bearer_auth(AccessToken)],
    HttpResult = oidcc_http_util:sync_http(get, Endpoint, Header, undefined),
    return_validated_user_info(HttpResult, Subject);
retrieve_user_info(Token, OpenIdProvider, Subject) ->
    {ok, Config} = get_openid_provider_info(OpenIdProvider),
    retrieve_user_info(Token, Config, Subject).


%% @doc
%% introspect the given token at the given provider
%%
%% this is done by looking up the IntrospectionEndpoint from the configuration
%% and then requesting info, using the client credentials as authentication
%% @end
-spec introspect_token(map() | binary(), binary()) -> {ok, map()} |
                                                      {error, any()}.
introspect_token(Token, #{introspection_endpoint := Endpoint,
                          client_id := ClientId,
                          client_secret := ClientSecret}) ->
    AccessToken = extract_access_token(Token),
    Header = [
              {<<"accept">>, <<"application/json">>},
              {<<"content-type">>, <<"application/x-www-form-urlencoded">>},
              basic_auth(ClientId, ClientSecret)
             ],
    BodyQs = cow_qs:qs([{<<"token">>, AccessToken}]),
    HttpResult = oidcc_http_util:sync_http(post, Endpoint, Header, BodyQs),
    return_json_info(HttpResult);
introspect_token(Token, ProviderId) ->
    {ok, Config} = get_openid_provider_info(ProviderId),
    introspect_token(Token, Config).


extract_access_token(#{access := AccessToken}) ->
    #{token := Token} = AccessToken,
    Token;
extract_access_token(#{token := Token}) ->
    Token;
extract_access_token(Token) when is_binary(Token) ->
    Token.



create_redirect_url_if_ready(#{ready := false}, _, _, _) ->
    {error, provider_not_ready};
create_redirect_url_if_ready(Info, Scopes, OidcState, OidcNonce) ->
    #{ local_endpoint := LocalEndpoint,
       client_id := ClientId,
       authorization_endpoint := AuthEndpoint
     } = Info,
    Scope = scopes_to_bin(Scopes, <<>>),
    UrlList = [
               {<<"response_type">>, <<"code">>},
               {<<"scope">>, Scope},
               {<<"client_id">>, ClientId},
               {<<"redirect_uri">>, LocalEndpoint}
              ],
    UrlList1 = append_state(OidcState, UrlList),
    UrlList2 = append_nonce(OidcNonce, UrlList1),
    Qs = cow_qs:qs(UrlList2),
    Url = << AuthEndpoint/binary, <<"?">>/binary, Qs/binary>>,
    {ok, Url}.


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




append_state(State, UrlList) when is_binary(State) ->
    [{<<"state">>, State} | UrlList];
append_state(_, UrlList)  ->
    UrlList.


append_nonce(Nonce, UrlList) when is_binary(Nonce) ->
    [{<<"nonce">>, Nonce} | UrlList];
append_nonce(_, UrlList) ->
    UrlList.


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


add_authentication(QsBodyList, Header, basic, ClientId, Secret) ->
    NewHeader = [basic_auth(ClientId, Secret)| Header ],
    {QsBodyList, NewHeader};
add_authentication(QsBodyList, Header, post, ClientId, ClientSecret) ->
    NewBodyList = [ {<<"client_id">>, ClientId},
                    {<<"client_secret">>, ClientSecret} | QsBodyList ],
    {NewBodyList, Header};
add_authentication(B, H, undefined, CI, CS) ->
    add_authentication(B, H, basic, CI, CS).



return_token( {error, Reason} ) ->
    {error, Reason};
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
    try jsx:decode(Data, [{labels, attempt_atom}, return_maps])
    of Map -> {ok, Map}
    catch Error -> {error, Error}
    end;
return_json_info({ok, Map}) ->
    {error, {bad_status, Map}};
return_json_info({error, _}=Error) ->
    Error.


basic_auth(User, Secret) ->
    UserEnc = cow_qs:urlencode(User),
    SecretEnc = cow_qs:urlencode(Secret),
    RawAuth = <<UserEnc/binary, <<":">>/binary, SecretEnc/binary>>,
    AuthData = base64:encode(RawAuth),
    BasicAuth = << <<"Basic ">>/binary, AuthData/binary >>,
    {<<"authorization">>, BasicAuth}.

bearer_auth(Token) ->
    {<<"authorization">>, << <<"Bearer ">>/binary, Token/binary >>}.

