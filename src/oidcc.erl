-module(oidcc).

-export([add_openid_provider/6]).
-export([add_openid_provider/7]).
-export([find_openid_provider/1]).
-export([get_openid_provider_info/1]).
-export([get_openid_provider_list/0]).
-export([create_redirect_url/1]).
-export([create_redirect_url/2]).
-export([create_redirect_url/3]).
-export([retrieve_token/2]).
-export([parse_and_validate_token/2]).
-export([parse_and_validate_token/3]).
-export([retrieve_user_info/2]).

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
    OidcProvider = oidcc_openid_provider_mgr:add_openid_provider(IdIn),
    update_provider_or_error(OidcProvider, Name, Description, ClientId,
                             ClientSecret, ConfigEndpoint, LocalEndpoint).


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
%% same as create_redirect_url/3 but with State and Nonce being undefined
%% @end
-spec create_redirect_url(binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId) ->
    create_redirect_url(OpenIdProviderId, undefined, undefined).

%% @doc
%% same as create_redirect_url/3 but with Nonce being undefined
%% @end
-spec create_redirect_url(binary(), binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, OidcState) ->
    create_redirect_url(OpenIdProviderId, OidcState, undefined).

%% @doc
%% create a redirection for the given OpenId Connect provider
%%
%% this can be used to redirect the useragent of the ressource owner
%% to the OpenId Connect Provider
%% @end
-spec create_redirect_url(binary(), binary(), binary()) ->
    {ok, binary()} | {error, provider_not_ready}.
create_redirect_url(OpenIdProviderId, OidcState, OidcNonce ) ->
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    create_redirect_url_if_ready(Info, OidcState, OidcNonce).

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

    CiEncoded = cow_qs:urlencode(ClientId),
    AcEncoded = cow_qs:urlencode(AuthCode),
    LeEncoded = cow_qs:urlencode(LocalEndpoint),


    Body0 = << <<"grant_type=authorization_code">>/binary,
              <<"&client_id=">>/binary, CiEncoded/binary,
              <<"&code=">>/binary, AcEncoded/binary,
              <<"&redirect_uri=">>/binary, LeEncoded/binary >>,
    Header0 = [ {<<"content-type">>, <<"application/x-www-form-urlencoded">>}],

    {Body, Header} = add_authentication(Body0, Header0, AuthMethods, ClientId,
                                        Secret),
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
retrieve_user_info(#{access := AccessToken}, OpenIdProvider) ->
    #{token := Token} = AccessToken,
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(#{token := Token}, OpenIdProvider) ->
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(Token, #{userinfo_endpoint := Endpoint})
  when is_binary(Token) ->
    Header = [{<<"Authorization">>, << <<"Bearer ">>/binary, Token/binary >>}],
    HttpResult = oidcc_http_util:sync_http(get, Endpoint, Header, undefined),
    return_user_info(HttpResult);
retrieve_user_info(Token, OpenIdProvider) ->
    {ok, Config} = get_openid_provider_info(OpenIdProvider),
    retrieve_user_info(Token, Config).


create_redirect_url_if_ready(#{ready := false}, _, _) ->
    {error, provider_not_ready};
create_redirect_url_if_ready(Info, OidcState, OidcNonce) ->
    #{ local_endpoint := LocalEndpoint,
       client_id := ClientId,
       authorization_endpoint := AuthEndpoint
     } = Info,
    CiEncoded = cow_qs:urlencode(ClientId),
    LeEncoded = cow_qs:urlencode(LocalEndpoint),
    Static1 = <<"?response_type=code&scope=openid&client_id=">>,
    Static2 = <<"&redirect_uri=">>,
    Url = << AuthEndpoint/binary, Static1/binary, CiEncoded/binary,
             Static2/binary, LeEncoded/binary >>,
    Url1 = append_state(OidcState, Url),
    Url2 = append_nonce(OidcNonce, Url1),
    {ok, Url2}.

update_provider_or_error({error, Reason}, _Name, _Description, _ClientId,
                         _ClientSecret, _ConfigEndpoint, _LocalEndpoint) ->
    {error, Reason};
update_provider_or_error({ok, Id, Pid}, Name, Description, ClientId,
                         ClientSecret, ConfigEndpoint, LocalEndpoint) ->
    ok = update_openid_provider(Name, Description, ClientId, ClientSecret,
                           ConfigEndpoint, LocalEndpoint, Pid),
    {ok, Id, Pid}.

update_openid_provider(Name, Description, ClientId, ClientSecret,
                       ConfigEndpoint, LocalEndpoint, Pid) ->
    ok = oidcc_openid_provider:set_name(Name, Pid),
    ok = oidcc_openid_provider:set_description(Description, Pid),
    ok = oidcc_openid_provider:set_client_id(ClientId, Pid),
    ok = oidcc_openid_provider:set_client_secret(ClientSecret, Pid),
    ok = oidcc_openid_provider:set_config_endpoint(ConfigEndpoint, Pid),
    ok = oidcc_openid_provider:set_local_endpoint(LocalEndpoint, Pid),
    ok = oidcc_openid_provider:update_config(Pid),
    ok.


append_state(State, Url) when is_binary(State) ->
    Encoded = cow_qs:urlencode(State),
    Static = <<"&state=">>,
    << Url/binary, Static/binary, Encoded/binary >>;
append_state(_, Url)  ->
    Url.


append_nonce(Nonce, Url) when is_binary(Nonce) ->
    Encoded = cow_qs:urlencode(Nonce),
    Static = <<"&nonce=">>,
    << Url/binary, Static/binary, Encoded/binary >>;
append_nonce(_, Url) ->
    Url.

add_authentication(Body, Header, [<<"client_secret_post">>|_], _ClientId,
                   ClientSecret) ->
    CsEncoded = cow_qs:urlencode(ClientSecret),
    Secret = << <<"&client_secret=">>/binary, CsEncoded/binary >>,
    NewBody = << Body/binary, Secret/binary >>,
    {NewBody, Header};
add_authentication(Body, Header, [<<"client_secret_basic">>|_], ClientId,
                   ClientSecret) ->
    RawData = <<ClientId/binary, <<":">>/binary, ClientSecret/binary>>,
    AuthData = base64:encode(RawData),
    BasicAuth = << <<"Basic ">>/binary, AuthData/binary >>,
    NewHeader = [{<<"Authorization">>, BasicAuth} | Header ],
    {Body, NewHeader};
add_authentication(B, H, [], CI, CS) ->
    add_authentication(B, H, [<<"client_secret_basic">>], CI, CS);
add_authentication(B, H, [_|T], CI, CS) ->
    add_authentication(B, H, T, CI, CS).

return_token( {error, Reason} ) ->
    {error, Reason};
return_token( {ok, #{body := Token, status := 200}} ) ->
    {ok, Token};
return_token( {ok, #{body := Body, status := Status}} ) ->
    {error, {http_error, Status, Body}}.



return_user_info({ok, #{status := 200, body := Data}}) ->
    try jsx:decode(Data, [{labels, attempt_atom}, return_maps])
    of Map -> {ok, Map}
    catch Error -> {error, Error}
    end;
return_user_info({ok, Map}) ->
    {error, {bad_status, Map}};
return_user_info({error, _}=Error) ->
    Error.

