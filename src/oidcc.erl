-module(oidcc).

-export([add_openid_provider/6]).
-export([get_openid_provider_info/1]).
-export([get_openid_provider_list/0]).
-export([create_redirect_url/1]).
-export([create_redirect_url/2]).
-export([create_redirect_url/3]).
-export([retrieve_token/2]).
-export([parse_and_validate_token/2]).
-export([parse_and_validate_token/3]).
-export([retrieve_user_info/2]).


add_openid_provider(Id, Description, ClientId, ClientSecret, ConfigEndpoint,
                    LocalEndpoint) ->
    {ok, Pid} = oidcc_openid_provider_sup:add_openid_provider(Id), 
    ok = oidcc_openid_provider:set_description(Description,Pid),
    ok = oidcc_openid_provider:set_client_id(ClientId,Pid),
    ok = oidcc_openid_provider:set_client_secret(ClientSecret,Pid),
    ok = oidcc_openid_provider:set_config_endpoint(ConfigEndpoint,Pid),
    ok = oidcc_openid_provider:set_local_endpoint(LocalEndpoint,Pid),
    ok.

get_openid_provider_info(Pid) when is_pid(Pid) ->
    oidcc_openid_provider:get_config(Pid);
get_openid_provider_info(OpenIdProviderId) when is_binary(OpenIdProviderId) ->
    case oidcc_openid_provider_sup:get_openid_provider(OpenIdProviderId) of
        {ok, Pid} ->
            oidcc_openid_provider:get_config(Pid);
        {error, Reason} -> 
            {error, Reason}
    end.


get_openid_provider_list() ->
    oidcc_openid_provider_sup:get_openid_provider_list().

create_redirect_url(OpenIdProviderId) -> 
    create_redirect_url(OpenIdProviderId, undefined, undefined).

create_redirect_url(OpenIdProviderId, OidcState) -> 
    create_redirect_url(OpenIdProviderId, OidcState, undefined).

create_redirect_url(OpenIdProviderId, OidcState, OidcNonce ) -> 
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    #{ local_endpoint := LocalEndpoint,
       client_id := ClientId,
       authorization_endpoint := AuthEndpoint
     } = Info,
    CI_Encoded = cow_qs:urlencode(ClientId), 
    LE_Encoded = cow_qs:urlencode(LocalEndpoint),
    Static1 = <<"?response_type=code&scope=openid&client_id=">>,
    Static2 = <<"&redirect_uri=">>,
    Url = << AuthEndpoint/binary, Static1/binary, CI_Encoded/binary,
             Static2/binary, LE_Encoded/binary >>,
    Url1 = append_state(OidcState, Url),
    Url2 = append_nonce(OidcNonce, Url1),
    {ok, Url2}.

append_state(State,Url) when is_binary(State) ->
    Encoded = cow_qs:urlencode(State),
    Static = <<"&state=">>,
    << Url/binary, Static/binary, Encoded/binary >>;
append_state(_,Url)  ->
    Url.


append_nonce(Nonce,Url) when is_binary(Nonce) ->
    Encoded = cow_qs:urlencode(Nonce),
    Static = <<"&nonce=">>,
    << Url/binary, Static/binary, Encoded/binary >>;
append_nonce(_,Url) ->
    Url.


retrieve_token(AuthCode, OpenIdProviderId) ->
    {ok, Info} = get_openid_provider_info(OpenIdProviderId),
    #{ client_id := ClientId,
       client_secret := Secret,
       token_endpoint := Endpoint,
       token_endpoint_auth_methods_supported := AuthMethods,
       local_endpoint := LocalEndpoint
     } = Info,

    CI_Encoded = cow_qs:urlencode(ClientId), 
    AC_Encoded = cow_qs:urlencode(AuthCode), 
    LE_Encoded = cow_qs:urlencode(LocalEndpoint), 


    Body0 = << <<"grant_type=authorization_code">>/binary,
              <<"&client_id=">>/binary, CI_Encoded/binary,
              <<"&code=">>/binary, AC_Encoded/binary,
              <<"&redirect_uri=">>/binary, LE_Encoded/binary >>,
    Header0 = [ {<<"content-type">>,  <<"application/x-www-form-urlencoded">>}], 

    {Body, Header} = add_authentication(Body0, Header0, AuthMethods, ClientId, Secret),
    return_token(ehtc:http_sync_post(Endpoint,Header,Body)).


add_authentication(Body, Header, [<<"client_secret_post">>|_], _ClientId, ClientSecret) ->
    CS_Encoded = cow_qs:urlencode(ClientSecret), 
    Secret = << <<"&client_secret=">>/binary,  CS_Encoded/binary >>,
    NewBody = << Body/binary, Secret/binary >>,
    {NewBody, Header};
add_authentication(Body, Header, [<<"client_secret_basic">>|_], ClientId, ClientSecret) ->
    AuthData = base64:encode(<<ClientId/binary, <<":">>/binary, ClientSecret/binary>>),
    BasicAuth = << <<"Basic ">>/binary, AuthData/binary >>,
    NewHeader = [{<<"authorization">>, BasicAuth} | Header ],
    {Body, NewHeader};
add_authentication(B, H, [], CI, CS) ->
    add_authentication(B, H, [<<"client_secret_basic">>], CI, CS);
add_authentication(B, H, [_|T], CI, CS) ->
    add_authentication(B, H, T, CI, CS).


return_token( {error,Reason} ) -> 
    {error, Reason};
return_token( {ok, #{body := Token, status := 200}} ) -> 
    {ok, Token};
return_token( {ok, #{body := Body, status := Status}} ) -> 
    {error, {http_error, Status, Body}}.

parse_and_validate_token(Token, OpenIdProvider) ->
    parse_and_validate_token(Token, OpenIdProvider, undefined).

parse_and_validate_token(Token, OpenIdProvider, Nonce) when is_binary(Nonce) ->
    TokenMap = oidcc_token:extract_token_map(Token),
    #{id := IdToken0 } = TokenMap,
    try oidcc_token:validate_id_token(IdToken0,OpenIdProvider,Nonce)
    of IdToken ->
           {ok, maps:put(id,IdToken,TokenMap)}
    catch
        Error ->
            {error, Error}
    end;
parse_and_validate_token(Token, OpenIdProvider, _Nonce) ->
    parse_and_validate_token(Token, OpenIdProvider).


retrieve_user_info(#{access := AccessToken},OpenIdProvider) ->
    #{token := Token} = AccessToken,
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(#{token := Token},OpenIdProvider) ->
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(Token,#{userinfo_endpoint := Endpoint}) when is_binary(Token) ->
    Header = [{<<"authorization">>,<< <<"Bearer ">>/binary, Token/binary >>}],
    return_user_info(ehtc:http_sync_get(Endpoint,Header));
retrieve_user_info(Token,OpenIdProvider) ->
    {ok, Config} = get_openid_provider_info(OpenIdProvider),
    retrieve_user_info(Token, Config).


return_user_info({ok, #{status := 200, body := Data}}) ->
    jsx:decode(Data,[{labels, attempt_atom}, return_maps]);
return_user_info({ok, Map}) ->
    {error, {bad_status, Map}};
return_user_info({error, _}=Error) ->
    Error.

