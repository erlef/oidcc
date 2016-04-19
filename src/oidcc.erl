-module(oidcc).

-export([add_openid_provider/6]).
-export([add_openid_provider/7]).
-export([get_openid_provider_info/1]).
-export([get_openid_provider_list/0]).
-export([create_redirect_url/1]).
-export([create_redirect_url/2]).
-export([create_redirect_url/3]).
-export([retrieve_token/2]).
-export([parse_and_validate_token/2]).
-export([parse_and_validate_token/3]).
-export([retrieve_user_info/2]).


add_openid_provider(Name, Description, ClientId, ClientSecret, ConfigEndpoint,
                    LocalEndpoint) ->
    add_openid_provider(undefined, Name, Description, ClientId, ClientSecret,
                        ConfigEndpoint, LocalEndpoint).

add_openid_provider(IdIn, Name, Description, ClientId, ClientSecret,
                    ConfigEndpoint, LocalEndpoint) ->
    {ok, Id, Pid} = oidcc_openid_provider_mgr:add_openid_provider(IdIn),
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


get_openid_provider_info(Pid) when is_pid(Pid) ->
    oidcc_openid_provider:get_config(Pid);
get_openid_provider_info(OpenIdProviderId) when is_binary(OpenIdProviderId) ->
    case oidcc_openid_provider_mgr:get_openid_provider(OpenIdProviderId) of
        {ok, Pid} ->
            oidcc_openid_provider:get_config(Pid);
        {error, Reason} ->
            {error, Reason}
    end.


get_openid_provider_list() ->
    oidcc_openid_provider_mgr:get_openid_provider_list().

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
    CiEncoded = cow_qs:urlencode(ClientId),
    LeEncoded = cow_qs:urlencode(LocalEndpoint),
    Static1 = <<"?response_type=code&scope=openid&client_id=">>,
    Static2 = <<"&redirect_uri=">>,
    Url = << AuthEndpoint/binary, Static1/binary, CiEncoded/binary,
             Static2/binary, LeEncoded/binary >>,
    Url1 = append_state(OidcState, Url),
    Url2 = append_nonce(OidcNonce, Url1),
    {ok, Url2}.

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
    return_token(http_post(Endpoint, Header, Body)).


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
    NewHeader = [{<<"authorization">>, BasicAuth} | Header ],
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

parse_and_validate_token(Token, OpenIdProvider) ->
    parse_and_validate_token(Token, OpenIdProvider, undefined).

parse_and_validate_token(Token, OpenIdProvider, Nonce) ->
    TokenMap = oidcc_token:extract_token_map(Token),
    #{id := IdToken0 } = TokenMap,
    case oidcc_token:validate_id_token(IdToken0, OpenIdProvider, Nonce) of
        {ok, IdToken} ->
           {ok, maps:put(id, IdToken, TokenMap)};
        Other -> Other
    end.

retrieve_user_info(#{access := AccessToken}, OpenIdProvider) ->
    #{token := Token} = AccessToken,
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(#{token := Token}, OpenIdProvider) ->
    retrieve_user_info(Token, OpenIdProvider);
retrieve_user_info(Token, #{userinfo_endpoint := Endpoint})
  when is_binary(Token) ->
    Header = [{<<"authorization">>, << <<"Bearer ">>/binary, Token/binary >>}],
    return_user_info(http_get(Endpoint, Header));
retrieve_user_info(Token, OpenIdProvider) ->
    {ok, Config} = get_openid_provider_info(OpenIdProvider),
    retrieve_user_info(Token, Config).


return_user_info({ok, #{status := 200, body := Data}}) ->
    try jsx:decode(Data, [{labels, attempt_atom}, return_maps])
    of Map -> {ok, Map}
    catch Error -> {error, Error}
    end;
return_user_info({ok, Map}) ->
    {error, {bad_status, Map}};
return_user_info({error, _}=Error) ->
    Error.


http_get(Url, Header) ->
    Uri = uri:from_string(Url),
    Host= binary:bin_to_list(uri:host(Uri)),
    Port0 = uri:port(Uri),
    Scheme = uri:scheme(Uri),
    Config = scheme_to_map(Scheme),
    Path = binary:bin_to_list(uri:path(Uri)),
    Port = ensure_port(Port0, Scheme),
    {ok, ConPid} = gun:open(Host, Port, Config),
    {ok, _Protocol} = gun:await_up(ConPid),
    StreamRef = gun:get(ConPid, Path, Header),
    ok = gun:shutdown(ConPid),
    {Status, Headers, Body} =
    case gun:await(ConPid, StreamRef) of
        {response, fin, S, H} ->
            {S, H, <<>>};
        {response, nofin, S, H} ->
            {ok, B} = gun:await_body(ConPid, StreamRef),
            {S, H, B}
    end,
    {ok, #{status => Status, header => Headers, body => Body }}.

http_post(Url, Header, Body) ->
    Uri = uri:from_string(Url),
    Host= binary:bin_to_list(uri:host(Uri)),
    Port0 = uri:port(Uri),
    Scheme = uri:scheme(Uri),
    Config = scheme_to_map(Scheme),
    Path = binary:bin_to_list(uri:path(Uri)),
    Port = ensure_port(Port0, Scheme),
    {ok, ConPid} = gun:open(Host, Port, Config),
    {ok, _Protocol} = gun:await_up(ConPid),
    StreamRef = gun:post(ConPid, Path, Header, Body),
    ok = gun:shutdown(ConPid),
    {Status, Headers, InBody} =
    case gun:await(ConPid, StreamRef) of
        {response, fin, S, H} ->
            {S, H, <<>>};
        {response, nofin, S, H} ->
            {ok, B} = gun:await_body(ConPid, StreamRef),
            {S, H, B}
    end,
    {ok, #{status => Status, header => Headers, body => InBody }}.

scheme_to_map(<<"http">>) ->
    #{};
scheme_to_map(<<"https">>) ->
    #{transport => ssl};
scheme_to_map(_) ->
    #{transport => ssl}.


ensure_port(undefined, <<"http">>) ->
    80;
ensure_port(undefined, <<"https">>) ->
    443;
ensure_port(Port, _) when is_number(Port) ->
    Port;
ensure_port(_Port, _)  ->
    443.
