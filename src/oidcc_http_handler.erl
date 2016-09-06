-module(oidcc_http_handler).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

-record(state, {
          request_type = bad,
          code = undefined,
          error = undefined,
          state = undefined,
          provider = undefined,

          session = undefined,
          peer_ip = undefined,
          user_agent = undefined,
          referer = undefined,
          client_mod = undefined,
          use_cookie = undefined,
          cookie_data = undefined
         }).

-define(COOKIE, <<"oidcc_session">>).

init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ -> {ok, Req, #state{}}
    end.

handle(Req, #state{request_type = redirect} = State) ->
    %% redirect the client to the given provider Id
    %% set the cookie
    handle_redirect(State, Req);
handle(Req, #state{request_type = return,
                   error = undefined
                  } = State) ->
    %% the user comes back from the OpenId Connect Provider
    handle_return(Req, State);
handle(Req, #state{request_type = return, error=Desc} = State) ->
    %% the user comes back from the OpenId Connect Provider with an error
    %% redirect him to the
    Error = oidc_provider_error,
    handle_fail(Error, Desc, Req, State);
handle(Req, #state{request_type = bad_request, error=Desc} = State) ->
    Error = bad_request,
    handle_fail(Error, Desc, Req, State).

handle_redirect(#state{
                   session = Session,
                   user_agent = UserAgent,
                   peer_ip = PeerIp,
                   client_mod = ClientModId,
                   use_cookie = UseCookie
                  } = State, Req) ->
    ok = oidcc_session:set_user_agent(UserAgent, Session),
    ok = oidcc_session:set_peer_ip(PeerIp, Session),
    ok = oidcc_session:set_client_mod(ClientModId, Session),
    {ok, Url} = oidcc:create_redirect_for_session(Session),
    CookieUpdate = cookie_update_if_requested(UseCookie, Session),
    Redirect = {redirect, Url},
    Updates = [CookieUpdate, Redirect],
    {ok, Req2} = apply_updates(Updates, Req),
    {ok, Req2, State}.



handle_return(Req, #state{code = AuthCode,
                          session = Session,
                          user_agent = UserAgent,
                          peer_ip = PeerIp,
                          cookie_data = CookieData
                         } = State) ->
    {ok, Provider} = oidcc_session:get_provider(Session),
    {ok, Pkce} = oidcc_session:get_pkce(Session),
    {ok, Token} = oidcc:retrieve_token(AuthCode, Pkce, Provider),
    {ok, Nonce} = oidcc_session:get_nonce(Session),
    IsUserAgent = oidcc_session:is_user_agent(UserAgent, Session),
    CheckUserAgent = application:get_env(oidcc, check_user_agent, true),
    IsPeerIp = oidcc_session:is_peer_ip(PeerIp, Session),
    CheckPeerIp = application:get_env(oidcc, check_peer_ip, true),
    CookieValid = oidcc_session:is_cookie_data(CookieData, Session),
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),

    UserAgentValid = ((not CheckUserAgent) or IsUserAgent),
    PeerIpValid = ((not CheckPeerIp) or IsPeerIp),
    TokenResult = oidcc:parse_and_validate_token(Token, Provider,
                                                         Nonce),
    try check_token_and_fingerprint(TokenResult, UserAgentValid,
                                    PeerIpValid, CookieValid) of
        {ok, VerifiedToken0} ->
            {ok, VerifiedToken} = add_userinfo_if_configured(VerifiedToken0,
                                                             Provider),
            {ok, Req2} = close_session_delete_cookie(Session, Req),
            {ok, UpdateList} = oidcc_client:succeeded(VerifiedToken,
                                                      ClientModId),
            {ok, Req3} = apply_updates(UpdateList, Req2),
            {ok, Req3, State}
    catch Error ->
            handle_fail(internal, Error, Req, State)
    end.


add_userinfo_if_configured(Token, Provider) ->
    GetUserInfo = application:get_env(oidcc, retrieve_userinfo, false),
    add_userinfo_to_token(GetUserInfo, Token, Provider).
add_userinfo_to_token(false, Token, _Provider) ->
    {ok, Token};
add_userinfo_to_token(true, Token, Provider) ->
    Result = oidcc:retrieve_user_info(Token, Provider),
    insert_userinfo_in_token(Result, Token).
insert_userinfo_in_token({ok, UserInfo}, Token) ->
    {ok, maps:put(user_info, UserInfo, Token)};
insert_userinfo_in_token( _, Token) ->
    {ok, maps:put(user_info, #{}, Token)}.



check_token_and_fingerprint({ok, VerifiedToken}, true, true, true) ->
    {ok, VerifiedToken};
check_token_and_fingerprint(_, true, true, true) ->
    throw(token_invalid);
check_token_and_fingerprint(_, false, _, _) ->
    throw(bad_user_agent);
check_token_and_fingerprint(_, _, false, _) ->
    throw(bad_peer_ip);
check_token_and_fingerprint(_, _, _, false) ->
    throw(bad_cookie).


handle_fail(Error, Desc, Req, #state{
                                 session = undefined
                                } = State) ->
    {ok, UpdateList} = oidcc_client:failed(Error, Desc, default),
    {ok, Req2} = apply_updates(UpdateList, Req),
    {ok, Req2, State};
handle_fail(Error, Desc, Req, #state{
                                 session = Session
                                } = State) ->
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),
    {ok, Req2} = close_session_delete_cookie(Session, Req),
    {ok, UpdateList} = oidcc_client:failed(Error, Desc, ClientModId),
    {ok, Req3} = apply_updates(UpdateList, Req2),
    {ok, Req3, State}.

apply_updates([], Req) ->
    {ok, Req};
apply_updates([{redirect, Url}|T], Req) ->
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    apply_updates(T, Req2);
apply_updates([{cookie, Name, Data, Options} | T], Req) ->
    Req2 = cowboy_req:set_resp_cookie(Name, Data, Options, Req),
    apply_updates(T, Req2);
apply_updates([{none} | T], Req) ->
    apply_updates(T, Req).


cookie_update_if_requested(true, Session) ->
    CookieData =  base64url:encode(crypto:strong_rand_bytes(32)),
    ok = oidcc_session:set_cookie_data(CookieData, Session),
    MaxAge = application:get_env(oidcc, session_max_age, 600),
    {cookie, ?COOKIE, CookieData, cookie_opts(MaxAge)};
cookie_update_if_requested(_, _Session) ->
    {none}.


close_session_delete_cookie(undefined, Req) ->
    {ok, Req};
close_session_delete_cookie(Session, Req) ->
    HasCookie = not oidcc_session:is_cookie_data(undefined, Session),
    ok = oidcc_session:close(Session),
    case HasCookie of
        true ->
            apply_updates([clear_cookie()], Req);
        false ->
            {ok, Req}
    end.

clear_cookie() ->
    {cookie, ?COOKIE, <<"deleted">>, cookie_opts(0)}.

cookie_opts(MaxAge) ->
    BasicOpts = [ {http_only, true}, {max_age, MaxAge}, {path, <<"/">>}],
    add_secure(application:get_env(oidcc, secure_cookie, false), BasicOpts).

add_secure(true, BasicOpts) ->
    [{secure, true} | BasicOpts];
add_secure(_, BasicOpts) ->
    BasicOpts.

terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {QsList, Req1} = cowboy_req:qs_vals(Req),
    {ok, BodyQsList, Req2} = cowboy_req:body_qs(Req1),
    {Headers, Req3} = cowboy_req:headers(Req2),
    {Method, Req4} = cowboy_req:method(Req3),
    {CookieData, Req5} = cowboy_req:cookie(?COOKIE, Req4),
    {{PeerIP, _Port}, Req99} = cowboy_req:peer(Req5),

    QsMap = create_map_from_proplist(QsList ++ BodyQsList),
    SessionId = maps:get(state, QsMap, undefined),

    UserAgent = get_header(<<"user-agent">>, Headers),
    Referer = get_header(<<"referer">>, Headers),
    Referer = get_header(<<"referer">>, Headers),
    NewState = #state{
                  peer_ip = PeerIP,
                  user_agent = UserAgent,
                  referer = Referer
                 },
    ProviderId0  = maps:get(provider, QsMap, undefined),
    ProviderId = validate_provider(ProviderId0),
    case ProviderId of
        undefined ->
            Method = <<"GET">>,
            {ok, Session} = oidcc_session_mgr:get_session(SessionId),
            Code = maps:get(code, QsMap, undefined),
            Error = maps:get(error, QsMap, undefined),
            State = maps:get(state, QsMap, undefined),
            ClientModId = maps:get(client_mod, QsMap, undefined),
            {ok, Req99, NewState#state{request_type=return,
                                       session = Session,
                                       code = Code,
                                       error = Error,
                                       state = State,
                                       client_mod = ClientModId,
                                       cookie_data = CookieData
                                      }};
        bad_provider ->
            Desc = <<"unknown provider id">>,
            {ok, Req99, NewState#state{request_type=bad_request,
                                       error = Desc
                                      }};
        ProviderId ->
            {ok, Session} = oidcc_session_mgr:new_session(ProviderId),
            CookieDefault = application:get_env(oidcc, use_cookie, false),
            UseCookie = maps:is_key(use_cookie, QsMap) or CookieDefault,
            {ok, Req99, NewState#state{request_type = redirect,
                                       session = Session,
                                       use_cookie = UseCookie}}
    end.

validate_provider(ProviderId) ->
    case oidcc:get_openid_provider_info(ProviderId) of
        {ok, _ } ->
            ProviderId;
        _ ->
            bad_provider
    end.

-define(QSMAPPING, [
                    {<<"code">>, code},
                    {<<"error">>, error},
                    {<<"state">>, state},
                    {<<"provider">>, provider},
                    {<<"client_mod">>, client_mod},
                    {<<"use_cookie">>, use_cookie}
                   ]).

create_map_from_proplist(List) ->
    KeyToAtom = fun({Key, Value}, Map) ->
                        NewKey = map_to_atom(Key, ?QSMAPPING),
                        maps:put(NewKey, Value, Map)
                end,
    lists:foldl(KeyToAtom, #{}, List).

map_to_atom(Key, Mapping) ->
    case lists:keyfind(Key, 1, Mapping) of
        {Key, AKey} ->
            AKey;
        _ ->
            Key
    end.

get_header(Key, Headers) ->
    case lists:keyfind(Key, 1, Headers) of
        {Key, Value} -> Value;
        false -> undefined
    end.
