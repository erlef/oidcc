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
          client_mod = undefined
         }).


init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ -> {ok, Req, #state{}}
    end.

handle(Req, #state{request_type = redirect,
                   provider = ProviderId,
                   session = Session,
                   user_agent = UserAgent,
                   peer_ip = PeerIp,
                   client_mod = ClientModId
                  } = State) ->
    %% redirect the client to the given provider Id
    %% set the cookie
    {ok, Req2} = handle_redirect(ProviderId, Session, UserAgent, PeerIp,
                                 ClientModId, Req),
    {ok, Req2, State};
handle(Req, #state{request_type = return,
                   error = undefined
                  } = State) ->
    %% the user comes back from the OpenId Connect Provider
    handle_return(Req, State);
handle(Req, #state{request_type = return, error=Desc} = State) ->
    %% the user comes back from the OpenId Connect Provider with an error
    %% redirect him to the
    Error = oidc_provider_error,
    handle_fail(Error, Desc, Req, State).

handle_redirect(ProviderId, Session, UserAgent, PeerIp, ClientModId, Req) ->
    ok = oidcc_session:set_user_agent(UserAgent, Session),
    ok = oidcc_session:set_peer_ip(PeerIp, Session),
    ok = oidcc_session:set_client_mod(ClientModId, Session),
    {ok, Url} = oidcc:create_redirect_for_session(Session, ProviderId),
    Header = [{<<"location">>, Url}],
    cowboy_req:reply(302, Header, Req).

handle_return(Req, #state{code = AuthCode,
                          session = Session,
                          user_agent = UserAgent,
                          peer_ip = PeerIp
                         } = State) ->
    {ok, Provider} = oidcc_session:get_provider(Session),
    {ok, Token} = oidcc:retrieve_token(AuthCode, Provider),
    {ok, Nonce} = oidcc_session:get_nonce(Session),
    IsUserAgent = oidcc_session:is_user_agent(UserAgent, Session),
    CheckUserAgent = application:get_env(oidcc, check_user_agent, true),
    IsPeerIp = oidcc_session:is_peer_ip(PeerIp, Session),
    CheckPeerIp = application:get_env(oidcc, check_peer_ip, true),
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),

    UserAgentValid = ((not CheckUserAgent) or IsUserAgent),
    PeerIpValid = ((not CheckPeerIp) or IsPeerIp),
    TokenResult = oidcc:parse_and_validate_token(Token, Provider,
                                                         Nonce),
    try check_token_and_fingerprint(TokenResult, UserAgentValid,
                                    PeerIpValid) of
        {ok, VerifiedToken} ->
            ok = oidcc_session:close(Session),
            {ok, UpdateList} = oidcc_client:succeeded(VerifiedToken,
                                                      ClientModId),
            {ok, Req2} = apply_updates(UpdateList, Req),
            {ok, Req2, State}
    catch Error ->
            handle_fail(internal, Error, Req, State)
    end.


check_token_and_fingerprint({ok, VerifiedToken}, true, true) ->
    {ok, VerifiedToken};
check_token_and_fingerprint(_, true, true) ->
    throw(token_invalid);
check_token_and_fingerprint(_, false, _) ->
    throw(bad_user_agent);
check_token_and_fingerprint(_, _, false) ->
    throw(bad_peer_ip).


handle_fail(Error, Desc, Req, #state{
                                 session = Session
                                } = State) ->
    {ok, ClientModId} = oidcc_session:get_client_mod(Session),
    ok = oidcc_session:close(Session),
    {ok, UpdateList} = oidcc_client:failed(Error, Desc, ClientModId),
    {ok, Req2} = apply_updates(UpdateList, Req),
    {ok, Req2, State}.

apply_updates([], Req) ->
    {ok, Req};
apply_updates([{redirect, Url}|T], Req) ->
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    apply_updates(T, Req2);
apply_updates([{cookie, Name, Data, Options} | T], Req) ->
    Req2 = cowboy_req:set_resp_cookie(Name, Data, Options, Req),
    apply_updates(T, Req2).



terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {QsList, Req1} = cowboy_req:qs_vals(Req),
    {Headers, Req2} = cowboy_req:headers(Req1),
    {<<"GET">>, Req3} = cowboy_req:method(Req2),
    {{PeerIP, _Port}, Req99} = cowboy_req:peer(Req3),

    QsMap = create_map_from_proplist(QsList),
    SessionId = maps:get(state, QsMap, undefined),
    {ok, Session} = oidcc_session_mgr:get_session(SessionId),

    UserAgent = get_header(<<"user-agent">>, Headers),
    Referer = get_header(<<"referer">>, Headers),
    NewState = #state{
                  session = Session,
                  peer_ip = PeerIP,
                  user_agent = UserAgent,
                  referer = Referer
                 },
    case maps:get(provider, QsMap, undefined) of
        undefined ->
            Code = maps:get(code, QsMap, undefined),
            Error = maps:get(error, QsMap, undefined),
            State = maps:get(state, QsMap, undefined),
            ClientModId = maps:get(client_mod, QsMap, undefined),
            {ok, Req99, NewState#state{request_type=return,
                                       code = Code,
                                       error = Error,
                                       state = State,
                                       client_mod = ClientModId
                                      }};
        Value ->
            oidcc_session:set_provider(Value, Session),
            {ok, Req99, NewState#state{request_type = redirect,
                                       provider = Value}}
    end.

-define(QSMAPPING, [
                    {<<"code">>, code},
                    {<<"error">>, error},
                    {<<"state">>, state},
                    {<<"provider">>, provider},
                    {<<"client_mod">>, client_mod}
                   ]).

create_map_from_proplist(List) ->
    KeyToAtom = fun({Key, Value}, Map) ->
                        {NewKey, NewVal} = map_to_atoms(Key, Value, ?QSMAPPING),
                        maps:put(NewKey, NewVal, Map)
                end,
    lists:foldl(KeyToAtom, #{}, List).

map_to_atoms(Key, Value, Mapping) ->
    case lists:keyfind(Key, 1, Mapping) of
        {Key, AKey, value} ->
            case lists:keyfind(Value, 1, Mapping) of
                {Value, AValue} ->
                    {AKey, AValue};
                _ ->
                    {AKey, Value}
            end;
        {Key, AKey} ->
            {AKey, Value};
        _ ->
            {Key, Value}
    end.

get_header(Key, Headers) ->
    case lists:keyfind(Key, 1, Headers) of
        {Key, Value} -> Value;
        false -> undefined
    end.
