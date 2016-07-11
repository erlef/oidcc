-module(oidcc_http_handler).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

-define(COOKIE, <<"oidcc_session">>).

-record(state, {
          request_type = bad,
          code = undefined,
          error = undefined,
          state = undefined,
          provider = undefined,

          session = undefined,
          peer = undefined,
          user_agent = undefined,
          referer = undefined
         }).


init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ -> {ok, Req, #state{}}
    end.

handle(Req, #state{request_type = redirect,
                   provider = ProviderId,
                   session = Session
                  } = State) ->
    %% redirect the client to the given provider Id
    %% set the cookie
    {ok, Url} = oidcc:create_redirect_for_session(Session, ProviderId),
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cookie(update, Req, Session),
    {ok, Req3} = cowboy_req:reply(302, Header, Req2),
    {ok, Req3, State};
handle(Req, #state{request_type = return,
                   error = undefined,
                   code = AuthCode,
                   session = Session,
                   state = OidcState} = State) ->

    try handle_return(AuthCode, Session, OidcState, State, Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch _:_ ->
            Error = internal,
            Desc = <<"an internal error occured">>,
            handle_fail(Error, Desc, Req, State)
    end;
handle(Req, #state{request_type = return} = State) ->
    %% the user comes back from the OpenId Provider with an error
    %% redirect him to the
    Error = oidc_provider_error,
    Desc = <<"the oidc provider returned an error">>,
    handle_fail(Error, Desc, Req, State).

handle_return(AuthCode, Session, OidcState, State, Req) ->
    true = oidcc_session:is_state(OidcState, Session),
    {ok, Provider} = oidcc_session:get_provider(Session),
    {ok, Token} = oidcc:retrieve_token(AuthCode, Provider),
    {ok, Nonce} = oidcc_session:get_nonce(Session),
    {ok, VerifiedToken} = oidcc:parse_and_validate_token(Token, Provider,
                                                         Nonce),
    {ok, Req2} = cookie(clear, Req, Session),
    ok = oidcc_session:close(Session),
    {ok, CookieName, CookieData, Path} = oidcc_client:succeeded(VerifiedToken),
    redirect_and_maybe_set_cookie(CookieName, CookieData, Path, Req2, State).


redirect_and_maybe_set_cookie(undefined, undefined, Path, Req, State) ->
    Header = [{<<"location">>, Path}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    {ok, Req2, State};
redirect_and_maybe_set_cookie(CookieName, CookieData, Path, Req, State) ->
    Opts = cookie_opts(60),
    Req2 = cowboy_req:set_resp_cookie(CookieName, CookieData, Opts, Req),
    redirect_and_maybe_set_cookie(undefined, undefined, Path, Req2, State).

handle_fail(Error, Desc, Req, State) ->
    {ok, CookieName, CookieData, Path} = oidcc_client:failed(Error, Desc),
    redirect_and_maybe_set_cookie(CookieName, CookieData, Path, Req, State).


terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {QsList, Req1} = cowboy_req:qs_vals(Req),
    {CookieSessionId, Req2} = cowboy_req:cookie(?COOKIE, Req1),
    {Headers, Req3} = cowboy_req:headers(Req2),
    {<<"GET">>, Req4} = cowboy_req:method(Req3),
    {{PeerIP, _Port}, Req99} = cowboy_req:peer(Req4),

    {ok, Session} = oidcc_session_mgr:get_session(CookieSessionId),
    QsMap = create_map_from_proplist(QsList),
    UserAgent = get_header(<<"user-agent">>, Headers),
    Referer = get_header(<<"referer">>, Headers),
    NewState = #state{
                  session = Session,
                  peer = PeerIP,
                  user_agent = UserAgent,
                  referer = Referer
                 },
    case maps:get(provider, QsMap, undefined) of
        undefined ->
            Code = maps:get(code, QsMap, undefined),
            Error = maps:get(error, QsMap, undefined),
            State = maps:get(state, QsMap, undefined),
            {ok, Req99, NewState#state{request_type=return,
                                       code = Code,
                                       error = Error,
                                       state = State}};
        Value ->
            oidcc_session:set_provider(Value, Session),
            {ok, Req99, NewState#state{request_type = redirect,
                                       provider = Value}}
    end.

cookie(clear, Req, _Session) ->
    Opts = cookie_opts(0),
    Req2 = cowboy_req:set_resp_cookie(?COOKIE, <<"deleted">>, Opts, Req),
    {ok, Req2};
cookie(update, Req, Session) ->
    MaxAge = application:get_env(oidcc, session_max_age, 600),
    {ok, ID} = oidcc_session:get_id(Session),
    Opts = cookie_opts(MaxAge),
    Req2 = cowboy_req:set_resp_cookie(?COOKIE, ID, Opts, Req),
    {ok, Req2}.

cookie_opts(MaxAge) ->
    BasicOpts = [ {http_only, true}, {max_age, MaxAge}, {path, <<"/">>}],
    add_secure(application:get_env(oidcc, secure_cookie), BasicOpts).

add_secure(true, BasicOpts) ->
    [{secure, true} | BasicOpts];
add_secure(_, BasicOpts) ->
    BasicOpts.


-define(QSMAPPING, [
                    {<<"code">>, code},
                    {<<"error">>, error},
                    {<<"state">>, state},
                    {<<"provider">>, provider}
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
