-module(basic_client_http).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).
-export([cookie_name/0]).

-define(COOKIE, <<"basic_client_session">>).

-record(state, {
	  session = undefined
	 }).


cookie_name() ->
    ?COOKIE.

init(_, Req, _Opts) ->
    try extract_args(Req) of
        {ok, Req2, State} -> {ok, Req2, State}
    catch
        _:_ -> {ok, Req, #state{}}
    end.

handle(Req, #state{session = Session } = State) ->
    {ok, Body} = basic_client_dtl:render([{session, Session}]),
    Status = 200,
    %% clear the cookie again, so after a page reload one can retest it.
    Opts = [{max_age, 0},{http_only, true},{path, <<"/">>}],
    Req2 = cowboy_req:set_resp_cookie(?COOKIE, <<"deleted">>, Opts, Req),
    Req3 = cowboy_req:set_resp_body(Body, Req2),
    {ok, Req4} = cowboy_req:reply(Status, Req3),
    {ok, Req4, State}.

terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {Session, Req2} = cowboy_req:cookie(?COOKIE, Req),
    NewState = #state{
		  session = Session
		 },
    {ok, Req2, NewState}.

