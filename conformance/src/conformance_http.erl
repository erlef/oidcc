-module(conformance_http).
-behaviour(cowboy_http_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

-record(state, {
	  test_id = undefined
	 }).



init(_, Req, _Opts) ->
    extract_args(Req).

handle(Req, #state{test_id = undefined } = State) ->
    main_page(Req, State);
handle(Req, #state{test_id = TestId } = State) ->
    Req2 = conformance:run_test(TestId, Req),
    {ok, Req2, State}.


terminate(_Reason, _Req, _State) ->
    ok.

extract_args(Req) ->
    {TestId, Req2} = cowboy_req:qs_val(<<"test">>, Req),
    NewState = #state{
		  test_id = TestId
		 },
    {ok, Req2, NewState}.


main_page(Req, State) ->
    Status = 200,
    {ok, Body} = conformance_dtl:render([]),
    Req3 = cowboy_req:set_resp_body(Body, Req),
    {ok, Req4} = cowboy_req:reply(Status, Req3),
    {ok, Req4, State}.
