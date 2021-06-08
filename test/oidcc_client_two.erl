-module(oidcc_client_two).

-export([login_succeeded/1, login_failed/2]).

login_succeeded(_) ->
    ok.

login_failed(_, _) ->
    ok.
