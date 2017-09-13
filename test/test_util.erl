-module(test_util).

-export([wait_for_process_to_die/2]).
-export([wait_for_true/2]).
-export([meck_new/1]).
-export([meck_done/1]).


wait_for_process_to_die(_Pid, 0) ->
    still_alive;
wait_for_process_to_die(Pid, Iterations) ->
    case process_info(Pid) of
        undefined ->
            ok;
        _ ->
            timer:sleep(10),
            wait_for_process_to_die(Pid, Iterations-1)
    end.


wait_for_true(_Fun, 0) ->
    failed;
wait_for_true(Fun, Iterations) ->
    case Fun() of
        true ->
            ok;
        _ ->
            timer:sleep(10),
            wait_for_true(Fun, Iterations-1)
    end.



meck_new([]) ->
    ok;
meck_new([Module | T]) ->
    meck:new(Module),
    meck_new(T).

meck_done([]) ->
    ok;
meck_done([Module | T]) ->
    true = meck:validate(Module),
    meck:unload(Module),
    meck_done(T).
