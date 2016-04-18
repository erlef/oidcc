-module(test_util).

-export([wait_for_process_to_die/2]).


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
