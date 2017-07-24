-module(backwater_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([fast_catch/2]).
-export([lists_anymap/2]).
-export([purge_stacktrace_below/2]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec fast_catch(Function :: fun ((...) -> term()), Args :: [term()]) -> term().
fast_catch(Function, Args) ->
    try
        apply(Function, Args)
    catch
        Class:Exception ->
            {error, {Class, Exception}}
    end.

-spec lists_anymap(Fun :: fun((term()) -> {true, term()} | true | false), [term()])
        -> {true, term()} | false.
lists_anymap(_Fun, []) ->
    false;
lists_anymap(Fun, [H|T]) ->
    case Fun(H) of
        {true, MappedH} -> {true, MappedH};
        true -> {true, H};
        false -> lists_anymap(Fun, T)
    end.

-spec purge_stacktrace_below({module(),atom(),arity()}, [erlang:stack_item()])
        -> [erlang:stack_item()].
purge_stacktrace_below(MarkerMFA, Stacktrace) ->
    lists:takewhile(
      fun ({M,F,A,_Location}) -> {M,F,A} =/= MarkerMFA end,
      Stacktrace).
