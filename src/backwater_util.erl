%% @private
-module(backwater_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([copies/2]).
-export([fast_catch/2]).
-export([latin1_binary_to_lower/1]).
-export([latin1_binary_trim_whitespaces/1]).
-export([lists_allmap/2]).
-export([lists_anymap/2]).
-export([lists_enumerate/1]).
-export([lists_intersect/1]).
-export([maps_mapfold/3]).
-export([maps_merge/1]).
-export([proplists_sort_and_merge/2]).
-export([purge_stacktrace_below/2]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type proplist() :: [proplists:property()].
-export_type([proplist/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec copies(term(), non_neg_integer()) -> [term()].
copies(_Value, 0) ->
    [];
copies(Value, Count) ->
    copies_recur([Value], Count).

-spec fast_catch(Function :: fun ((...) -> term()), Args :: [term()]) -> term().
fast_catch(Function, Args) ->
    try
        apply(Function, Args)
    catch
        Class:Exception ->
            {error, {Class, Exception}}
    end.

-spec latin1_binary_to_lower(binary()) -> binary().
latin1_binary_to_lower(Bin) ->
    % TODO: optimize
    list_to_binary( string:to_lower( binary_to_list(Bin) ) ).

latin1_binary_trim_whitespaces(Bin) ->
    re:replace(Bin, <<"(^\\s+)|(\\s+$)">>, <<>>, [global, {return, binary}]).

lists_allmap(Fun, List) ->
    lists_allmap_recur(Fun, List, []).

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

-spec lists_enumerate([term()]) -> [{pos_integer(), term()}].
lists_enumerate(List) ->
    lists:zip(lists:seq(1, length(List)), List).

-spec lists_intersect([[term()]]) -> [term()].
lists_intersect(Lists) ->
    Ordsets = lists:map(fun ordsets:from_list/1, Lists),
    ordsets:to_list( ordsets:intersection(Ordsets) ).

-spec maps_mapfold(fun ((term(), term(), term()) -> {term(), term()}),
                   term(), map()) -> {map(), term()}.
maps_mapfold(Fun, Acc0, Map) ->
    List = maps:to_list(Map),
    {MappedList, AccN} =
        lists:mapfoldl(
          fun ({K, V1}, Acc1) ->
                  {V2, Acc2} = Fun(K, V1, Acc1),
                  {{K, V2}, Acc2}
          end,
          Acc0,
          List),
    MappedMap = maps:from_list(MappedList),
    {MappedMap, AccN}.

-spec maps_merge([map()]) -> map().
maps_merge(Maps) ->
    lists:foldl(fun (Map2, Map1) -> maps:merge(Map1, Map2) end, #{}, Maps).

-spec proplists_sort_and_merge(proplist(), proplist()) -> proplist().
proplists_sort_and_merge(List1, List2) ->
    SortedList1 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List1)),
    SortedList2 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List2)),
    lists:merge(fun proplists_element_cmp/2, SortedList2, SortedList1).

-spec purge_stacktrace_below({module(),atom(),arity()}, [erlang:stack_item()])
        -> [erlang:stack_item()].
purge_stacktrace_below(MarkerMFA, Stacktrace) ->
    lists:takewhile(
      fun ({M,F,A,_Location}) -> {M,F,A} =/= MarkerMFA end,
      Stacktrace).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec copies_recur([term(), ...], pos_integer()) -> [term(), ...].
copies_recur(Acc, Count) when Count < 2 ->
    Acc;
copies_recur([Value | _] = Acc, Count) ->
    copies_recur([Value | Acc], Count - 1).

lists_allmap_recur(_Fun, [], Acc) ->
    {true, lists:reverse(Acc)};
lists_allmap_recur(Fun, [H|T], Acc) ->
    case Fun(H) of
        {true, MappedH} -> lists_allmap_recur(Fun, T, [MappedH | Acc]);
        true -> lists_allmap_recur(Fun, T, [H | Acc]);
        false -> false
    end.

-spec proplists_element_cmp(proplists:property(), proplists:property()) -> boolean().
proplists_element_cmp(A, B) ->
    proplists_element_key(A) =< proplists_element_key(B).

-spec proplists_element_key(proplists:property()) -> atom().
proplists_element_key(Atom) when is_atom(Atom) ->
    Atom;
proplists_element_key({Atom, _Value}) when is_atom(Atom) ->
    Atom.
