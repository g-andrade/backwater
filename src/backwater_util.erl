%% @private
-module(backwater_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([copies/2]).
-export([latin1_binary_to_lower/1]).
-export([latin1_binary_trim_whitespaces/1]).
-export([lists_allmap/2]).
-export([lists_anymap/2]).
-export([lists_enumerate/1]).
-export([maps_mapfold/3]).
-export([maps_merge/1]).
-export([maps_merge_with/3]).
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

-spec latin1_binary_to_lower(binary()) -> binary().
latin1_binary_to_lower(Bin) ->
    list_to_binary( string:to_lower( binary_to_list(Bin) ) ).

-spec latin1_binary_trim_whitespaces(binary()) -> binary().
latin1_binary_trim_whitespaces(Bin) ->
    re:replace(Bin, <<"(^\\s+)|(\\s+$)">>, <<>>, [global, {return, binary}]).

-spec lists_allmap(Fun :: fun((term()) -> {boolean(), term()} | boolean()), [term()])
        -> {true, [term()]} | {false, term()}.
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

-spec maps_merge_with(fun ((term(), term(), term()) -> term()), map(), map()) -> map().
maps_merge_with(Fun, Map1, Map2) ->
    List1 = lists:keysort(1, maps:to_list(Map1)),
    List2 = lists:keysort(1, maps:to_list(Map2)),
    maps_merge_with_recur(Fun, List1, List2, []).

-spec proplists_sort_and_merge(proplist(), proplist()) -> proplist().
proplists_sort_and_merge(List1, List2) ->
    SortedList1 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List1)),
    SortedList2 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List2)),
    lists:umerge(fun proplists_element_cmp/2, SortedList2, SortedList1).

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

-spec lists_allmap_recur(Fun :: fun((term()) -> {boolean(), term()} | boolean()), [term()], [term()])
        -> {true, [term()]} | {false, term()}.
lists_allmap_recur(_Fun, [], Acc) ->
    {true, lists:reverse(Acc)};
lists_allmap_recur(Fun, [H|T], Acc) ->
    case Fun(H) of
        {true, MappedH} -> lists_allmap_recur(Fun, T, [MappedH | Acc]);
        true -> lists_allmap_recur(Fun, T, [H | Acc]);
        {false, MappedH} -> {false, MappedH};
        false -> {false, H}
    end.

-spec maps_merge_with_recur(fun ((term(), term(), term()) -> term()),
                            [{term(), term()}], [{term(), term()}], [{term(), term()}])
        -> map().
maps_merge_with_recur(Fun, [{K1,V1}|T1], [{K2,_}|_] = L2, Acc)
  when K1 < K2 ->
    % List1 is lagging behind
    NewAcc = [{K1,V1} | Acc],
    maps_merge_with_recur(Fun, T1, L2, NewAcc);
maps_merge_with_recur(Fun, [{K1,V1}|T1], [{K2,V2}|T2], Acc)
  when K1 =:= K2 ->
    % a common key - merge the values
    MergedV = Fun(K1, V1, V2),
    NewAcc = [{K1,MergedV} | Acc],
    maps_merge_with_recur(Fun, T1, T2, NewAcc);
maps_merge_with_recur(Fun, [{K1,_}|_] = L1, [{K2,V2}|T2], Acc)
  when K1 > K2 ->
    % List2 is lagging behind
    NewAcc = [{K2,V2} | Acc],
    maps_merge_with_recur(Fun, L1, T2, NewAcc);
maps_merge_with_recur(_Fun, [], L2, Acc) ->
    % List1 is over
    maps:from_list(L2 ++ Acc);
maps_merge_with_recur(_Fun, L1, [], Acc) ->
    % List2 is over
    maps:from_list(L1 ++ Acc).
-spec proplists_element_cmp(proplists:property(), proplists:property()) -> boolean().
proplists_element_cmp(A, B) ->
    proplists_element_key(A) =< proplists_element_key(B).

-spec proplists_element_key(proplists:property()) -> atom().
proplists_element_key(Atom) when is_atom(Atom) ->
    Atom;
proplists_element_key({Atom, _Value}) when is_atom(Atom) ->
    Atom.
