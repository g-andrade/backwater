-module(rebar3_backwater_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([copies/2]).
-export([lists_anymap/2]).
-export([lists_enumerate/1]).
-export([lists_intersect/1]).
-export([maps_mapfold/3]).
-export([random_ascii_alphanum_string/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

copies(Value, Count) ->
    copies_recur([Value], Count).

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

lists_enumerate(List) ->
    lists:zip(lists:seq(1, length(List)), List).

lists_intersect(Lists) ->
    Ordsets = lists:map(fun ordsets:from_list/1, Lists),
    ordsets:to_list( ordsets:intersection(Ordsets) ).

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

random_ascii_alphanum_string(N) ->
    random_string(
      N,
      {48,49,50,51,52,53,54,55,56,57,65,66,67,68,69,70,71,72,73,
       74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,97,98,99,
       100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,
       115,116,117,118,119,120,121,122}).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

copies_recur(Acc, Count) when Count < 2 ->
    Acc;
copies_recur([Value | _] = Acc, Count) ->
    copies_recur([Value | Acc], Count - 1).

random_string(N, Alphabet) when is_list(Alphabet) ->
    random_string(N, list_to_tuple(Alphabet));
random_string(N, Alphabet) when tuple_size(Alphabet) > 0 ->
    AlphabetSize = tuple_size(Alphabet),
    (fun Recur(M, Acc) when M < 1 ->
             Acc;
         Recur(M, Acc) ->
              Index = rand:uniform(AlphabetSize),
              Char = element(Index, Alphabet),
              Recur(M - 1, [Char | Acc])
     end)(N, []).

