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
-export([proplists_sort_and_merge/1]).
-export([proplists_sort_and_merge/2]).
-export([purge_stacktrace_below/2]).
-export([validate_config_map/3]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type proplist() :: [proplists:property()].
-export_type([proplist/0]).

-type config_validation_error() ::
    {invalid_config_parameter, {Key :: term(), Value :: term()}} |
    {missing_mandatory_config_parameters, [Key :: term(), ...]} |
    config_not_a_map.
-export_type([config_validation_error/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec copies(term(), non_neg_integer()) -> [term()].
%% @private
copies(_Value, 0) ->
    [];
copies(Value, Count) ->
    copies_recur([Value], Count).

-spec latin1_binary_to_lower(binary()) -> binary().
%% @private
latin1_binary_to_lower(Bin) ->
    list_to_binary( string:to_lower( binary_to_list(Bin) ) ).

-spec latin1_binary_trim_whitespaces(binary()) -> binary().
%% @private
latin1_binary_trim_whitespaces(Bin) ->
    re:replace(Bin, <<"(^\\s+)|(\\s+$)">>, <<>>, [global, {return, binary}]).

-spec lists_allmap(Fun :: fun((term()) -> {boolean(), term()} | boolean()), [term()])
        -> {true, [term()]} | {false, term()}.
%% @private
lists_allmap(Fun, List) ->
    lists_allmap_recur(Fun, List, []).

-spec lists_anymap(Fun :: fun((term()) -> {true, term()} | true | false), [term()])
        -> {true, term()} | false.
%% @private
lists_anymap(_Fun, []) ->
    false;
lists_anymap(Fun, [H|T]) ->
    case Fun(H) of
        {true, MappedH} -> {true, MappedH};
        true -> {true, H};
        false -> lists_anymap(Fun, T)
    end.

-spec lists_enumerate([term()]) -> [{pos_integer(), term()}].
%% @private
lists_enumerate(List) ->
    lists:zip(lists:seq(1, length(List)), List).

-spec maps_mapfold(fun ((term(), term(), term()) -> {term(), term()}),
                   term(), map()) -> {map(), term()}.
%% @private
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
%% @private
maps_merge(Maps) ->
    lists:foldl(fun (Map2, Map1) -> maps:merge(Map1, Map2) end, #{}, Maps).

-spec proplists_sort_and_merge([proplist()]) -> proplist().
%% @private
proplists_sort_and_merge([]) ->
    [];
proplists_sort_and_merge([H | T]) ->
    SortedH = lists:usort(fun proplists_element_cmp/2, lists:reverse(H)),
    lists:foldl(
      fun (List, Acc) ->
              SortedList = lists:usort(fun proplists_element_cmp/2, lists:reverse(List)),
              lists:umerge(fun proplists_element_cmp/2, SortedList, Acc)
      end,
      SortedH, T).

-spec proplists_sort_and_merge(proplist(), proplist()) -> proplist().
%% @private
proplists_sort_and_merge(List1, List2) ->
    SortedList1 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List1)),
    SortedList2 = lists:usort(fun proplists_element_cmp/2, lists:reverse(List2)),
    lists:umerge(fun proplists_element_cmp/2, SortedList2, SortedList1).

-spec purge_stacktrace_below({module(),atom(),arity()}, [erlang:stack_item()])
        -> [erlang:stack_item()].
%% @private
purge_stacktrace_below(MarkerMFA, Stacktrace) ->
    lists:takewhile(
      fun ({M,F,A,_Location}) -> {M,F,A} =/= MarkerMFA end,
      Stacktrace).

-spec validate_config_map(term(), MandatoryKeys, PairValidationFun)
        -> {ok, ValidConfig} | {error, Error}
            when MandatoryKeys :: [term()],
                 PairValidationFun :: fun (({term(), term()}) -> {boolean() | MappedValue} | boolean()),
                 MappedValue :: term(),
                 ValidConfig :: map(),
                 Error :: config_validation_error().
%% @private
validate_config_map(Config, MandatoryKeys, PairValidationFun) when is_map(Config) ->
    MissingKeys = MandatoryKeys -- maps:keys(Config),
    case MandatoryKeys -- maps:keys(Config) of
        [] ->
            ConfigList = maps:to_list(Config),
            ValidationResult = lists_allmap(PairValidationFun, ConfigList),
            case ValidationResult of
                {true, ValidatedConfigList} ->
                    {ok, maps:from_list(ValidatedConfigList)};
                {false, InvalidSetting} ->
                    {error, {invalid_config_parameter, InvalidSetting}}
            end;
        MissingKeys ->
            {error, {missing_mandatory_config_parameters, lists:usort(MissingKeys)}}
    end;
validate_config_map(_Config, _MandatoryKeys, _PairValidationFun) ->
    {error, config_not_a_map}.

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

-spec proplists_element_cmp(proplists:property(), proplists:property()) -> boolean().
proplists_element_cmp(A, B) ->
    proplists_element_key(A) =< proplists_element_key(B).

-spec proplists_element_key(proplists:property()) -> atom().
proplists_element_key(Atom) when is_atom(Atom) ->
    Atom;
proplists_element_key({Atom, _Value}) when is_atom(Atom) ->
    Atom.
