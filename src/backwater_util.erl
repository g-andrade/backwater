%% Copyright (c) 2017-2018 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(backwater_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([latin1_binary_to_lower/1]).
-export([latin1_binary_trim_whitespaces/1]).
-export([lists_allmap/2]).
-export([lists_anymap/2]).
-export([lists_keyupdate_with/5]).
-export([is_iodata/1]).
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
    options_not_a_map.
-export_type([config_validation_error/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec latin1_binary_to_lower(binary()) -> binary().
%% @private
latin1_binary_to_lower(Bin) ->
    <<<<(string:to_lower(C))>> || <<C>> <= Bin>>.

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

-spec lists_keyupdate_with(term(), pos_integer(), fun ((tuple()) -> tuple()), tuple(), [tuple()])
        -> [tuple(), ...].
%% @private
lists_keyupdate_with(Key, N, Fun, Initial, List) when element(N, Initial) =:= Key ->
    lists_keyupdate_with_recur(Key, N, Fun, Initial, List, []).

-spec is_iodata(term()) -> boolean().
%% @private
is_iodata(Term) ->
    try
        iolist_size(Term) >= 0
    catch
        error:badarg -> false
    end.

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
    {error, options_not_a_map}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

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

-spec lists_keyupdate_with_recur(term(), pos_integer(), fun ((tuple()) -> tuple()), tuple(),
                                 [tuple()], [tuple()])
        -> [tuple(), ...].
lists_keyupdate_with_recur(Key, N, Fun, Initial, [H | T], Acc) ->
    case element(N, H) =:= Key of
        true ->
            % object found; update in place
            Updated = Fun(H),
            true = (element(N, Updated) =:= Key),
            lists:reverse([Updated | Acc], T);
        false ->
            % keep walking the list
            lists_keyupdate_with_recur(Key, N, Fun, Initial, T, [H | Acc])
    end;
lists_keyupdate_with_recur(_Key, _N, _Fun, Initial, [], Acc) ->
    % not found; place initial at end of list
    lists:reverse(Acc, [Initial]).

-spec proplists_element_cmp(proplists:property(), proplists:property()) -> boolean().
proplists_element_cmp(A, B) ->
    proplists_element_key(A) =< proplists_element_key(B).

-spec proplists_element_key(proplists:property()) -> atom().
proplists_element_key(Atom) when is_atom(Atom) ->
    Atom;
proplists_element_key({Atom, _Value}) when is_atom(Atom) ->
    Atom.
