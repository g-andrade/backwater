-module(backwater_util).

-export([parse_unicode_string/1]).
-export([string_tokens_n/3]).
-export([iolist_to_list/1]).
-export([kvlists_merge/2]).

parse_unicode_string(Atom) when is_atom(Atom) ->
    atom_to_list(Atom);
parse_unicode_string(Other) ->
    case catch io_lib:format("~s", [Other]) of
        List when is_list(List) ->
            Binary = iolist_to_binary(List),
            unicode:characters_to_list(Binary);
        {'EXIT', '_'} ->
            io_lib:format("~p", [Other])
    end.

string_tokens_n(String, SeparatorList, N) ->
    string_tokens_n_recur(String, SeparatorList, N, []).

string_tokens_n_recur(String, _SeparatorList, N, TokensAcc)
  when String =:= [] orelse N < 2 ->
    lists:reverse(TokensAcc) ++ [String];
string_tokens_n_recur(String, SeparatorList, N, TokensAcc) ->
    IsSeparator = fun (C) -> lists:member(C, SeparatorList) end,
    {Token, Remaining} = lists:splitwith(fun (C) -> not IsSeparator(C) end, String),
    Trimmed = lists:dropwhile(fun (C) -> IsSeparator(C) end, Remaining),
    case Token =:= [] of
        true ->
            % empty token
            string_tokens_n_recur(Trimmed, SeparatorList, N, TokensAcc);
        false ->
            string_tokens_n_recur(Trimmed, SeparatorList, N - 1, [Token | TokensAcc])
    end.

iolist_to_list(IoData) ->
    binary_to_list(iolist_to_binary(IoData)).

kvlists_merge(KVList, [{K,V} | T]) ->
    kvlists_merge(lists:keystore(K, 1, KVList, {K,V}), T);
kvlists_merge(KVList, []) ->
    KVList.

