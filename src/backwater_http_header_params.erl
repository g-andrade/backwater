-module(backwater_http_header_params).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

encode(Map) ->
    Pairs = maps:to_list(Map),
    SortedPairs = lists:keysort(1, Pairs),
    EncodedPairs = lists:map(fun encode_pair/1, SortedPairs),
    iolist_to_binary(lists:join(",", EncodedPairs)).

decode(Encoded) ->
    EncodedPairs = binary:split(Encoded, <<",">>, [global, trim_all]),
    case backwater_util:lists_allmap(fun decode_pair/1, EncodedPairs) of
        {true, Pairs} ->
            {ok, maps:from_list(Pairs)};
        false ->
            error
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

encode_pair({Key, Value}) ->
    QuotedValue = [$", Value, $"],
    [Key, $=, QuotedValue].

decode_pair(EncodedPair) ->
    case binary:split(EncodedPair, <<"=">>) of
        [Key, QuotedValue] ->
            case unquote_value(QuotedValue) of
                {true, Value} ->
                    {true, {Key, Value}};
                false ->
                    false
            end;
        _ ->
            false
    end.

unquote_value(QuotedValue) when byte_size(QuotedValue) >= 2 ->
    ValueSize = byte_size(QuotedValue) - 2,
    case QuotedValue of
        <<$", Value:ValueSize/binary, $">> ->
            {true, Value};
        _ ->
            false
    end;
unquote_value(_QuotedValue) ->
    false.

