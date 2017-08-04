-module(backwater_http_header_params).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(#{ binary() => binary() }) -> binary().
encode(Map) ->
    Pairs = maps:to_list(Map),
    SortedPairs = lists:keysort(1, Pairs),
    EncodedPairs = lists:map(fun encode_pair/1, SortedPairs),
    iolist_to_binary(lists:join(",", EncodedPairs)).

-spec decode(binary()) -> {ok, #{ binary() => binary() }} | error.
decode(Encoded) ->
    EncodedPairs = binary:split(Encoded, <<",">>, [global, trim_all]),
    case backwater_util:lists_allmap(fun decode_pair/1, EncodedPairs) of
        {true, Pairs} ->
            {ok, maps:from_list(Pairs)};
        {false, _FailedEncodedPair} ->
            error
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec encode_pair({binary(), binary()}) -> iolist().
encode_pair({Key, Value}) ->
    QuotedValue = [$", Value, $"],
    [Key, $=, QuotedValue].

-spec decode_pair(binary()) -> {true, {binary(), binary()}} | false.
decode_pair(EncodedPair) ->
    case binary:split(EncodedPair, <<"=">>) of
        [Key, QuotedValue] ->
            case unquote_value(QuotedValue) of
                {ok, Value} ->
                    {true, {Key, Value}};
                error ->
                    false
            end;
        _ ->
            false
    end.

-spec unquote_value(binary()) -> {ok, binary()} | error.
unquote_value(QuotedValue) when byte_size(QuotedValue) >= 2 ->
    ValueSize = byte_size(QuotedValue) - 2,
    case QuotedValue of
        <<$", Value:ValueSize/binary, $">> ->
            {ok, Value};
        _ ->
            error
    end;
unquote_value(_QuotedValue) ->
    error.
