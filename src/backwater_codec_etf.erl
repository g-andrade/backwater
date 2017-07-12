-module(backwater_codec_etf).
-export([decode/2]).
-export([encode/2]).

decode(Binary, DecodeUnsafeTerms) when DecodeUnsafeTerms ->
    decode_(Binary, []);
decode(Binary, DecodeUnsafeTerms) when not DecodeUnsafeTerms ->
    decode_(Binary, [safe]).

encode(Term, RequestedParams) ->
    RawCompressionLevel = proplists:get_value(<<"compressed">>, RequestedParams),
    CompressionLevel = decode_compression_level(RawCompressionLevel),
    Data = erlang:term_to_binary(Term, [{compressed, CompressionLevel}]),
    EncodedParamsSuffix =
        case CompressionLevel =:= 0 of
            true -> <<>>;
            false -> <<"; compressed=", (integer_to_binary(CompressionLevel))/binary>>
        end,
    {Data, EncodedParamsSuffix}.

%%%%
decode_(Binary, Options) ->
    try
        {ok, erlang:binary_to_term(Binary, Options)}
    catch
        error:badarg ->
            error
    end.

decode_compression_level(<<"0">>) -> 0;
decode_compression_level(<<"1">>) -> 1;
decode_compression_level(<<"2">>) -> 2;
decode_compression_level(<<"3">>) -> 3;
decode_compression_level(<<"4">>) -> 4;
decode_compression_level(<<"5">>) -> 5;
decode_compression_level(<<"6">>) -> 6;
decode_compression_level(<<"7">>) -> 7;
decode_compression_level(<<"8">>) -> 8;
decode_compression_level(<<"9">>) -> 9;
decode_compression_level(_) -> 0.
