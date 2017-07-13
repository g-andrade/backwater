-module(backwater_codec_etf).
-compile(export_all).

decode(Binary, DecodeUnsafeTerms) when DecodeUnsafeTerms ->
    decode_(Binary, []);
decode(Binary, DecodeUnsafeTerms) when not DecodeUnsafeTerms ->
    decode_(Binary, [safe]).

encode(Term) ->
    erlang:term_to_binary(Term, [compressed]).

%%%%
decode_(Binary, Options) ->
    try
        {ok, erlang:binary_to_term(Binary, Options)}
    catch
        error:badarg ->
            error
    end.
