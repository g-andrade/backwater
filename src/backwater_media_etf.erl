-module(backwater_media_etf).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/2]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

encode(Term) ->
    erlang:term_to_binary(Term).

decode(Binary, DecodeUnsafeTerms) when DecodeUnsafeTerms ->
    decode_(Binary, []);
decode(Binary, DecodeUnsafeTerms) when not DecodeUnsafeTerms ->
    decode_(Binary, [safe]).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

decode_(Binary, Options) ->
    try
        {ok, erlang:binary_to_term(Binary, Options)}
    catch
        error:badarg ->
            error
    end.
