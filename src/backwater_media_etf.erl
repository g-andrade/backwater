%% @private
-module(backwater_media_etf).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

%% TODO: use content-type parameters for negotiating this
-define(MINOR_VERSION, 1).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(term()) -> binary().
encode(Term) ->
    erlang:term_to_binary(Term, [{minor_version, ?MINOR_VERSION}]).

-spec decode(binary(), boolean()) -> {ok, term()} | error.
decode(Binary, DecodeUnsafeTerms) when DecodeUnsafeTerms ->
    decode_(Binary, []);
decode(Binary, DecodeUnsafeTerms) when not DecodeUnsafeTerms ->
    decode_(Binary, [safe]).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec decode_(binary(), [safe]) -> {ok, term()} | error.
decode_(Binary, Options) ->
    try
        {ok, erlang:binary_to_term(Binary, Options)}
    catch
        error:badarg ->
            error
    end.
