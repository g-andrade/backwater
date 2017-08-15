%% @private
-module(backwater_media_etf).

%% @doc Mostly a wrapper around erlang:{term_to_binary,binary_to_term} that:
%% - transforms exceptions into errors
%% - always encodes using a hardcoded format minor version (currently 1)
%% - refuses to decode compressed payloads as these could be used to
%%   work around existing request and response size limits enforced
%%   both on HTTP and content encoding levels (gzip)

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

%% XXX: We should use content-type parameters for negotiating this.
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
decode_(<<131, 80, _UncompressedSize:32, _CompressedData/binary>>, _Options) ->
    % Refuse to decode compressed payloads
    error;
decode_(Binary, Options) ->
    try
        {ok, erlang:binary_to_term(Binary, Options)}
    catch
        error:badarg ->
            error
    end.
