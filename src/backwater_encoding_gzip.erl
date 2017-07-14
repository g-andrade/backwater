-module(backwater_encoding_gzip).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(iodata()) -> binary().
encode(Data) ->
    zlib:gzip(Data).

-spec decode(iodata()) -> {ok, binary()} | {error, term()}.
decode(Data) ->
    try
        {ok, zlib:gunzip(Data)}
    catch
       error:Reason ->
            {error, Reason}
    end.
