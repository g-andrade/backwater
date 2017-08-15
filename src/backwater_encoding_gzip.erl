%% @private
-module(backwater_encoding_gzip).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/1]).
-export([decode/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

% taken from zlib.erl at Erlang/OTP source code
-define(MAX_WBITS, 15).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(iodata()) -> binary().
encode(Data) ->
    zlib:gzip(Data).

-spec decode(iodata(), non_neg_integer()) -> {ok, binary()} | {error, term()}.
decode(Data, MaxUncompressedSize) ->
    Z = zlib:open(),
    try
        zlib:inflateInit(Z, 16 + ?MAX_WBITS),
        zlib:setBufSize(Z, MaxUncompressedSize),
        case zlib:inflateChunk(Z, Data) of
            {more, _Chunk} ->
                {error, too_big};
            UncompressedIoData ->
                zlib:inflateEnd(Z),
                UncompressedData = iolist_to_binary(UncompressedIoData),
                true = (byte_size(UncompressedData) =< MaxUncompressedSize),
                {ok, UncompressedData}
        end
    catch
        error:Reason ->
            {error, Reason}
    after
        zlib:close(Z)
    end.
