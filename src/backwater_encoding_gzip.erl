%% Copyright (c) 2017-2021 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

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

-ifndef('OTP_20').
    -ifndef('POST_OTP_20').
        -define(NO_ZLIB_SAFE_INFLATE, 1).
    -else.
        -undef(NO_ZLIB_SAFE_INFLATE).
    -endif.
-else.
    -ifdef('OTP_20.0').
        -define(NO_ZLIB_SAFE_INFLATE, 1).
    -else.
        -undef(NO_ZLIB_SAFE_INFLATE).
    -endif.
-endif.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(iodata()) -> binary().
encode(Data) ->
    zlib:gzip(Data).

-spec decode(iodata(), non_neg_integer()) -> {ok, binary()} | {error, too_big} | {error, term()}.
-ifndef(NO_ZLIB_SAFE_INFLATE).
decode(Data, MaxUncompressedSize) ->
    Z = zlib:open(),
    try
        zlib:inflateInit(Z, 16 + ?MAX_WBITS),
        decode_recur(Z, zlib:safeInflate(Z, Data), [], 0, MaxUncompressedSize)
    catch
        error:Reason ->
            {error, Reason}
    after
        zlib:close(Z)
    end.
-else.
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
-endif.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-ifndef(NO_ZLIB_SAFE_INFLATE).
decode_recur(Z, {Stage,Chunk}, OutputAcc, OutputSize, MaxUncompressedSize)
  when Stage =:= continue;
       Stage =:= finished ->
    UpdatedOutputAcc = [Chunk | OutputAcc],
    UpdatedOutputSize = OutputSize + iolist_size(Chunk),
    case UpdatedOutputSize > MaxUncompressedSize of
        true ->
            {error, too_big};
        _ when Stage =:= continue ->
            decode_recur(Z, zlib:safeInflate(Z, ""), UpdatedOutputAcc,
                         UpdatedOutputSize, MaxUncompressedSize);
        _ ->
            zlib:inflateEnd(Z),
            Output = iolist_to_binary( lists:reverse(UpdatedOutputAcc) ),
            {ok, Output}
    end.
-endif.
