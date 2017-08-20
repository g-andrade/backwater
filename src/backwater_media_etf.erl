%% @copyright 2017 Guilherme Andrade <backwater@gandrade.net>
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
