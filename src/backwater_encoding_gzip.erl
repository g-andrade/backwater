-module(backwater_encoding_gzip).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec decode(iodata()) -> {ok, iodata()} | {error, term()}.
decode(Data) ->
    try
        {ok, zlib:gunzip(Data)}
    catch
       error:Reason ->
            {error, Reason}
    end.
