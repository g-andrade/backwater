-module(backwater_encoding_gzip).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

decode(Data) ->
    try
        {ok, zlib:gunzip(Data)}
    catch
       error:Reason ->
            {error, Reason}
    end.
