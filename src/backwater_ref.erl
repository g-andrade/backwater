-module(backwater_ref).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([to_unicode_string/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

to_unicode_string(Atom) when is_atom(Atom) ->
    atom_to_list(Atom);
to_unicode_string(Other) ->
    case catch io_lib:format("~s", [Other]) of
        List when is_list(List) ->
            Binary = iolist_to_binary(List),
            unicode:characters_to_list(Binary);
        {'EXIT', '_'} ->
            io_lib:format("~p", [Other])
    end.
