-module(module_with_backwater_attributes).

-export([exported_functionA/0]).
-export([exported_functionB/1]).
-export([exported_functionC/0]).
-export([exported_functionD/1]).

% single export
-backwater_export({exported_functionA,0}).

% export list
-backwater_export([{exported_functionC,0},
                   {exported_functionD,1},
                   {exported_functionE,0}]).

exported_functionA() ->
    internal_function({foobar}).

exported_functionB(V) ->
    internal_function({V}).

exported_functionC() ->
    internal_function({barfoo}).

exported_functionD(V) ->
    internal_function({V}).

internal_function(V) ->
    V.
