-module(module_with_custom_attributes).

-export([function1/0]).
-export([function2/0]).

% Only 'function1' will be available to
% call using RPC by default, even with function2
% being exported in a regular fashion.
-backwater_export({function1,0}).


function1() ->
    hello.

function2() ->
    world.
