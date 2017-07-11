-module(test_exposed_module).
-export([function1/0]).
-export([function2/0]).
-export([function3/0]).
-export([function5/1]).

-rpcaller_version("1").
-rpcaller_export([{function2,0}]).
-rpcaller_export({function3,0}).
-rpcaller_export({function4,0}).
-rpcaller_export({function5,1}).

function1() ->
    wow.

function2() ->
    wow2.

function3() ->
    exit(ohhhhh).

function5(V) when V > 0 ->
    function5(V - 1);
function5(V) ->
    function6(V).

function6(Bla) ->
    case rand:uniform(2) of
        1 -> rand:uniform();
        2 -> 3 / Bla
    end.

%%%

int_function() ->
    yeah.
