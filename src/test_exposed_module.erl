-module(test_exposed_module).
-export([function1/0]).
-export([function2/0]).
-export([function3/0]).
-export([function5/1]).
%-export([function7/1]).
%-export([parse_function7_json_in/1]).
%-export([parse_function7_json_out/1]).

-backwater_version("1").
-backwater_export({function1,0}).
-backwater_export([{function2,0}]).
-backwater_export({function3,0}).
-backwater_export({function4,0}).
-backwater_export({function5,1}).

%-backwater_export({function7,1, #{ <<"application/json">> => {decode_function7_json_args, encode_function7_json_result} }}).

function1() ->
    [0 || _ <- lists:seq(1, 1000)].

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

%function7(Bla) ->
%    {Bla, Bla}.

%decode_function7_json_args(Value) ->
%    jsx:decode(Value).
%
%encode_function7_json_result({Value1, Value2}) ->
%    jsx:encode([Value1, Value2]).

%%%

int_function() ->
    yeah.
