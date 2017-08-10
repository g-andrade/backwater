-module(backwater_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([basic_test/1]).

all() ->
    application:ensure_all_started(backwater),
    [basic_test].

init_per_suite(Config) ->
    ServerConfig =
        #{ secret => <<"foobar">>,
           exposed_modules => [{erlang, [{exports, all}]}] },
    {ok, _Pid} = backwater_server:start_clear(ref, [], #{}, ServerConfig),

    ClientConfig =
        #{ endpoint => <<"http://127.0.0.1:8080">>,
           secret => <<"foobar">> },
    ok = backwater_client:start(ref, ClientConfig),
    Config.

end_per_suite(Config) ->
    ok = backwater_server:stop_listener(ref),
    ok = backwater_client:stop(ref),
    Config.

basic_test(_Config) ->
    A = rand:uniform(1000),
    B = rand:uniform(1000),
    C = A * B,
    ?assertEqual({ok, C}, backwater_client:call(ref, "1", erlang, '*', [A, B])),
    ok.
