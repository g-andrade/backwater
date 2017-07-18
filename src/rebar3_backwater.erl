-module(rebar3_backwater).

-export([init/1]).

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State0) ->
    rebar3_backwater_prv_generate:init(State0).
