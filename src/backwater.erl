%% @private
-module(backwater).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Exports
%% ------------------------------------------------------------------

-export([init/1]).                            -ignore_xref({init,1}).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Definitions
%% ------------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State0) ->
    backwater_rebar3_prv_generate:init(State0).
