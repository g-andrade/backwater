-module(backwater).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/5]).                            -ignore_xref({call,5}).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Exports
%% ------------------------------------------------------------------

-export([init/1]).                            -ignore_xref({init,1}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec call(Config, Version, Module, Function, Args) -> Result
        when Config :: backwater_client:config(),
             Version :: unicode:chardata(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: backwater_client:result().

call(Config, Version, Module, Function, Args) ->
    backwater_client:call(Config, Version, Module, Function, Args).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Definitions
%% ------------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
%% @private
init(State0) ->
    backwater_rebar3_prv_generate:init(State0).
