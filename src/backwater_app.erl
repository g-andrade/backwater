%% @private
-module(backwater_app).
-behaviour(application).

%% ------------------------------------------------------------------
%% application Function Exports
%% ------------------------------------------------------------------

-export([start/2]).
-export([stop/1]).

%% ------------------------------------------------------------------
%% application Function Definitions
%% ------------------------------------------------------------------

-spec start(application:start_type(), term()) -> backwater_sup_util:start_link_ret().
start(_StartType, _StartArgs) ->
    backwater_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
