-module(backwater).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/5]).                            -ignore_xref({call,5}).
-export([server_child_spec/3]).               -ignore_xref({server_child_spec,3}).
-export([start_server/2]).                    -ignore_xref({start_server,2}).
-export([stop_server/1]).                     -ignore_xref({stop_server,1}).

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


-spec server_child_spec(Id, Ref, Config) -> ChildSpec
        when Id :: term(),
             Ref :: backwater_cowboy_instance:ref(),
             Config :: backwater_cowboy_instance:config(),
             ChildSpec :: backwater_cowboy_instance:child_spec(Id).

server_child_spec(Id, Ref, Config) ->
    backwater_cowboy_instance:child_spec(Id, Ref, Config).


-spec start_server(Ref, Config) -> Result
        when Ref :: backwater_cowboy_instance:ref(),
             Config :: backwater_cowboy_instance:config(),
             Result :: {ok, pid()} | {error, term()}.

start_server(Ref, Config) ->
    backwater_cowboy_instance:start_cowboy(standalone, Ref, Config).


-spec stop_server(Ref) -> Result
        when Ref :: backwater_cowboy_instance:ref(),
             Result :: ok | {error, not_found}.

stop_server(Ref) ->
    backwater_cowboy_instance:stop_cowboy(standalone, Ref).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Definitions
%% ------------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
%% @private
init(State0) ->
    backwater_rebar3_prv_generate:init(State0).
