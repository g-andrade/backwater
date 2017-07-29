-module(backwater_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([child_spec/3]).
-export([start/2]).
-export([stop/1]).
-export([cowboy_route_rule/1]).
-export([cowboy_route_path/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec(ChildId, Ref, Config) -> ChildSpec
        when ChildId :: term(),
             Ref :: term(),
             Config :: backwater_server_instance:config(),
             ChildSpec :: backwater_server_sup:child_spec(ChildId).

child_spec(ChildId, Ref, Config) ->
    backwater_server_sup:child_spec(ChildId, Ref, Config).


-spec start(Ref, Config) -> Result
        when Ref :: term(),
             Config :: backwater_server_instance:config(),
             Result :: backwater_sup_util:start_link_ret().

start(Ref, Config) ->
    backwater_sup:start_server(Ref, Config).


-spec stop(Ref) -> Result
        when Ref :: term(),
             Result :: backwater_sup_util:stop_child_ret().

stop(Ref) ->
    backwater_sup:stop_server(Ref).


-spec cowboy_route_rule(Config) -> RouteRule
        when Config :: backwater_server_instance:config(),
             RouteRule :: backwater_server_instance:route_rule().

cowboy_route_rule(Config) ->
    backwater_server_instance:cowboy_route_rule(Config).


-spec cowboy_route_path(Config) -> RoutePath
        when Config :: backwater_server_instance:config(),
             RoutePath :: backwater_server_instance:route_path().

cowboy_route_path(Config) ->
    backwater_server_instance:cowboy_route_path(Config).
