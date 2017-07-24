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

-spec child_spec(ChildId, Ref, ServerConfig) -> ChildSpec
        when ChildId :: term(),
             Ref :: term(),
             ServerConfig :: backwater_cowboy_instance:config(),
             ChildSpec :: backwater_server_sup:child_spec().

child_spec(ChildId, Ref, ServerConfig) ->
    backwater_server_sup:child_spec(ChildId, Ref, ServerConfig).


-spec start(Ref, ServerConfig) -> Result
        when Ref :: term(),
             ServerConfig :: backwater_cowboy_instance:config(),
             Result :: supervisor:startlink_ret().

start(Ref, ServerConfig) ->
    backwater_server_app_sup:start_server(Ref, ServerConfig).


stop(Ref) ->
    backwater_server_app_sup:stop_server(Ref).


-spec cowboy_route_rule(BackwaterOpts) -> RouteRule
        when BackwaterOpts :: backwater_cowboy_handler:backwater_opts(),
             RouteRule :: backwater_cowboy_instance:route_rule().

cowboy_route_rule(BackwaterOpts) ->
    backwater_cowboy_instance:cowboy_route_rule(BackwaterOpts).


-spec cowboy_route_path(BackwaterOpts) -> RoutePath
        when BackwaterOpts :: backwater_cowboy_handler:backwater_opts(),
             RoutePath :: backwater_cowboy_instance:route_path().

cowboy_route_path(BackwaterOpts) ->
    backwater_cowboy_instance:cowboy_route_path(BackwaterOpts).
