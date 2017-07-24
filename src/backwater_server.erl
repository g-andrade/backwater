-module(backwater_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([childspec/3]).
-export([start/2]).
-export([stop/1]).
-export([cowboy_route_rule/1]).
-export([cowboy_route_path/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

childspec(Id, Ref, ServerConfig) ->
    backwater_server_sup:childspec(Id, Ref, ServerConfig).

start(Ref, ServerConfig) ->
    backwater_sup:start_server(Ref, ServerConfig).

stop(Ref) ->
    backwater_sup:stop_server(Ref).

cowboy_route_rule(BackwaterOpts) ->
    backwater_cowboy_instance:cowboy_route_rule(BackwaterOpts).

cowboy_route_path(BackwaterOpts) ->
    backwater_cowboy_instance:cowboy_route_path(BackwaterOpts).
