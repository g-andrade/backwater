-module(rpcaller_server).

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
    rpcaller_server_sup:childspec(Id, Ref, ServerConfig).

start(Ref, ServerConfig) ->
    rpcaller_sup:start_server(Ref, ServerConfig).

stop(Ref) ->
    rpcaller_sup:stop_server(Ref).

cowboy_route_rule(RPCallerOpts) ->
    rpcaller_cowboy_instance:cowboy_route_rule(RPCallerOpts).

cowboy_route_path(RPCallerOpts) ->
    rpcaller_cowboy_instance:cowboy_route_path(RPCallerOpts).
