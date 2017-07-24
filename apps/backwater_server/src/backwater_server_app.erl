-module(backwater_server_app).
-behaviour(application).

%% ------------------------------------------------------------------
%% application Function Exports
%% ------------------------------------------------------------------

-export([start/2]).
-export([stop/1]).
-export([config_change/3]).

%% ------------------------------------------------------------------
%% application Function Definitions
%% ------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    Servers = servers_from_config(),
    backwater_server_app_sup:start_link(Servers).

stop(_State) ->
    ok.

config_change(_Changed, _New, _Removed) ->
    Servers = servers_from_config(),
    backwater_server_app_sup:app_config_changed(Servers).

%% internal

servers_from_config() ->
    Env = application:get_all_env(backwater_server),
    [{Ref, Config} || {Ref, Config} <- Env, is_map(Config)].
