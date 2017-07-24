-module(backwater_client_app).
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
    Clients = clients_from_config(),
    backwater_client_app_sup:start_link(Clients).

stop(_State) ->
    ok.

config_change(_Changed, _New, _Removed) ->
    Clients = clients_from_config(),
    backwater_client_app_sup:app_config_changed(Clients).

%% internal

clients_from_config() ->
    Env = application:get_all_env(backwater_client),
    [{Ref, Config} || {Ref, Config} <- Env, is_map(Config)].
