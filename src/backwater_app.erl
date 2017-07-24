-module(backwater_app).
-behaviour(application).

%% ------------------------------------------------------------------
%% application Function Exports
%% ------------------------------------------------------------------

-export([start/2]).
-export([stop/1]).
-export([config_change/3]).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% application Function Definitions
%% ------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    Clients = application:get_env(backwater, clients, #{}),
    Servers = application:get_env(backwater, servers, #{}),
    backwater_sup:start_link(Clients, Servers).

stop(_State) ->
    ok.

config_change(_Changed, _New, _Removed) ->
    Clients = application:get_env(backwater, clients, #{}),
    Servers = application:get_env(backwater, servers, #{}),
    backwater_sup:app_config_changed(Clients, Servers).

%% ------------------------------------------------------------------
%% rebar3 Plugin Function Definitions
%% ------------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State0) ->
    backwater_rebar3_prv_generate:init(State0).
