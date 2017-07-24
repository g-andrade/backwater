-module(backwater_server_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]).
-export([childspec/3]).

%% ------------------------------------------------------------------
%% supervisor Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Ref, ServerConfig) ->
    supervisor:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, ServerConfig]).

childspec(Id, Ref, ServerConfig) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, ServerConfig]},
       restart => transient,
       type => supervisor,
       modules => [?MODULE] }.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([Ref, ServerConfig]) ->
    Children = [backwater_cowboy_instance:childspec(cowboy_instance, Ref, ServerConfig)],
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_server_sup").
