-module(backwater_server_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]).
-export([child_spec/3]).

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

start_link(Ref, Config) ->
    supervisor:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, Config]).

child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => transient,
       type => supervisor,
       modules => [?MODULE] }.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([Ref, Config]) ->
    Children = [backwater_server_instance:child_spec(server_instance, Ref, Config)],
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_server_sup").
