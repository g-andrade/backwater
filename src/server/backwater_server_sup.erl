%% @private
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
%% Type Definitions
%% ------------------------------------------------------------------

-type child_spec(Id) ::
        #{ id := Id,
           start := {?MODULE, start_link, [atom() | backwater_server_instance:config(), ...]},
           restart := permanent,
           type := supervisor,
           modules := [?MODULE, ...] }.
-export_type([child_spec/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(atom(), backwater_server_instance:config()) -> backwater_sup_util:start_link_ret().
start_link(Ref, Config) ->
    supervisor:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, Config]).

-spec child_spec(term(), atom(), backwater_server_instance:config()) -> child_spec(term()).
child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => permanent,
       type => supervisor,
       modules => [?MODULE] }.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([atom() | backwater_server_instance:config(), ...])
        -> {ok, {#{}, [backwater_server_instance:child_spec(server_instance), ...]}}.
init([Ref, Config]) ->
    Children = [backwater_server_instance:child_spec(server_instance, Ref, Config)],
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec server_name(atom()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ atom_to_list(Ref) ++ "_server_sup").
