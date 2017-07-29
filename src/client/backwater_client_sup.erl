-module(backwater_client_sup).
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
           start := {?MODULE, start_link, [term() | backwater_client_config:t(), ...]},
           restart := permanent,
           type := supervisor,
           modules := [?MODULE, ...] }.
-export_type([child_spec/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(term(), backwater_client_config:t()) -> backwater_sup_util:start_link_ret().
start_link(Ref, Config) ->
    supervisor:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, Config]).

-spec child_spec(term(), term(), backwater_client_config:t()) -> child_spec(term()).
child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => permanent,
       type => supervisor,
       modules => [?MODULE] }.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([term() | backwater_client_config:t(), ...]) -> {ok, {#{}, [child_spec(term()), ...]}}.
init([Ref, Config]) ->
    Children = [backwater_client_config:child_spec(config, Ref, Config)],
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec server_name(term()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_client_sup").
