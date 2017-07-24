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

-type child_spec() ::
        #{ id := term(),
           start := {?MODULE, start_link, [term() | backwater_cowboy_instance:config(), ...]},
           restart := transient,
           type := supervisor,
           modules := [?MODULE, ...] }.

-export_type([child_spec/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(term(), backwater_cowboy_instance:config()) -> supervisor:startlink_ret().
start_link(Ref, ServerConfig) ->
    supervisor:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, ServerConfig]).

-spec child_spec(term(), term(), backwater_cowboy_instance:config()) -> child_spec().
child_spec(Id, Ref, ServerConfig) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, ServerConfig]},
       restart => transient,
       type => supervisor,
       modules => [?MODULE] }.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([term() | backwater_cowboy_instance:config(), ...])
        -> {ok, {#{}, [backwater_cowboy_instance:child_spec(cowboy_instance), ...]}}.
init([Ref, ServerConfig]) ->
    Children = [backwater_cowboy_instance:child_spec(cowboy_instance, Ref, ServerConfig)],
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec server_name(term()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_server_sup").
