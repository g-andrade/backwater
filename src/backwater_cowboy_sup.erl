%% @private
-module(backwater_cowboy_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([child_spec/2]).
-export([start_link/1]).                -ignore_xref({start_link,1}).

%% ------------------------------------------------------------------
%% supervisor Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(SERVER, ?MODULE).
-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type child_spec(Id) ::
    #{ id := Id,
       start := {?MODULE, start_link, [instances(), ...]},
       restart := permanent,
       type := worker,
       modules := [?MODULE, ...] }.
-export_type([child_spec/1]).

-type instances() :: #{ backwater_cowboy_instance:ref() => backwater_cowboy_instance:config() }.
-export_type([instances/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec(Id, instances()) -> child_spec(Id) when Id :: term().
child_spec(Id, Instances) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Instances]},
       restart => permanent,
       type => worker,
       modules => [?MODULE] }.

-spec start_link(instances()) -> backwater_sup_util:start_link_ret().
start_link(Instances) ->
    supervisor:start_link({local, ?SERVER}, ?CB_MODULE, [Instances]).

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([instances(), ...])
        -> {ok, {#{}, [backwater_cowboy_instance:child_spec(Ref), ...]}}
        when Ref :: backwater_cowboy_instance:ref().
init([Instances]) ->
    InstancesList = maps:to_list(Instances),
    Children = [backwater_cowboy_instance:child_spec(Ref, Ref, Config)
                || {Ref, Config} <- InstancesList],
    {ok, {#{}, Children}}.
