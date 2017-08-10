%% @private
-module(backwater_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).

%% ------------------------------------------------------------------
%% supervisor Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).
-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type children_spec() ::
        [backwater_cache:child_spec(cache) |
         backwater_client_instances:child_spec(client_instances),
         ...].
-export_type([children_spec/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link() -> backwater_sup_util:start_link_ret().
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?CB_MODULE, []).

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([]) -> {ok, {#{}, children_spec()}}.
init([]) ->
    Children =
        [backwater_cache:child_spec(cache),
         backwater_client_instances:child_spec(client_instances)],
    {ok, {#{}, Children}}.
