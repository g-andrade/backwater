%% @private
-module(backwater_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([app_config_changed/1]).
-export([start_link/1]).

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

-type children_spec() ::
        [backwater_cache:child_spec(cache) |
         backwater_cowboy_sup:child_spec(cowboy_instances),
         ...].
-export_type([children_spec/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec app_config_changed(backwater_cowboy_sup:servers()) -> ok.
app_config_changed(Servers) ->
    {ok, PrevChildSpec} = supervisor:get_childspec(?SERVER, cowboy_instances),
    NewChildSpec = backwater_cowboy_sup:child_spec(cowboy_instances, Servers),
    case PrevChildSpec =/= NewChildSpec of
        false -> ok;
        true ->
            ok = supervisor:terminate_child(?SERVER, cowboy_instances),
            ok = supervisor:delete_child(?SERVER, cowboy_instances),
            {ok, _Pid} = supervisor:start_child(?SERVER, NewChildSpec),
            ok
    end.

-spec start_link([backwater_cowboy_sup:servers()])
        -> backwater_sup_util:start_link_ret().
start_link(Servers) ->
    supervisor:start_link({local, ?SERVER}, ?CB_MODULE, [Servers]).

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([backwater_cowboy_sup:servers(), ...]) -> {ok, {#{}, children_spec()}}.
init([Servers]) ->
    Children = [backwater_cache:child_spec(cache),
                backwater_cowboy_sup:child_spec(cowboy_instances, Servers)],
    {ok, {#{}, Children}}.
