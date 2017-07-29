%% @private
-module(backwater_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]).
-export([start_client/2]).
-export([stop_client/1]).
-export([start_server/2]).
-export([stop_server/1]).
-export([app_config_changed/2]).

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

-type clients() :: #{ (Ref :: term()) => backwater_client_config:t() }.
-export_type([clients/0]).

-type servers() :: #{ (Ref :: term()) => backwater_server_instance:config() }.
-export_type([servers/0]).

-type child_spec() ::
        backwater_cache:child_spec(cache) |
        backwater_client_sup:child_spec({client, Ret :: term()}) |
        backwater_server_sup:child_spec({server, Ret :: term()}).
-export_type([child_spec/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(clients(), servers()) -> backwater_sup_util:start_link_ret().
start_link(Clients, Servers) ->
    supervisor:start_link({local, ?SERVER}, ?CB_MODULE, [Clients, Servers]).

-spec start_client(term(), backwater_client_config:t()) -> backwater_sup_util:start_child_ret().
start_client(Ref, Config) ->
    Child = client_child_spec(Ref, Config),
    start_child(Child).

-spec stop_client(term()) -> backwater_sup_util:stop_child_ret().
stop_client(Ref) ->
    stop_child({client, Ref}).

-spec start_server(term(), backwater_server_instance:config()) -> backwater_sup_util:start_child_ret().
start_server(Ref, Config) ->
    Child = server_child_spec(Ref, Config),
    start_child(Child).

-spec stop_server(term()) -> backwater_sup_util:stop_child_ret().
stop_server(Ref) ->
    stop_child({server, Ref}).

-spec app_config_changed(clients(), servers()) -> ok.
app_config_changed(Clients, Servers) ->
    UpdatedChildren =
        maps:values(maps:map(fun client_child_spec/2, Clients)) ++
        maps:values(maps:map(fun server_child_spec/2, Servers)),

    UpdatedChildrenPerId =
        maps:from_list(
          [{maps:get(id, Child), Child} || Child <- UpdatedChildren]),

    % handle existing children
    HandledIds =
        lists:map(
          fun ({Id, _Type, _PidOrStatus, _Modules}) ->
                  case maps:find(Id, UpdatedChildrenPerId) of
                      {ok, UpdatedChild} ->
                          ok = update_child(UpdatedChild);
                      error ->
                          % removed
                          ok = stop_child(Id)
                  end,
                  Id
          end,
          supervisor:which_children(?SERVER)),

    % handle new children
    lists:foreach(
      fun (#{ id := Id } = Child) ->
              case lists:member(Id, HandledIds) of
                  true -> ok;
                  false -> {ok, _} = start_child(Child)
              end
      end,
      UpdatedChildren).

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

-spec init([clients() | servers(), ...]) -> {ok, {#{}, [child_spec(), ...]}}.
init([Clients, Servers]) ->
    CacheChildSpec = backwater_cache:child_spec(cache),
    Children =
        [CacheChildSpec] ++
        maps:values(maps:map(fun client_child_spec/2, Clients)) ++
        maps:values(maps:map(fun server_child_spec/2, Servers)),
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec client_child_spec(term(), backwater_client_config:t())
        -> backwater_client_sup:child_spec({client, term()}).
client_child_spec(Ref, Config) ->
    backwater_client_sup:child_spec({client, Ref}, Ref, Config).

-spec server_child_spec(term(), backwater_server_instance:config())
        -> backwater_server_sup:child_spec({server, term()}).
server_child_spec(Ref, Config) ->
    backwater_server_sup:child_spec({server, Ref}, Ref, Config).

-spec start_child(child_spec()) -> backwater_sup_util:start_child_ret().
start_child(ChildSpec) ->
    supervisor:start_child(?SERVER, ChildSpec).

-spec stop_child(term()) -> backwater_sup_util:stop_child_ret().
stop_child(ChildId) ->
    case supervisor:terminate_child(?SERVER, ChildId) of
        ok ->
            supervisor:delete_child(?SERVER, ChildId);
        {error, _} = Error ->
            Error
    end.

-spec update_child(child_spec()) -> ok | {error, not_found}.
update_child(#{ id := Id } = NewChild) ->
    case supervisor:get_childspec(?SERVER, Id) of
        {ok, ExistingChild} when ExistingChild =:= NewChild ->
            % nothing changed, leave it be
            ok;
        {ok, _ExistingChild} ->
            ok = stop_child(Id),
            {ok, _Pid} = start_child(NewChild),
            ok;
        {error, not_found} ->
            {error, not_found}
    end.
