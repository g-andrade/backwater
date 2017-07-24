-module(backwater_client_app_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1]).
-export([start_client/2]).
-export([stop_client/1]).
-export([app_config_changed/1]).

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
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Clients) ->
    supervisor:start_link({local, ?SERVER}, ?CB_MODULE, [Clients]).

start_client(Ref, Config) ->
    Child = client_child_spec({Ref, Config}),
    start_child(Child).

stop_client(Ref) ->
    stop_child({client, Ref}).

app_config_changed(Clients) ->
    UpdatedChildren =
        lists:map(fun client_child_spec/1, Clients),

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

init([Clients]) ->
    Children = lists:map(fun client_child_spec/1, Clients),
    {ok, {#{}, Children}}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

client_child_spec({Ref, Config}) ->
    backwater_client_sup:child_spec(Ref, Ref, Config).

start_child(Child) ->
    supervisor:start_child(?SERVER, Child).

stop_child(ChildId) ->
    case supervisor:terminate_child(?SERVER, ChildId) of
        ok ->
            supervisor:delete_child(?SERVER, ChildId);
        {error, _} = Error ->
            Error
    end.

update_child(#{ id := Id } = NewChild) ->
    case supervisor:get_childspec(?SERVER, Id) of
        {ok, ExistingChild} when ExistingChild =:= NewChild ->
            % nothing changed, leave it be
            ok;
        {ok, _ExistingChild} ->
            ok = stop_child(Id),
            start_child(NewChild);
        {error, not_found} ->
            {error, not_found}
    end.
