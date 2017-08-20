%% @private
-module(backwater_rebar3_prv_generate).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([init/1]).
-export([do/1]).                          -ignore_xref({do,1}).
-export([format_error/1]).                -ignore_xref({format_error,1}).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(PROVIDER, generate).
-define(DEPS, [{default, app_discovery},
               {default, install_deps} % crucial in order for source paths of dependencies to be available
              ]).
-define(SHORT_DESC, "Generate wrapper modules for RPC calls to exposed modules").
-define(DESC, lists:join("\n",
                         ["Configure generation options (backwater_gen) in your rebar.config, e.g."
                          "    {backwater_gen,"
                          "     [{client_ref, %REF_OF_THE_CLIENT_YOU'LL_START%},"
                          "      {target, {stdlib, string, [{exports, all}]}}]}."])).


%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider =
        providers:create(
          [{name, ?PROVIDER},            % The 'user friendly' name of the task
           {namespace, backwater},
           {module, ?MODULE},            % The module implementation of the task
           {bare, true},                 % The task can be run by the user, always true
           {deps, ?DEPS},                % The list of dependencies
           {opts, []},                   % list of options understood by the plugin
           {example, "rebar3 backwater generate"},
           {short_desc, ?SHORT_DESC},
           {desc, ?DESC}]),
    {ok, rebar_state:add_provider(State, Provider)}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, {?MODULE, term()}}.
do(State) ->
    case backwater_rebar3_generator:generate(State) of
        ok -> {ok, State};
        {error, Error} ->
            {error, {?MODULE, Error}}
    end.

-spec format_error(any()) ->  iolist().
format_error(Error) ->
    io_lib:format("~p", [Error]).
