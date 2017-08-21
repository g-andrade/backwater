%% Copyright (c) 2017 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

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

-define(NAMESPACE, backwater).
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
    Example =
        backwater_util:iodata_to_list(
          io_lib:format("rebar3 ~s ~s", [?NAMESPACE, ?PROVIDER])),

    Provider =
        providers:create(
          [{namespace, ?NAMESPACE},
           {name, ?PROVIDER},            % The 'user friendly' name of the task
           {module, ?MODULE},            % The module implementation of the task
           {bare, true},                 % The task can be run by the user, always true
           {deps, ?DEPS},                % The list of dependencies
           {opts, []},                   % list of options understood by the plugin
           {example, Example},
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
    io_lib:format("~s ~s: ~p", [?NAMESPACE, ?PROVIDER, Error]).
