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
-module(backwater_client_instances).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]). -ignore_xref({start_link, 0}).
-export([child_spec/1]).
-export([find_client_config/1]).
-export([start_client/2]).
-export([stop_client/1]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).
-define(SERVER, ?MODULE).
-define(TABLE, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type child_spec(Id) ::
        #{ id => Id,
           start => {?MODULE, start_link, []},
           restart => permanent,
           type => worker,
           modules => [?MODULE, ...] }.
-export_type([child_spec/1]).

-type state() :: no_state.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link() -> backwater_sup_util:start_link_ret().
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?CB_MODULE, [], []).

-spec child_spec(term()) -> child_spec(term()).
child_spec(Id) ->
    #{ id => Id,
       start => {?MODULE, start_link, []},
       restart => permanent,
       type => worker,
       modules => [?MODULE] }.

-spec find_client_config(term()) -> {ok, term()} | error.
find_client_config(Ref) ->
    case ets:lookup(?TABLE, Ref) of
        [{Ref, Config}] -> {ok, Config};
        [] -> error
    end.

-spec start_client(term(), term()) -> ok | {error, already_started}.
start_client(Ref, Config) ->
    gen_server:call(?SERVER, {start_client, Ref, Config}, infinity).

-spec stop_client(term()) -> ok | {error, not_found}.
stop_client(Ref) ->
    gen_server:call(?SERVER, {stop_client, Ref}, infinity).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([]) -> {ok, state()}.
init([]) ->
    _ = ets:new(?TABLE, [named_table, {read_concurrency, true}]),
    {ok, no_state}.

-spec handle_call(term(), {pid(), reference()}, state())
        -> {reply, ok | {error, Error}, state()} |
           {noreply, state()}
                when Error :: already_started | not_found.
handle_call({start_client, Ref, Config}, _From, State) ->
    Reply =
        case ets:insert_new(?TABLE, {Ref, Config}) of
            true -> ok;
            false -> {error, already_started}
        end,
    {reply, Reply, State};
handle_call({stop_client, Ref}, _From, State) ->
    Reply =
        case ets:take(?TABLE, Ref) of
            [{Ref, _Config}] -> ok;
            [] -> {error, not_found}
        end,
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
