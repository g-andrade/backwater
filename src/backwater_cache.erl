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
-module(backwater_cache).
-behaviour(gen_server).

-include_lib("stdlib/include/ms_transform.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).            -ignore_xref({start_link,0}).
-export([child_spec/1]).
-export([find/1]).
-export([put/3]).

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
-define(DEFAULT_NAME, ?MODULE).
-define(DEFAULT_TABLE, ?MODULE).
-define(DEFAULT_PURGE_EXPIRED_ENTRIES_INTERVAL, (timer:seconds(5))).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(cache_entry, {
          key :: term(),
          value :: term(),
          expiry :: integer()
         }).

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

-type state() ::
        #{ table => atom(),
           purge_interval => pos_integer() % in milliseconds
         }.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link() -> backwater_sup_util:start_link_ret().
start_link() ->
    start_link(?DEFAULT_NAME, ?DEFAULT_TABLE, ?DEFAULT_PURGE_EXPIRED_ENTRIES_INTERVAL).

-spec child_spec(term()) -> child_spec(term()).
child_spec(Id) ->
    #{ id => Id,
       start => {?MODULE, start_link, []},
       restart => permanent,
       type => worker,
       modules => [?MODULE] }.

-spec find(term()) -> {ok, term()} | error.
find(Key) ->
    find(?DEFAULT_TABLE, Key).

-spec put(term(), term(), non_neg_integer()) -> true.
put(Key, Value, TTL) ->
    put(?DEFAULT_TABLE, Key, Value, TTL).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([atom() | pos_integer(), ...]) -> {ok, state()}.
init([Table, PurgeInterval]) ->
    Table =
        ets:new(
          Table,
          [named_table, public, {keypos, #cache_entry.key},
           {read_concurrency, true},
           {write_concurrency, true}]),

    erlang:send_after(PurgeInterval, self(), purge_expired_entries),
    {ok, #{ table => Table, purge_interval => PurgeInterval }}.

-spec handle_call(term(), {pid(), reference()}, state()) -> {noreply, state()}.
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(purge_expired_entries, State) ->
    #{ table := Table, purge_interval := PurgeInterval } = State,
    Now = now_milliseconds(),
    MatchSpec = ets:fun2ms(fun (#cache_entry{ expiry = Expiry }) -> Expiry =< Now end),
    ets:select_delete(Table, MatchSpec),
    erlang:send_after(PurgeInterval, self(), purge_expired_entries),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

start_link(Name, Table, PurgeInterval) ->
    gen_server:start_link({local, Name}, ?CB_MODULE, [Table, PurgeInterval], []).

find(Table, Key) ->
    case ets:lookup(Table, Key) of
        [#cache_entry{ value = Value }] -> {ok, Value};
        [] -> error
    end.

put(Table, Key, Value, TTL) ->
    Expiry = now_milliseconds() + TTL,
    NewEntry = #cache_entry{ key = Key, value = Value, expiry = Expiry },
    ets:insert(Table, NewEntry).

-spec now_milliseconds() -> integer().
now_milliseconds() ->
    erlang:monotonic_time(milli_seconds). % from 19.1 and up it can be just 'millisecond'

%% ------------------------------------------------------------------
%% Unit Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

-spec purge_test() -> ok.
purge_test() ->
    Name = backwater_cache_purge_test,
    Table = Name,
    PurgeInterval = 100,
    {ok, Pid} = start_link(Name, Table, PurgeInterval),
    put(Table, key1, value1, PurgeInterval div 2),
    put(Table, key2, value2, (PurgeInterval * 3) div 2),
    put(Table, key3, value3, (PurgeInterval * 5) div 2),

    % check first purge cycle
    timer:sleep((PurgeInterval * 3) div 2),
    ?assertEqual(error, find(Table, key1)),
    ?assertEqual({ok, value2}, find(Table, key2)),
    ?assertEqual({ok, value3}, find(Table, key3)),
    ?assertEqual(2, ets:info(Table, size)),

    % check second purge cycle
    timer:sleep(PurgeInterval),
    ?assertEqual(error, find(Table, key1)),
    ?assertEqual(error, find(Table, key2)),
    ?assertEqual({ok, value3}, find(Table, key3)),
    ?assertEqual(1, ets:info(Table, size)),

    % check third purge cycle
    timer:sleep(PurgeInterval),
    ?assertEqual(error, find(Table, key1)),
    ?assertEqual(error, find(Table, key2)),
    ?assertEqual(error, find(Table, key3)),
    ?assertEqual(0, ets:info(Table, size)),

    ok = gen_server:stop(Pid).

-endif.
