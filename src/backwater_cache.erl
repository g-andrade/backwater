%% @private
-module(backwater_cache).
-behaviour(gen_server).

-include_lib("stdlib/include/ms_transform.hrl").

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
-define(SERVER, ?MODULE).
-define(TABLE, ?SERVER).

-define(PURGE_EXPIRED_ENTRIES_INTERVAL, (timer:seconds(5))).

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
        #{ id := Id,
           start := {?MODULE, start_link, []},
           restart := permanent,
           type := worker,
           modules := [?MODULE, ...] }.
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

-spec find(term()) -> {ok, term()} | error.
find(Key) ->
    case ets:lookup(?TABLE, Key) of
        [#cache_entry{ value = Value }] -> {ok, Value};
        [] -> error
    end.

-spec put(term(), term(), non_neg_integer()) -> true.
put(Key, Value, TTL) ->
    Expiry = now_milliseconds() + TTL,
    NewEntry = #cache_entry{ key = Key, value = Value, expiry = Expiry },
    ets:insert(?TABLE, NewEntry).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([]) -> {ok, state()}.
init([]) ->
    _ = ets:new(
          ?TABLE,
          [named_table, public, {keypos, #cache_entry.key},
           {read_concurrency, true},
           {write_concurrency, true}]),

    erlang:send_after(?PURGE_EXPIRED_ENTRIES_INTERVAL, self(), purge_expired_entries),
    {ok, no_state}.

-spec handle_call(term(), {pid(), reference()}, state()) -> {noreply, state()}.
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(purge_expired_entries, State) ->
    Now = now_milliseconds(),
    MatchSpec = ets:fun2ms(fun (#cache_entry{ expiry = Expiry }) -> Expiry =< Now end),
    ets:select_delete(?TABLE, MatchSpec),
    erlang:send_after(?PURGE_EXPIRED_ENTRIES_INTERVAL, self(), purge_expired_entries),
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

-spec now_milliseconds() -> integer().
now_milliseconds() ->
    erlang:monotonic_time(millisecond).
