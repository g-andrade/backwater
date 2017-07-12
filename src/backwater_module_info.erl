-module(backwater_module_info).
-behaviour(gen_server).

-include_lib("stdlib/include/ms_transform.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1]). -ignore_xref({start_link, 1}).
-export([find/2]).

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
-define(CACHE_REFRESH_INTERVAL, (timer:seconds(1))).
-define(INACTIVE_ENTRY_TTL, (timer:seconds(5))).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(cached_module_info_lookup, {
          module :: module(),
          result :: {ok, term()} | error, % TODO define type
          last_accessed :: integer()
         }).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Ref) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref], []).

find(Ref, Module) ->
    Cache = cache_name(Ref),
    find_recur(Cache, Module).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([Ref]) ->
    Cache = cache_name(Ref),
    _ = ets:new(
          Cache,
          [named_table, public, {keypos, #cached_module_info_lookup.module}, {read_concurrency, true}]),

    State = #{ cache => Cache },
    erlang:send_after(?CACHE_REFRESH_INTERVAL, self(), refresh_cache),
    {ok, State}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refresh_cache, #{ cache := Cache } = State) ->
    refresh_cache(Cache),
    erlang:send_after(?CACHE_REFRESH_INTERVAL, self(), refresh_cache),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_util:parse_unicode_string(Ref) ++ "_module_info").

cache_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_util:parse_unicode_string(Ref) ++ "_module_info_cache").

refresh_cache(Cache) ->
    purge_expired_entries(Cache),
    update_entry_results(Cache).

purge_expired_entries(Cache) ->
    Now = now_milliseconds(),
    TTL = ?INACTIVE_ENTRY_TTL,
    MatchSpec =
        ets:fun2ms(
          fun (#cached_module_info_lookup{ last_accessed = LastAccessed }) ->
                  (Now - LastAccessed) > TTL
          end),
    ets:select_delete(Cache, MatchSpec).

update_entry_results(Cache) ->
    Entries = ets:tab2list(Cache),
    UpdatedEntries =
        lists:map(
          fun (CachedModuleInfo) ->
                  #cached_module_info_lookup{ module = Module } = CachedModuleInfo,
                  UpdatedResult = find_and_parse_module_info(Module),
                  CachedModuleInfo#cached_module_info_lookup{ result = UpdatedResult }
          end,
          Entries),
    ets:insert(Cache, UpdatedEntries).

find_and_parse_module_info(Module) ->
    case find_module_info(Module) of
        {ok, RawModuleInfo} ->
            {attributes, ModuleAttributes} = lists:keyfind(attributes, 1, RawModuleInfo),
            {exports, Exports} = lists:keyfind(exports, 1, RawModuleInfo),
            case module_attributes_find_backwater_version(ModuleAttributes) of
                {ok, BackwaterVersion} ->
                    BackwaterExports = module_attributes_get_backwater_exports(ModuleAttributes),
                    FilteredBackwaterExports = maps:with(Exports, BackwaterExports),
                    {ok, #{ version => BackwaterVersion,
                            exports => FilteredBackwaterExports }};
                error ->
                    error
            end;
        error ->
            error
    end.

find_module_info(Module) ->
    try
        {ok, Module:module_info()}
    catch
        error:undef -> error
    end.

module_attributes_find_backwater_version(ModuleAttributes) ->
    case lists:keyfind(backwater_version, 1, ModuleAttributes) of
        {backwater_version, Version} ->
            <<BinVersion/binary>> = unicode:characters_to_binary(Version),
            {ok, BinVersion};
        false ->
            error
    end.

module_attributes_get_backwater_exports(ModuleAttributes) ->
    lists:foldl(
      fun ({backwater_export, Tuple}, Acc) when is_tuple(Tuple) ->
              {FA, Properties} = backwater_export_entry_pair(Tuple),
              maps:put(FA, Properties, Acc);
          ({backwater_export, List}, Acc) when is_list(List) ->
              EntryPairs = lists:map(fun backwater_export_entry_pair/1, List),
              maps:merge(Acc, maps:from_list(EntryPairs));
          (_Other, Acc) ->
              Acc
      end,
      #{},
      ModuleAttributes).

backwater_export_entry_pair({F,A}) ->
    Properties = #{ known_content_types => [{<<"application">>, <<"x-erlang-etf">>}] },
    {{F,A}, Properties}.

now_milliseconds() ->
    erlang:monotonic_time(millisecond).

find_recur(Cache, Module) ->
    Now = now_milliseconds(),
    case ets:lookup(Cache, Module) of
        [#cached_module_info_lookup{ result = Result }] ->
            case ets:update_element(Cache, Module, {#cached_module_info_lookup.last_accessed, Now}) of
                true -> Result;
                false -> find_recur(Cache, Module)
            end;
        [] ->
            Result = find_and_parse_module_info(Module),
            CachedModuleInfo =
                #cached_module_info_lookup{ module = Module, result = Result, last_accessed = Now },
            case ets:insert_new(Cache, CachedModuleInfo) of
                true -> Result;
                false -> find_recur(Cache, Module)
            end
    end.
