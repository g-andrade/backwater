-module(backwater_module_info).
%%
%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([find/1]).
-export([find/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CACHED_MODULE_INFO_TTL, 500).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

find(Module) ->
    find(Module, []).

find(Module, [use_process_dictionary_cache])  ->
    % WARNING: very dirty hack using process dictionary
    Now = now_milliseconds(),
    case erlang:get({cached_module_info_lookup, Module}) of
        undefined ->
            find_and_parse_and_cache_module_info(Module);
        #{ creation_timestamp := CreationTimestamp } when Now - CreationTimestamp >= ?CACHED_MODULE_INFO_TTL ->
            find_and_parse_and_cache_module_info(Module);
        #{ result := CachedResult } ->
            CachedResult
    end;
find(Module, []) ->
    find_and_parse_module_info(Module).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

find_and_parse_and_cache_module_info(Module) ->
    Result = find_and_parse_module_info(Module),
    CachedLookup = #{ result => Result, creation_timestamp => now_milliseconds() },
    erlang:put({cached_module_info_lookup, Module}, CachedLookup),
    Result.

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
