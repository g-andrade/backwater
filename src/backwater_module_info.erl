-module(backwater_module_info).

-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([generate/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CACHED_MODULE_INFO_TTL, 500).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type module_info() :: #{ version := version(), exports := exports() }.
-export_type([module_info/0]).

-type version() :: binary().
-export_type([version/0]).

-type exports() :: #{ fun_arity_pair() => fun_properties() }.
-export_type([exports/0]).

-type fun_arity_pair() :: {binary(), arity()}.
-export_type([fun_arity_pair/0]).

-type fun_properties() ::
        #{ known_content_types := [content_type(), ...],
           function_ref := fun() }.
-export_type([fun_properties/0]).

-type content_type() :: {non_empty_binary(), non_empty_binary()}.
-export_type([content_type/0]).

-type lookup_result() :: {true, {BinModule :: non_empty_binary(), module_info()}} | false.
-export_type([lookup_result/0]).

-type raw_module_info() :: [{atom(), term()}].
-type raw_module_attributes() :: [{atom(), term()}].

-type cached_result() :: #{ creation_timestamp := integer(), result := lookup_result() }.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

generate(Modules, [use_process_dictionary_cache]) ->
    KvList = lists:filtermap(fun find_and_parse_module_info_with_cache/1, Modules),
    maps:from_list(KvList);
generate(Modules, []) ->
    KvList = lists:filtermap(fun find_and_parse_module_info/1, Modules),
    maps:from_list(KvList).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec find_and_parse_module_info_with_cache(module()) -> lookup_result().
find_and_parse_module_info_with_cache(Module) ->
    CacheKey = {cached_module_info_lookup, Module},
    CachedResult = erlang:get(CacheKey),
    case CachedResult =:= undefined orelse cached_result_age(CachedResult) >= ?CACHED_MODULE_INFO_TTL
    of
        true ->
            Result = find_and_parse_module_info(Module),
            CachedLookup = #{ result => Result, creation_timestamp => now_milliseconds() },
            erlang:put({cached_module_info_lookup, Module}, CachedLookup),
            Result;
        false ->
            maps:get(result, CachedResult)
    end.

-spec cached_result_age(cached_result()) -> integer().
cached_result_age(#{ creation_timestamp := CreationTimestamp }) ->
    now_milliseconds() - CreationTimestamp.

-spec find_and_parse_module_info(module()) -> lookup_result().
find_and_parse_module_info(Module) ->
    case find_module_info(Module) of
        {ok, RawModuleInfo} ->
            {attributes, ModuleAttributes} = lists:keyfind(attributes, 1, RawModuleInfo),
            {exports, AtomKeyedExports} = lists:keyfind(exports, 1, RawModuleInfo),
            Exports = [{atom_to_binary(K, utf8), V} || {K, V} <- AtomKeyedExports],
            case module_attributes_find_backwater_module_version(ModuleAttributes) of
                {ok, BackwaterModuleVersion} ->
                    BackwaterExports = module_attributes_get_backwater_exports(Module, ModuleAttributes),
                    FilteredBackwaterExports = maps:with(Exports, BackwaterExports),
                    BinModule = atom_to_binary(Module, utf8),
                    {true,
                     {BinModule, #{ version => BackwaterModuleVersion,
                                    exports => FilteredBackwaterExports }}};
                error ->
                    false
            end;
        error ->
            false
    end.

-spec find_module_info(module()) -> {ok, raw_module_info()} | error.
find_module_info(Module) ->
    try
        {ok, Module:module_info()}
    catch
        error:undef -> error
    end.

-spec module_attributes_find_backwater_module_version(raw_module_attributes())
        -> {ok, version()} | error.
module_attributes_find_backwater_module_version(ModuleAttributes) ->
    case lists:keyfind(backwater_module_version, 1, ModuleAttributes) of
        {backwater_module_version, Version} ->
            <<BinVersion/binary>> = unicode:characters_to_binary(Version),
            {ok, BinVersion};
        false ->
            error
    end.

-spec module_attributes_get_backwater_exports(module(), raw_module_attributes()) -> exports().
module_attributes_get_backwater_exports(Module, ModuleAttributes) ->
    lists:foldl(
      fun ({backwater_export, Tuple}, Acc) when is_tuple(Tuple) ->
              {FA, Properties} = backwater_export_entry_pair(Module, Tuple),
              maps:put(FA, Properties, Acc);
          ({backwater_export, List}, Acc) when is_list(List) ->
              EntryPairs = [backwater_export_entry_pair(Module, Tuple) || Tuple <- List],
              maps:merge(Acc, maps:from_list(EntryPairs));
          (_Other, Acc) ->
              Acc
      end,
      #{},
      ModuleAttributes).

-spec backwater_export_entry_pair(module(), {atom(), arity()})
        -> {fun_arity_pair(), fun_properties()}.
backwater_export_entry_pair(Module, {AtomF,A}) ->
    Properties =
        #{ known_content_types => [{<<"application">>, <<"x-erlang-etf">>}],
           function_ref => fun Module:AtomF/A },
    F = atom_to_binary(AtomF, utf8),
    {{F,A}, Properties}.

-spec now_milliseconds() -> integer().
now_milliseconds() ->
    erlang:monotonic_time(millisecond).
