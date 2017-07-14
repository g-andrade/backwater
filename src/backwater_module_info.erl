-module(backwater_module_info).

-include("backwater_common.hrl").

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

-type module_info() :: #{ version := version(), exports := exports() }.
-export_type([module_info/0]).

-type version() :: binary().
-export_type([version/0]).

-type exports() :: #{ fun_arity_pair() => fun_properties() }.
-export_type([exports/0]).

-type fun_arity_pair() :: {atom(), arity()}.
-export_type([fun_arity_pair/0]).

-type fun_properties() :: #{ known_content_types => [content_type(), ...] }.
-export_type([fun_properties/0]).

-type content_type() :: {nonempty_binary(), nonempty_binary()}.
-export_type([content_type/0]).

-type lookup_result() :: {ok, module_info()} | error.
-export_type([lookup_result/0]).

-type raw_module_info() :: [{atom(), term()}].
-type raw_module_attributes() :: [{atom(), term()}].

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec find(module()) -> lookup_result().
find(Module) ->
    find(Module, []).

-spec find(module(), [use_process_dictionary_cache]) -> lookup_result().
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

-spec find_and_parse_and_cache_module_info(module()) -> lookup_result().
find_and_parse_and_cache_module_info(Module) ->
    Result = find_and_parse_module_info(Module),
    CachedLookup = #{ result => Result, creation_timestamp => now_milliseconds() },
    erlang:put({cached_module_info_lookup, Module}, CachedLookup),
    Result.

-spec find_and_parse_module_info(module()) -> lookup_result().
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

-spec find_module_info(module()) -> {ok, raw_module_info()} | error.
find_module_info(Module) ->
    try
        {ok, Module:module_info()}
    catch
        error:undef -> error
    end.

-spec module_attributes_find_backwater_version(raw_module_attributes())
        -> {ok, version()} | error.
module_attributes_find_backwater_version(ModuleAttributes) ->
    case lists:keyfind(backwater_version, 1, ModuleAttributes) of
        {backwater_version, Version} ->
            <<BinVersion/binary>> = unicode:characters_to_binary(Version),
            {ok, BinVersion};
        false ->
            error
    end.

-spec module_attributes_get_backwater_exports(raw_module_attributes()) -> exports().
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

-spec backwater_export_entry_pair(fun_arity_pair()) -> {fun_arity_pair(), fun_properties()}.
backwater_export_entry_pair({F,A}) ->
    Properties = #{ known_content_types => [{<<"application">>, <<"x-erlang-etf">>}] },
    {{F,A}, Properties}.

-spec now_milliseconds() -> integer().
now_milliseconds() ->
    erlang:monotonic_time(millisecond).
