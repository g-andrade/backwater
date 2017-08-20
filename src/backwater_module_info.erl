-module(backwater_module_info).

-include("backwater_common.hrl").
-include("backwater_module_info.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([exposed_module_name/1]).
-export([generate/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_MODULE_EXPORTS, use_backwater_attributes).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type content_type() :: {nonempty_binary(), nonempty_binary()}.
-export_type([content_type/0]).

-type exports() :: #{ fun_arity_pair() => fun_properties() }.
-export_type([exports/0]).

-type exposed_module() :: module() | {module(), [exposed_module_opt()]}.
-export_type([exposed_module/0]).

-type exposed_module_opt() :: {exports, all | use_backwater_attributes | [atom()]}.
-export_type([exposed_module_opt/0]).

-type fun_arity_pair() :: {binary(), arity()}.
-export_type([fun_arity_pair/0]).

-type fun_properties() ::
        #{ known_content_types := [content_type(), ...],
           function_ref := fun() }.
-export_type([fun_properties/0]).

-type lookup_result() :: {true, {BinModule :: nonempty_binary(), module_info()}} | false.
-export_type([lookup_result/0]).

-type module_info() :: #{ exports := exports() }.
-export_type([module_info/0]).

-type raw_module_info() :: [{atom(), term()}].
-type raw_module_attributes() :: [{atom(), term()}].

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec exposed_module_name(exposed_module()) -> module().
%% @private
exposed_module_name({Module, _Opts}) ->
    Module;
exposed_module_name(Module) ->
    Module.

-spec generate([exposed_module()]) -> #{ BinModule :: nonempty_binary() => module_info() }.
%% @private
generate(ExposedModules) ->
    KvList = lists:filtermap(fun find_and_parse_module_info/1, ExposedModules),
    maps:from_list(KvList).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec find_and_parse_module_info(exposed_module()) -> lookup_result().
find_and_parse_module_info(ExposedModule) ->
    Module = exposed_module_name(ExposedModule),
    case find_module_info(Module) of
        {ok, RawModuleInfo} ->
            BackwaterExports = determine_module_exports(ExposedModule, RawModuleInfo),
            FilteredBackwaterExports =
                maps:filter(
                  fun ({BinFunction, Arity}, _Info) ->
                          Function = binary_to_existing_atom(BinFunction, utf8),
                          not lists:member({Function, Arity}, ?METADATA_EXPORT_LIST)
                  end,
                  BackwaterExports),
            BinModule = atom_to_binary(Module, utf8),
            {true, {BinModule, #{ exports => FilteredBackwaterExports }}};
        error ->
            false
    end.

-spec exposed_module_opts(exposed_module()) -> [exposed_module_opt()].
exposed_module_opts({_Module, Opts}) ->
    Opts;
exposed_module_opts(_Module) ->
    [].

-spec find_module_info(module()) -> {ok, raw_module_info()} | error.
find_module_info(Module) ->
    try
        {ok, Module:module_info()}
    catch
        error:undef -> error
    end.

-spec determine_module_exports(exposed_module(), raw_module_info()) -> exports().
determine_module_exports(ExposedModule, RawModuleInfo) ->
    Module = exposed_module_name(ExposedModule),
    Opts = exposed_module_opts(ExposedModule),
    {attributes, ModuleAttributes} = lists:keyfind(attributes, 1, RawModuleInfo),
    {exports, AtomKeyedExports} = lists:keyfind(exports, 1, RawModuleInfo),

    case proplists:get_value(exports, Opts, ?DEFAULT_MODULE_EXPORTS) of
        all ->
            maps:from_list([backwater_export_entry_pair(Module, Pair) || Pair <- AtomKeyedExports]);
        use_backwater_attributes ->
            Exports = [{atom_to_binary(K, utf8), V} || {K, V} <- AtomKeyedExports],
            BackwaterExports = module_attributes_get_backwater_exports(Module, ModuleAttributes),
            maps:with(Exports, BackwaterExports);
        List when is_list(List) ->
            maps:from_list(
              [backwater_export_entry_pair(Module, Pair) || Pair <- AtomKeyedExports,
               lists:member(Pair, List)])
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
    % XXX if we ever want to support custom marshalling (e.g. JSON),
    % this would be a good point to start
    Properties =
        #{ known_content_types => [{<<"application">>, <<"x-erlang-etf">>}],
           function_ref => fun Module:AtomF/A },
    F = atom_to_binary(AtomF, utf8),
    {{F,A}, Properties}.
