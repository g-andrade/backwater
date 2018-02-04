%% Copyright (c) 2017-2018 Guilherme Andrade <backwater@gandrade.net>
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

-module(backwater_module_exposure).

-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([module_name/1]).
-export([interpret_list/1]).
-export([metadata_export_list/0]).      -ignore_xref([metadata_export_list/0]).

-dialyzer({nowarn_function, metadata_export_list/0}).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_MODULE_EXPORTS, all).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type content_type() :: {nonempty_binary(), nonempty_binary()}.
-export_type([content_type/0]).

-type exports() :: #{ fun_arity_pair() => fun_properties() }.
-export_type([exports/0]).

-type t() :: module() | {module(), [opt()]}.
-export_type([t/0]).

-type opt() :: {exports, all | [{atom(),arity()}]}.
-export_type([opt/0]).

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

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec module_name(t()) -> module().
%% @private
module_name({Module, _Opts}) ->
    Module;
module_name(Module) ->
    Module.

-spec interpret_list([t()]) -> #{ BinModule :: nonempty_binary() => module_info() }.
%% @private
interpret_list(ExposedModules) ->
    KvList = lists:filtermap(fun find_and_parse_module_info/1, ExposedModules),
    maps:from_list(KvList).

-spec metadata_export_list() -> [{atom(), arity()}].
metadata_export_list() ->
    [{backwater_export,0}, % faux backwater export attribute in Elixir modules (legacy)
     {behaviour_info,1},   % callbacks
     {module_info,0},      % Erlang module info
     {module_info,1},      % Erlang module info
     {'__info__',1}].      % Elixir module info

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec find_and_parse_module_info(t()) -> lookup_result().
find_and_parse_module_info(ExposedModule) ->
    Module = module_name(ExposedModule),
    case find_module_info(Module) of
        {ok, RawModuleInfo} ->
            BackwaterExports = determine_module_exports(ExposedModule, RawModuleInfo),
            FilteredBackwaterExports =
                maps:filter(
                  fun ({BinFunction, Arity}, _Info) ->
                          Function = binary_to_existing_atom(BinFunction, utf8),
                          not lists:member({Function, Arity}, metadata_export_list())
                  end,
                  BackwaterExports),
            BinModule = atom_to_binary(Module, utf8),
            {true, {BinModule, #{ exports => FilteredBackwaterExports }}};
        error ->
            false
    end.

-spec exposed_module_opts(t()) -> [opt()].
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

-spec determine_module_exports(t(), raw_module_info()) -> exports().
determine_module_exports(ExposedModule, RawModuleInfo) ->
    Module = module_name(ExposedModule),
    Opts = exposed_module_opts(ExposedModule),
    {exports, AtomKeyedExports} = lists:keyfind(exports, 1, RawModuleInfo),

    case proplists:get_value(exports, Opts, ?DEFAULT_MODULE_EXPORTS) of
        all ->
            maps:from_list([backwater_export_entry_pair(Module, Pair) || Pair <- AtomKeyedExports]);
        List when is_list(List) ->
            maps:from_list(
              [backwater_export_entry_pair(Module, Pair) || Pair <- AtomKeyedExports,
               lists:member(Pair, List)])
    end.

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
