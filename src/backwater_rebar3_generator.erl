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

-module(backwater_rebar3_generator).

-include("backwater_common.hrl").
-include("backwater_module_info.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([generate/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_PARAM_CLIENT_REF, default).
-define(DEFAULT_PARAM_EXPORTS, use_backwater_attributes).
-define(DEFAULT_PARAM_UNEXPORTED_TYPES, warn).
-define(DEFAULT_PARAM_NAME_PREFIX, "rpc_").
-define(DEFAULT_PARAM_OUTPUT_DIRECTORY__SUBDIR, "rpc").
-define(DUMMY_LINE_NUMBER, (erl_anno:from_term(1))).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type opt() ::
    {target, target()} |
    overridable_opt().
-export_type([opt/0]).

-type target() ::
        module() | % search under current app
        {module(), [target_opt()]} | % search under current app
        {AppName :: atom(), module()} |
        {AppName :: atom(), module(), [target_opt()]}.
-export_type([target/0]).

-type target_opt() ::
        target_module_opt() |
        overridable_opt().

-type target_module_opt() ::
        {exports, target_exports()}.
-export_type([target_module_opt/0]).

-type target_exports() ::
        all |                       % all exported functions
        use_backwater_attributes |  % use custom backwater attributes
        [atom()].                   % use custom list
-export_type([target_exports/0]).

-type overridable_opt() ::
        {client_ref, term()} | % 'default' by default
        {module_name_prefix, file:name_all()} | % "rpc_" by default
        {module_name_suffix, file:name_all()} | % "" by default
        {unexported_types, ignore | warn | error | abort} | % warn by default
        {output_src_dir, file:name_all()}. % "src/rpc" by default
-export_type([overridable_opt/0]).

-type generation_params() ::
        #{ (module_name | module_path) => (atom() | file:name_all()), % compiled vs. source modules
           current_app_info => rebar_app_info:t(),
           target_opts => [target_opt()] }.

-type module_info() ::
        #{ module => module(),
           original_path => file:name_all(),
           exports => sets:set(name_arity()),
           type_exports => sets:set(name_arity()),
           deprecation_attributes => sets:set(tuple() | [tuple()]),
           backwater_exports => sets:set(name_arity()),
           function_specs => #{ name_arity() => [erl_parse:abstract_form()]  },
           function_definitions => #{ name_arity() => [function_definition()] },
           original_module => atom(),
           missing_types_messages => sets:set(missing_types_message())
         }.

-type name_arity() :: {Name :: atom(), arity()}.

-type function_definition() :: #{ vars => [term()] }.

-type missing_types_message() ::
        {ModulePath :: file:name_all(),
         Line :: pos_integer(),
         Fmt :: nonempty_string(),
         FmtArgs :: list()}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec generate(State :: rebar_state:t()) -> ok | {error, term()}.
%% @private
generate(State) ->
    AppInfos =
        case rebar_state:current_app(State) of
            undefined ->
                rebar_state:project_apps(State);
            AppInfo ->
                [AppInfo]
        end,

    SourceDirectoriesPerApp =
        lists:foldl(
          fun (AppInfo, Acc) ->
                  AppName = binary_to_atom(rebar_app_info:name(AppInfo), utf8),
                  AppSourceDirectories = app_info_src_directories(AppInfo),
                  dict:append_list(AppName, AppSourceDirectories, Acc)
          end,
          dict:new(),
          AppInfos ++ rebar_state:all_deps(State)),

    backwater_util:lists_foreach_until_error(
      fun (AppInfo) ->
              generate(AppInfo, SourceDirectoriesPerApp)
      end,
      AppInfos).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec generate(rebar_app_info:t(), dict:dict(atom(), [file:name_all()])) -> ok | {error, term()}.
generate(CurrentAppInfo, SourceDirectoriesPerApp) ->
    RebarOpts = rebar_app_info:opts(CurrentAppInfo),
    BackwaterOptsLookup = dict:find(backwater_gen, RebarOpts),
    generate(CurrentAppInfo, SourceDirectoriesPerApp, BackwaterOptsLookup).

-spec generate(rebar_app_info:t(), dict:dict(atom(), [file:name_all()]), error | {ok, [opt()]})
        -> ok | {error, term()}.
generate(_CurrentAppInfo, _SourceDirectoriesPerApp, error) ->
    {error, {missing_options, backwater_gen}};
generate(CurrentAppInfo, SourceDirectoriesPerApp, {ok, BackwaterOpts}) ->
    UnprocessedTargets = proplists:get_all_values(target, BackwaterOpts),
    CurrentAppName = binary_to_atom(rebar_app_info:name(CurrentAppInfo), utf8),

    GlobalTargetOpts =
        lists:filter(
          fun ({target, _}) -> false;
              (_) -> true
          end,
          BackwaterOpts),

    Targets =
        lists:map(
          fun (Module) when is_atom(Module) ->
                  {CurrentAppName, Module, GlobalTargetOpts};
              ({Module, Opts}) when is_atom(Module), is_list(Opts) ->
                  MergedOpts = backwater_util:proplists_sort_and_merge(GlobalTargetOpts, Opts),
                  {CurrentAppName, Module, MergedOpts};
              ({AppName, Module}) when is_atom(AppName), is_atom(Module) ->
                  {AppName, Module, GlobalTargetOpts};
              ({AppName, Module, Opts}) when is_atom(AppName), is_atom(Module), is_list(Opts) ->
                  MergedOpts = backwater_util:proplists_sort_and_merge(GlobalTargetOpts, Opts),
                  {AppName, Module, MergedOpts}
          end,
          UnprocessedTargets),

    backwater_util:lists_foreach_until_error(
      fun ({AppName, Module, TargetOpts}) ->
              backwater_util:with_success(
                fun (GenerationParams1) ->
                        GenerationParams2 =
                            GenerationParams1#{
                              current_app_info => CurrentAppInfo,
                              target_opts => TargetOpts },
                            generate_backwater_code(GenerationParams2)
                end,
                find_module_name_or_path(AppName, Module, SourceDirectoriesPerApp))
      end,
      Targets).

-spec generate_backwater_code(generation_params()) -> ok | {error, term()}.
generate_backwater_code(GenerationParams) ->
    backwater_util:with_success(
      fun (ModulePath, Forms) ->
              ParseResult = lists:foldl(fun parse_module/2, dict:new(), Forms),
              ModuleInfo = generate_module_info(ModulePath, ParseResult),
              TransformedModuleInfo = transform_module(GenerationParams, ModuleInfo),
              write_module(GenerationParams, TransformedModuleInfo)
      end,
      read_forms(GenerationParams)).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Finding the Code
%% ------------------------------------------------------------------

-spec app_info_src_directories(rebar_app_info:t()) -> [file:name_all()].
app_info_src_directories(AppInfo) ->
    BaseDir = rebar_app_info:dir(AppInfo),
    Opts = rebar_app_info:opts(AppInfo),
    ErlOpts = rebar_opts:get(Opts, erl_opts, []),
    RelDirs = rebar_opts:get(Opts, src_dirs, proplists:get_value(src_dirs, ErlOpts, ["src"])),
    [filename:join(ec_cnv:to_list(BaseDir), RelDir) || RelDir <- RelDirs].

-spec find_module_name_or_path(atom(), module(), dict:dict(atom(), [file:name_all()]))
        -> {ok, generation_params()} | {error, term()}.
find_module_name_or_path(AppName, Module, SourceDirectoriesPerApp) ->
    case dict:find(AppName, SourceDirectoriesPerApp) of
        {ok, SourceDirectories} ->
            find_module_path(Module, SourceDirectories);
        error ->
            case application:load(AppName) of
                ok ->
                    {ok, #{ module_name => Module }};
                {error, {already_loaded, AppName}} ->
                    {ok, #{ module_name => Module }};
                {error, Error} ->
                    {error, {unable_to_load_application, Error}}
            end
    end.

-spec find_module_path(module(), [file:name_all()])
        -> {ok, generation_params()} | {error, term()}.
find_module_path(Module, SourceDirectories) ->
    ModuleStr = atom_to_list(Module),
    MaybeSourceDirectoriesWithFiles =
        backwater_util:lists_map_until_error(
          fun (SourceDirectory) ->
                  backwater_util:with_success(
                    fun (SourceFiles) ->
                            {ok, {SourceDirectory, SourceFiles}}
                    end,
                    directory_source_files(SourceDirectory))
          end,
          SourceDirectories),

    backwater_util:with_success(
      fun (SourceDirectoriesWithFiles) ->
              SearchResult =
                backwater_util:lists_anymap(
                  fun ({SourceDirectory, SourceFiles}) ->
                          ExpectedPrefix = filename:join(SourceDirectory, ModuleStr) ++ ".",
                          backwater_util:lists_anymap(
                            fun (SourceFile) ->
                                    length(SourceFile) =:= length(ExpectedPrefix) + 3
                                    andalso lists:prefix(ExpectedPrefix, SourceFile)
                            end,
                            SourceFiles)
                  end,
                  SourceDirectoriesWithFiles),

              case SearchResult of
                  {true, SourceFile} ->
                      {ok, #{ module_path => SourceFile }};
                  false ->
                      {error, {module_not_found, Module}}
              end
      end,
      MaybeSourceDirectoriesWithFiles).

-spec directory_source_files(file:name_all()) -> {ok, [file:name_all()]} | {error, term()}.
directory_source_files(SrcDir) ->
    case file:list_dir(SrcDir) of
        {ok, Filenames} ->
            Extension = binary_to_list(?OPAQUE_BINARY(<<"erl">>)),
            FilteredFilenames = filter_filenames_by_extension(Filenames, Extension),
            {ok, full_paths(SrcDir, FilteredFilenames)};
        {error, enotdir} ->
            {ok, []};
        {error, OtherError} ->
            {error, {cant_list_directory, SrcDir, OtherError}}
    end.

-spec filter_filenames_by_extension([file:name_all()], nonempty_string()) -> [file:name_all()].
filter_filenames_by_extension(Filenames, Extension) ->
    ExtensionWithDot = [$. | Extension],
    lists:filter(
      fun (Filename) ->
              (lists:suffix(ExtensionWithDot, Filename) andalso
               length(Filename) > length(ExtensionWithDot))
      end,
      Filenames).

-spec full_paths(file:name_all(), [file:name_all()]) -> [file:name_all()].
full_paths(Dir, Names) ->
    [filename:join(Dir, Name) || Name <- Names].

%% ------------------------------------------------------------------
%% Internal Function Definitions - Parsing the Original Code
%% ------------------------------------------------------------------

%%
%% Based on forms[1] by Enrique Fernández, MIT License,
%% commit 491b6768dd9d4f2cd22a90327041b630f68dd66a
%%
%% [1]: https://github.com/efcasado/forms
%%
-spec read_forms(generation_params())
        -> {ok, file:name_all(), [erl_parse:abstract_form()]} |
           {error, term()}.
read_forms(#{ module_name := Module })  ->
    ModuleStr = atom_to_list(Module),
    ModulePath = code:where_is_file(ModuleStr ++ ".beam"),
    try beam_lib:chunks(ModulePath, [abstract_code]) of
        {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            {ok, ModulePath, Forms};
        {ok, {no_debug_info, _}} ->
            {error, {debug_info_not_found, Module}};
        {error, beam_lib, BeamLibError} ->
            {error, {{beam_lib, BeamLibError}, Module}}
    catch
        Class:Error ->
            {error, {{Class, Error}, Module}}
    end;
read_forms(#{ module_path := ModulePath }) ->
    try epp:parse_file(ModulePath, []) of
        {ok, Forms} ->
            {ok, ModulePath, Forms};
        {ok, Forms, _Extra} ->
            {ok, Forms};
        {error, enoent} ->
            {error, {file_not_found, ModulePath}}
    catch
        Class:Error ->
            {error, {{Class, Error}, ModulePath}}
    end.

-spec parse_module(erl_parse:abstract_form(), dict:dict()) -> dict:dict().
parse_module({attribute, _Line, module, Module}, Acc) ->
    dict:store(module, Module, Acc);
parse_module({attribute, _Line, export, Pairs}, Acc) ->
    dict:append_list(exports, Pairs, Acc);
parse_module({attribute, _Line, export_type, Pairs}, Acc) ->
    dict:append_list(type_exports, Pairs, Acc);
parse_module({attribute, _Line, deprecated, Data}, Acc) when is_list(Data) ->
    dict:append_list(deprecation_attributes, Data, Acc);
parse_module({attribute, _Line, deprecated, Data}, Acc) ->
    dict:append(deprecation_attributes, Data, Acc);
parse_module({attribute, _Line, backwater_export, {Name, Arity}}, Acc) ->
    dict:append(backwater_exports, {Name, Arity}, Acc);
parse_module({attribute, _Line, backwater_export, List}, Acc) when is_list(List) ->
    dict:append_list(backwater_exports, List, Acc);
parse_module({attribute, _Line, spec, {{_Name, _Arity}, _Definitions} = Spec}, Acc) ->
    dict:append(function_specs, Spec, Acc);
parse_module({function, _Line, Name, Arity, Clauses}, Acc) ->
    Definitions =
        lists:map(
          fun ({clause, _ClauseLine, Vars, _Guards, _Body}) when length(Vars) =:= Arity ->
                  #{ vars => Vars }
          end,
          Clauses),

    dict:update(
      function_definitions,
      fun (Previous) -> dict:append_list({Name, Arity}, Definitions, Previous) end,
      dict:from_list([{{Name, Arity}, Definitions}]),
      Acc);
parse_module(_Other, Acc) ->
    Acc.

-spec generate_module_info(file:name_all(), dict:dict()) -> module_info().
generate_module_info(ModulePath, ParseResult) ->
    BaseModuleInfo =
        #{ original_path => ModulePath,
           exports => sets:new(),
           type_exports => sets:new(),
           deprecation_attributes => sets:new(),
           backwater_exports => sets:new(),
           function_specs => maps:new(),
           function_definitions => maps:new() },

    ModuleInfo =
        maps:from_list(
          dict:to_list(
            dict:map(
              fun (module, Module) ->
                      Module;
                  (exports, Exports) ->
                      sets:from_list(Exports);
                  (deprecation_attributes, DeprecationAttributes) ->
                      sets:from_list(DeprecationAttributes);
                  (type_exports, TypeExports) ->
                      sets:from_list(TypeExports);
                  (backwater_exports, BackwaterExports) ->
                      sets:from_list(BackwaterExports);
                  (function_specs, FunctionSpecs) ->
                      maps:from_list(FunctionSpecs);
                  (function_definitions, FunctionDefinitions) ->
                      maps:from_list( dict:to_list(FunctionDefinitions) )
              end,
              ParseResult))),

    maps:merge(BaseModuleInfo, ModuleInfo).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Transforming the Code
%% ------------------------------------------------------------------

-spec transform_module(generation_params(), module_info()) -> module_info().
transform_module(GenerationParams, ModuleInfo1) ->
    ModuleInfo2 = transform_exports(GenerationParams, ModuleInfo1),
    ModuleInfo3 = trim_deprecation_attributes(ModuleInfo2),
    ModuleInfo4 = trim_functions_and_specs(ModuleInfo3),
    ModuleInfo5 = externalize_function_specs_user_types(GenerationParams, ModuleInfo4),
    rename_module(GenerationParams, ModuleInfo5).

-spec transform_exports(generation_params(), module_info()) -> module_info().
transform_exports(GenerationParams, ModuleInfo1) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    #{ exports := Exports1, backwater_exports := BackwaterExports } = ModuleInfo1,
    ModuleInfo2 = maps:remove(backwater_exports, ModuleInfo1),
    Exports2 =
        case proplists:get_value(exports, TargetOpts, ?DEFAULT_PARAM_EXPORTS)
        of
            all -> Exports1;
            use_backwater_attributes -> sets:intersection(Exports1, BackwaterExports);
            List when is_list(List) -> sets:intersection(Exports1, sets:from_list(List))
        end,
    Exports3 = sets:subtract(Exports2, sets:from_list(?METADATA_EXPORT_LIST)),
    ModuleInfo2#{ exports := Exports3 }.

-spec trim_deprecation_attributes(module_info()) -> module_info().
trim_deprecation_attributes(ModuleInfo) ->
    #{ exports := Exports, deprecation_attributes := DeprecationAttributes1 } = ModuleInfo,
    ExportsList = sets:to_list(Exports),
    ExportedNamesList = [Function || {Function, _Arity} <- ExportsList],
    ExportedNames = sets:from_list(ExportedNamesList),

    List = sets:to_list(DeprecationAttributes1),
    Flattened = lists:flatten(List),
    Filtered =
        lists:filter(
          fun (Tuple) when is_tuple(Tuple), tuple_size(Tuple) >= 2 ->
                  Function = element(1, Tuple),
                  Arity = element(2, Tuple),
                  if Function =:= '_' ->
                         sets:size(Exports) > 0;
                     Arity =:= '_' ->
                         sets:is_element(Function, ExportedNames);
                     true ->
                         sets:is_element({Function, Arity}, Exports)
                  end;
              (Other) when is_atom(Other); is_tuple(Other) ->
                  true
          end,
          Flattened),

    DeprecationAttributes2 = sets:from_list(Filtered),
    ModuleInfo#{ deprecation_attributes := DeprecationAttributes2 }.

-spec trim_functions_and_specs(module_info()) -> module_info().
trim_functions_and_specs(ModuleInfo) ->
    #{ exports := Exports,
       function_definitions := FunctionDefinitions,
       function_specs := FunctionSpecs } = ModuleInfo,
    ModuleInfo#{
      function_definitions => maps:with(sets:to_list(Exports), FunctionDefinitions),
      function_specs => maps:with(sets:to_list(Exports), FunctionSpecs) }.

-spec rename_module(generation_params(), module_info()) -> module_info().
rename_module(GenerationParams, ModuleInfo) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    #{ module := Module1 } = ModuleInfo,
    Module1Str = atom_to_list(Module1),
    Module2Str =
        case {proplists:get_value(module_name_prefix, TargetOpts),
              proplists:get_value(module_name_suffix, TargetOpts)}
        of
            {undefined, undefined} ->
                ?DEFAULT_PARAM_NAME_PREFIX ++ Module1Str;
            {undefined, Suffix} ->
                Module1Str ++ Suffix;
            {Prefix, undefined} ->
                Prefix ++ Module1Str;
            {Prefix, Suffix} ->
                Prefix ++ Module1Str ++ Suffix
        end,
    Module2 = list_to_atom(Module2Str),
    ModuleInfo#{ module => Module2, original_module => Module1 }.

-spec write_module(generation_params(), module_info()) -> ok | {error, term()}.
write_module(GenerationParams, ModuleInfo) ->
    ClientRef = target_client_ref(GenerationParams),
    OutputDirectory = target_output_directory(GenerationParams),
    ok = ensure_directory_exists(OutputDirectory),
    #{ module := Module } = ModuleInfo,
    ModuleFilename = filename:join(OutputDirectory, atom_to_list(Module) ++ ".erl"),
    ModuleSrc = generate_module_source(ClientRef, ModuleInfo),
    case file:write_file(ModuleFilename, ModuleSrc) of
        ok -> ok;
        {error, Error} -> {error, {couldnt_save_module, Error}}
    end.

-spec target_client_ref(generation_params()) -> term().
target_client_ref(GenerationParams) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    proplists:get_value(client_ref, TargetOpts, ?DEFAULT_PARAM_CLIENT_REF).

-spec target_output_directory(generation_params()) -> file:name_all().
target_output_directory(GenerationParams) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    case proplists:get_value(output_src_dir, TargetOpts) of
        undefined ->
            #{ current_app_info := CurrentAppInfo } = GenerationParams,
            CurrentAppSourceDirectories = app_info_src_directories(CurrentAppInfo),
            filename:join(hd(CurrentAppSourceDirectories), ?DEFAULT_PARAM_OUTPUT_DIRECTORY__SUBDIR);
        OutputDirectory ->
            OutputDirectory
    end.

-spec ensure_directory_exists(file:name_all()) -> ok.
ensure_directory_exists(Path) ->
    AbsPath = filename:absname(Path),
    Parts = filename:split(AbsPath),
    ensure_directory_exists_recur(Parts, "").

-spec ensure_directory_exists_recur([file:name_all()], file:name_all())
        -> ok | {error, atom()}.
ensure_directory_exists_recur([], _) ->
    ok;
ensure_directory_exists_recur([H|T], Acc) ->
    Path = filename:join(Acc, H),
    case file:make_dir(Path) of
        ok -> ensure_directory_exists_recur(T, Path);
        {error, eexist} -> ensure_directory_exists_recur(T, Path);
        {error, _} = Error -> Error
    end.

-spec externalize_function_specs_user_types(generation_params(), module_info())
        -> module_info().
externalize_function_specs_user_types(GenerationParams, ModuleInfo1) ->
    % do it
    #{ function_specs := FunctionSpecs1 } = ModuleInfo1,
    Acc1 = ModuleInfo1#{ missing_types_messages => sets:new() },
    {FunctionSpecs2, Acc2} =
        backwater_util:maps_mapfold(
          fun externalize_function_spec_definitions_user_types/3,
          Acc1,
          FunctionSpecs1),
    #{ missing_types_messages := MissingTypesMessages } = Acc2,
    ModuleInfo2 = maps:without([missing_types_messages], Acc2),
    ModuleInfo3 = ModuleInfo2#{ function_specs => FunctionSpecs2 },

    % handle types and records warnings
    (sets:size(MissingTypesMessages) > 0 andalso
     begin
         #{ target_opts := TargetOpts } = GenerationParams,
         MissingTypesBehaviour =
            proplists:get_value(unexported_types, TargetOpts, ?DEFAULT_PARAM_UNEXPORTED_TYPES),
         MissingTypesMsgFunction = missing_type_msg_function(MissingTypesBehaviour),
         MissingTypesMessagesList = lists:sort( sets:to_list(MissingTypesMessages) ),
         FormattedMsg =
            lists:foldl(
              fun ({ModulePath, Line, Fmt, Args}, Acc) ->
                      [Acc, "\n", io_lib:format("~s:~p - " ++ Fmt, [ModulePath, Line | Args])]
              end,
              [],
              MissingTypesMessagesList),
         MissingTypesMsgFunction(FormattedMsg, [])
     end),

    ModuleInfo3.

-spec externalize_function_spec_definitions_user_types(name_arity(), [erl_parse:abstract_form()],
                                                       module_info())
        -> {[erl_parse:abstract_form()], module_info()}.
externalize_function_spec_definitions_user_types({_Name, _Arity}, Definitions, Acc) ->
    lists:mapfoldl(fun externalize_user_types/2, Acc, Definitions).

%-spec externalize_user_types(erl_parse:abstract_form(), module_info())
%        -> {erl_parse:abstract_form(), module_info()}.
externalize_user_types({type, Line, record, Args}, Acc1) ->
    {atom, _NameLine, Name} = hd(Args),
    Acc2 = handle_unexported_record_reference(Line, Name, Acc1),
    {{type, Line, term, []}, Acc2};
externalize_user_types({user_type, Line, Name, Args1}, Acc1) ->
    {Args2, Acc2} = externalize_user_types(Args1, Acc1),
    #{ module := Module, type_exports := TypeExports } = Acc2,
    Arity = length(Args2),
    Id = {Name, Arity},
    Acc3 =
        case sets:is_element(Id, TypeExports) of
            true -> Acc2;
            false -> handle_unexported_type(Line, Name, Arity, Acc2)
        end,
    {{remote_type, Line, [{atom, Line, Module}, {atom, Line, Name}, Args2]}, Acc3};
externalize_user_types(List, Acc) when is_list(List) ->
    lists:mapfoldl(fun externalize_user_types/2, Acc, List);
externalize_user_types(Literal, Acc) when is_atom(Literal); is_integer(Literal) ->
    {Literal, Acc};
externalize_user_types({LiteralType, _Line, _LiteralValue} = T, Acc)
  when LiteralType =:= atom;
       LiteralType =:= char;
       LiteralType =:= float;
       LiteralType =:= integer;
       LiteralType =:= string ->
    {T, Acc};
externalize_user_types({ann_type, Line, Types1}, Acc1) ->
    {Types2, Acc2} = externalize_user_types(Types1, Acc1),
    {{ann_type, Line, Types2}, Acc2};
externalize_user_types({op, Line, Op, Arg1}, Acc1) ->
    % unary operator
    {Arg2, Acc2} = externalize_user_types(Arg1, Acc1),
    {{op, Line, Op, Arg2}, Acc2};
externalize_user_types({op, Line, Op, Left1, Right1}, Acc1) ->
    % binary operator
    {Left2, Acc2} = externalize_user_types(Left1, Acc1),
    {Right2, Acc3} = externalize_user_types(Right1, Acc2),
    {{op, Line, Op, Left2, Right2}, Acc3};
externalize_user_types({remote_type, Line, [ModuleSpec1, FunctionSpec1, Args1]}, Acc1) ->
    {ModuleSpec2, Acc2} = externalize_user_types(ModuleSpec1, Acc1),
    {FunctionSpec2, Acc3} = externalize_user_types(FunctionSpec1, Acc2),
    {Args2, Acc4} = externalize_user_types(Args1, Acc3),
    {{remote_type, Line, [ModuleSpec2, FunctionSpec2, Args2]}, Acc4};
externalize_user_types({type, _Line, _Builtin, any} = T, Acc) ->
    {T, Acc};
externalize_user_types({type, Line, Builtin, Args1}, Acc1) when is_list(Args1) ->
    {Args2, Acc2} = externalize_user_types(Args1, Acc1),
    {{type, Line, Builtin, Args2}, Acc2};
externalize_user_types({type, _Line, _Builtin} = T, Acc) ->
    {T, Acc};
externalize_user_types({var, _Line, _Name} = T, Acc) ->
    {T, Acc}.

-spec handle_unexported_record_reference(pos_integer(), atom(), module_info())
        -> module_info().
handle_unexported_record_reference(Line, Name, Acc) ->
    % XXX consider using this: http://erlang.org/doc/man/erl_expand_records.html
    backwater_util:maps_update_with(
      missing_types_messages,
      fun (Prev) ->
              #{ original_path := ModulePath } = Acc,
              Msg = {ModulePath, Line, "Reference to unexportable record #~p{}", [Name]},
              sets:add_element(Msg, Prev)
      end,
      Acc).

-spec handle_unexported_type(pos_integer(), atom(), arity(), module_info())
        -> module_info().
handle_unexported_type(Line, Name, Arity, Acc) ->
    backwater_util:maps_update_with(
      missing_types_messages,
      fun (Prev) ->
              #{ original_path := ModulePath } = Acc,
              Msg = {ModulePath, Line, "Reference to unexported type ~p/~p", [Name, Arity]},
              sets:add_element(Msg, Prev)
      end,
      Acc).

-spec missing_type_msg_function(ignore | warn | error | abort)
        -> fun((nonempty_string(), list()) -> ok).
missing_type_msg_function(ignore) ->
    fun rebar_api:debug/2;
missing_type_msg_function(warn) ->
    fun rebar_api:warn/2;
missing_type_msg_function(error) ->
    fun rebar_api:error/2;
missing_type_msg_function(abort) ->
    fun rebar_api:abort/2.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Generating the New Code
%% ------------------------------------------------------------------

%-spec generate_module_source(term(), module_info()) -> iolist().
generate_module_source(ClientRef, ModuleInfo) ->
    Header = generate_module_source_header(ModuleInfo),
    Exports = generate_module_source_exports(ModuleInfo),
    XRefAttributes = generate_module_source_xref_attributes(ModuleInfo),
    FunctionSpecs = generate_module_source_function_specs(ModuleInfo),
    FunctionDefinitions = generate_module_source_function_definitions(ClientRef, ModuleInfo),

    [Header,
     generate_module_source_section("Exports", Exports),
     generate_module_source_section("Xref", XRefAttributes),
     generate_module_source_section("Specifications", FunctionSpecs),
     generate_module_source_section("Definitions", FunctionDefinitions)].

-spec generate_module_source_header(module_info()) -> iolist().
generate_module_source_header(ModuleInfo) ->
    #{ module := Module } = ModuleInfo,
    erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, module, Module}).

-spec generate_module_source_exports(module_info()) -> [iolist()].
generate_module_source_exports(ModuleInfo) ->
    #{ exports := Exports } = ModuleInfo,
    ExportsList = lists:sort( sets:to_list(Exports) ),
    lists:map(
      fun ({Name, Arity}) ->
              erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, export, [{Name, Arity}]})
      end,
      ExportsList).

%-spec generate_module_source_xref_attributes(module_info()) -> [iolist()].
generate_module_source_xref_attributes(ModuleInfo) ->
    #{ exports := Exports, deprecation_attributes := DeprecationAttributes } = ModuleInfo,
    ExportsList = lists:sort( sets:to_list(Exports) ),
    DeprecationAttributesList = lists:sort( sets:to_list(DeprecationAttributes) ),

    AbstractIgnoreAttributes =
        lists:map(
          fun ({Name, Arity}) ->
                  erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, ignore_xref, {Name, Arity}})
          end,
          ExportsList),

    AbstractDeprecationAttributes =
        lists:map(
          fun (Data) ->
                  erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, deprecated, Data})
          end,
          DeprecationAttributesList),

    [AbstractIgnoreAttributes,
     case AbstractIgnoreAttributes =/= [] andalso AbstractDeprecationAttributes =/= [] of
         true -> "\n";
         false -> ""
     end,
     AbstractDeprecationAttributes].

-spec generate_module_source_function_specs(module_info()) -> [iolist()].
generate_module_source_function_specs(ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions } = ModuleInfo,
    FunctionNameArities = lists:keysort(1, maps:keys(FunctionDefinitions)),
    List =
        lists:map(
          fun ({Name, Arity}) ->
                  generate_module_source_function_spec({Name, Arity}, ModuleInfo)
          end,
          FunctionNameArities),
    backwater_util:lists_join("\n", List).

-spec generate_module_source_function_spec(name_arity(), module_info()) -> iolist().
generate_module_source_function_spec({Name, Arity}, ModuleInfo) ->
    #{ function_specs := FunctionSpecs } = ModuleInfo,
    Attribute =
        case maps:find({Name, Arity}, FunctionSpecs) of
            {ok, Definitions} ->
                WrappedDefinitions =
                    [wrap_function_spec_return_types(Definition) || Definition <- Definitions],
                {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, WrappedDefinitions}};
            error ->
                Definition = generic_function_spec(Arity),
                {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, [Definition]}}
        end,
    erl_pp:attribute(Attribute).

-spec generate_module_source_function_definitions(term(), module_info()) -> [iolist()].
generate_module_source_function_definitions(ClientRef, ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions } = ModuleInfo,
    FunctionDefinitionsList = lists:keysort(1, maps:to_list(FunctionDefinitions)),
    List =
        lists:map(
          fun (FunctionDefinitionKV) ->
                  generate_module_source_function(ClientRef, FunctionDefinitionKV, ModuleInfo)
          end,
          FunctionDefinitionsList),
    backwater_util:lists_join("\n", List).

wrap_function_spec_return_types({type, Line, 'fun', [ArgSpecs, ReturnSpec]}) ->
    WrappedReturnSpec = wrap_return_type(ReturnSpec),
    {type, Line, 'fun', [ArgSpecs, WrappedReturnSpec]};
wrap_function_spec_return_types({type, Line, bounded_fun, [FunSpec, Constraints]}) ->
    WrappedFunSpec = wrap_function_spec_return_types(FunSpec),
    {type, Line, bounded_fun, [WrappedFunSpec, Constraints]}.

generic_function_spec(Arity) ->
    TermType = {type, ?DUMMY_LINE_NUMBER, term, []},
    ArgSpecs = {type, ?DUMMY_LINE_NUMBER, product, backwater_util:copies(TermType, Arity)},
    ReturnSpec = wrap_return_type(TermType),
    {type, ?DUMMY_LINE_NUMBER, 'fun', [ArgSpecs, ReturnSpec]}.

wrap_return_type(OriginalType) ->
    SuccessSpec =
        {type, ?DUMMY_LINE_NUMBER, tuple,
         [{atom, ?DUMMY_LINE_NUMBER, ok}, OriginalType]},
    ErrorValueSpec =
        {remote_type, ?DUMMY_LINE_NUMBER,
         [{atom, ?DUMMY_LINE_NUMBER, backwater_client},
          {atom, ?DUMMY_LINE_NUMBER, error},
          []]},
    ErrorSpec =
        {type, ?DUMMY_LINE_NUMBER, tuple,
         [{atom, ?DUMMY_LINE_NUMBER, error}, ErrorValueSpec]},
    {type, ?DUMMY_LINE_NUMBER, union, [SuccessSpec, ErrorSpec]}.

-spec generate_module_source_function(term(), {name_arity(), [function_definition()]}, module_info())
        -> iolist().
generate_module_source_function(ClientRef, {{Name, Arity}, Definitions}, ModuleInfo) ->
    #{ original_module := OriginalModule } = ModuleInfo,
    IndexedVarLists = generate_module_source_indexed_var_lists(Definitions),
    ArgNames = generate_module_source_arg_names(Arity, IndexedVarLists),
    UniqueArgNames = generate_module_source_unique_arg_names(Arity, ArgNames),
    ArgVars = [{var, ?DUMMY_LINE_NUMBER, list_to_atom(StringName)} || StringName <- UniqueArgNames],
    Guards = [],
    Body = generate_module_source_function_body(
             ClientRef, OriginalModule, Name, ArgVars),
    Clause = {clause, ?DUMMY_LINE_NUMBER, ArgVars, Guards, Body},
    erl_pp:function({function, ?DUMMY_LINE_NUMBER, Name, Arity, [Clause]}).

-spec generate_module_source_indexed_var_lists([function_definition()])
        -> [{pos_integer(), [term()]}].
generate_module_source_indexed_var_lists(Definitions) ->
    IndexedVarListsDict =
        lists:foldl(
          fun (#{ vars := Vars }, AccA) ->
                  EnumeratedVars = backwater_util:lists_enumerate(Vars),
                  lists:foldl(
                    fun ({Index, Var}, AccB) ->
                            orddict:append(Index, Var, AccB)
                    end,
                    AccA,
                    EnumeratedVars)
          end,
          orddict:new(),
          Definitions),
    orddict:to_list(IndexedVarListsDict).

-spec generate_module_source_arg_names(arity(), [{pos_integer(), [term()]}])
        -> [nonempty_string()].
generate_module_source_arg_names(Arity, IndexedVarLists) ->
    lists:map(
      fun ({Index, Vars}) ->
              ArgNames = filter_arg_names_from_function_vars(Vars),
              CleanArgNames = lists:map(fun clean_arg_name/1, ArgNames),
              ValidArgNames = lists:filter(fun is_valid_arg_name/1, CleanArgNames),
              UniqueArgNames1 = lists:usort(ValidArgNames),
              UniqueArgNames2 =
                case UniqueArgNames1 =:= [] of
                    true -> [generated_arg_name(Arity, Index)];
                    false -> UniqueArgNames1
                end,
              Concat = string:join(UniqueArgNames2, "_Or_"),
              case length(Concat) > 255 of % atom limit
                  true -> generated_arg_name(Arity, Index);
                  false -> Concat
              end
      end,
      IndexedVarLists).

-spec filter_arg_names_from_function_vars([term()]) -> [nonempty_string()].
filter_arg_names_from_function_vars(Vars) ->
    lists:foldr(
      fun F({var, _Line, AtomName}, Acc) ->
              [atom_to_list(AtomName) | Acc];
          F({match, _Line1, Left, Right}, Acc1) ->
              Acc2 = F(Right, Acc1),
              F(Left, Acc2);
          F(_Other, Acc) ->
              Acc
      end,
      [],
      Vars).

-spec clean_arg_name(nonempty_string()) -> string().
clean_arg_name(ArgName1) ->
    ArgName2 = lists:dropwhile(fun (C) -> C =:= $_ end, ArgName1), % drop prefixing underscores
    lists:takewhile(fun (C) -> C =/= $_ end, ArgName2).            % drop trailing underscores

-spec is_valid_arg_name(string()) -> boolean().
is_valid_arg_name(ArgName) ->
    length(ArgName) > 0 andalso                        % non-empty
    [hd(ArgName)] =:= string:to_upper([hd(ArgName)]).  % first character is upper case

-spec generated_arg_name(arity(), pos_integer()) -> nonempty_string().
generated_arg_name(FunctionArity, Index) when FunctionArity =:= 1, Index =:= 1 ->
    "Arg";
generated_arg_name(_FunctionArity, Index) ->
    "Arg" ++ integer_to_list(Index).

-spec generate_module_source_unique_arg_names(arity(), [nonempty_string()])
        -> [nonempty_string()].
generate_module_source_unique_arg_names(Arity, ArgNames) ->
    CountPerArgName =
        lists:foldl(
          fun (ArgName, Acc) ->
                  dict:update_counter(ArgName, +1, Acc)
          end,
          dict:new(),
          ArgNames),

    case lists:any(fun ({_ArgName, Count}) -> Count > 1 end, dict:to_list(CountPerArgName)) of
        false ->
            % no conflicts
            ArgNames;
        true ->
            {MappedArgNames, _} =
                lists:mapfoldl(
                  fun (ArgName, Index) ->
                          MappedArgName =
                            case dict:fetch(ArgName, CountPerArgName) of
                                1 -> ArgName;
                                _ -> generated_arg_name(Arity, Index)
                            end,
                          {MappedArgName, Index + 1}
                  end,
                  1,
                  ArgNames),

            generate_module_source_unique_arg_names(Arity, MappedArgNames)
    end.

generate_module_source_function_body(ClientRef, OriginalModule, Name, ArgVars) ->
    [fully_qualified_call_clause(ClientRef, OriginalModule, Name, ArgVars)].

fully_qualified_call_clause(ClientRef, OriginalModule, Name, ArgVars) ->
    Call =
        {remote, ?DUMMY_LINE_NUMBER,
         {atom, ?DUMMY_LINE_NUMBER, backwater_client},
         {atom, ?DUMMY_LINE_NUMBER, call}},
    Args =
        [erl_syntax:revert( erl_syntax:abstract(ClientRef) ),
         {atom, ?DUMMY_LINE_NUMBER, OriginalModule},
         {atom, ?DUMMY_LINE_NUMBER, Name},
         fully_qualified_call_clause_args(ArgVars)],
    {call, ?DUMMY_LINE_NUMBER, Call, Args}.

fully_qualified_call_clause_args([]) ->
    {nil, ?DUMMY_LINE_NUMBER};
fully_qualified_call_clause_args([H|T]) ->
    {cons, ?DUMMY_LINE_NUMBER, H, fully_qualified_call_clause_args(T)}.

generate_module_source_section(Comment, Data) ->
    case iolist_size(Data) =:= 0 of
        true -> "";
        false ->
            [generate_module_source_section_header_comment(Comment), Data]
    end.

generate_module_source_section_header_comment(Comment) ->
    Rule = "% ------------------------------------------------------------------",
    Forms = [erl_syntax:comment([Rule, "% " ++ Comment, Rule])],
    ["\n", erl_prettypr:format( erl_syntax:form_list(Forms) ), "\n"].
